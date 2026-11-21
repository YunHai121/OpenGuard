"""3-Stage Hybrid Secret Detection Engine (Regex + Shannon Entropy + AST Semantic Filtering)."""

from __future__ import annotations

import hashlib
import math
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from openguard.config import AuditConfig, is_path_excluded
from openguard.models import FindingCategory, SecretFinding, Severity
from openguard.scanners.secret_rules import SecretRule, build_builtin_secret_rules
from openguard.utils.ast_analyzer import (
    CodeLineContext,
    analyze_generic_context,
    analyze_python_source,
)
from openguard.utils.entropy import (
    character_class_diversity,
    is_likely_placeholder,
    is_pure_hex_hash,
    mask_secret,
    shannon_entropy,
)

SECRET_VAR_HINTS = (
    "secret",
    "token",
    "key",
    "passwd",
    "password",
    "pwd",
    "auth",
    "credential",
    "dsn",
    "webhook",
    "sk",
    "ak",
    "private",
)

NON_SECRET_VAR_HINTS = (
    "hash",
    "sha256",
    "sha1",
    "md5",
    "checksum",
    "digest",
    "commit",
    "uuid",
    "guid",
    "regex",
    "pattern",
    "example",
    "placeholder",
    "sample",
    "mask",
)


@dataclass
class SecretScanOutcome:
    """Detailed result of scanning content or directory with transparency telemetry."""

    findings: List[SecretFinding]
    suppressed_count: int = 0
    suppressed_samples: List[Dict[str, Any]] = None  # type: ignore[assignment]
    files_scanned: int = 0
    lines_scanned: int = 0

    def __post_init__(self) -> None:
        if self.suppressed_samples is None:
            self.suppressed_samples = []


class SecretScanner:
    """Three-stage hybrid secret scanner combining fingerprints, entropy, and AST semantics."""

    def __init__(self, config: Optional[AuditConfig] = None) -> None:
        self.config = config or AuditConfig()
        self.rules: List[SecretRule] = build_builtin_secret_rules()
        self._load_custom_rules()

    def _load_custom_rules(self) -> None:
        for idx, raw in enumerate(self.config.custom_rules, start=1):
            try:
                rule_id = str(raw.get("rule_id") or f"OG-CUSTOM-{idx:03d}")
                name = str(raw.get("name") or f"Custom Rule {idx}")
                pattern = re.compile(str(raw["pattern"]))
                sev_str = str(raw.get("severity", "HIGH")).upper()
                severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.HIGH
                min_ent = float(raw.get("min_entropy", 2.5))
                remediation = str(raw.get("remediation", "检查并移除敏感硬编码配置。"))
                self.rules.append(
                    SecretRule(
                        rule_id=rule_id,
                        name=name,
                        pattern=pattern,
                        severity=severity,
                        category_tag="custom",
                        min_entropy=min_ent,
                        remediation=remediation,
                    )
                )
            except Exception:
                continue

    def scan_directory(self, root_path: Path) -> SecretScanOutcome:
        """Walk directory and scan all eligible text source/config files."""
        root = Path(root_path).resolve()
        if root.is_file():
            return self.scan_file(root, root.parent)

        if self.config.staged_only:
            return self.scan_staged_diff(root)

        all_findings: List[SecretFinding] = []
        suppressed_samples: List[Dict[str, Any]] = []
        suppressed_count = 0
        files_scanned = 0
        lines_scanned = 0

        candidate_files: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune obviously excluded top dirs early
            rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
            kept_dirs = []
            for d in sorted(dirnames):
                cand_rel = f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/"
                if not is_path_excluded(cand_rel, self.config.exclude_patterns):
                    kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                rel_path = fpath.relative_to(root).as_posix()
                if is_path_excluded(rel_path, self.config.exclude_patterns):
                    continue
                try:
                    if fpath.stat().st_size > self.config.max_file_size_kb * 1024:
                        continue
                except OSError:
                    continue
                candidate_files.append(fpath)

        workers = max(1, min(int(getattr(self.config, "max_workers", 4) or 1), 8))
        if workers > 1 and len(candidate_files) >= 16:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                outcomes = list(pool.map(lambda p: self.scan_file(p, root), candidate_files))
        else:
            outcomes = [self.scan_file(p, root) for p in candidate_files]

        for outcome in outcomes:
            files_scanned += outcome.files_scanned
            lines_scanned += outcome.lines_scanned
            all_findings.extend(outcome.findings)
            suppressed_count += outcome.suppressed_count
            if len(suppressed_samples) < 25 and outcome.suppressed_samples:
                suppressed_samples.extend(outcome.suppressed_samples[: 25 - len(suppressed_samples)])

        return SecretScanOutcome(
            findings=all_findings,
            suppressed_count=suppressed_count,
            suppressed_samples=suppressed_samples,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
        )

    def scan_file(self, file_path: Path, root_path: Optional[Path] = None) -> SecretScanOutcome:
        """Read and scan a single file if it appears to be UTF-8/text."""
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            return SecretScanOutcome(findings=[])

        if b"\x00" in raw_bytes[:4096]:
            # Binary file guard
            return SecretScanOutcome(findings=[])

        content = raw_bytes.decode("utf-8", errors="replace")
        rel_path = (
            file_path.resolve().relative_to(root_path.resolve()).as_posix()
            if root_path
            else file_path.name
        )
        return self.scan_content(content, rel_path)

    def scan_staged_diff(self, repo_path: Path) -> SecretScanOutcome:
        """Scan git-staged added lines with full-file AST context preserved (for pre-commit)."""
        from openguard.baseline import get_git_diff_added_lines

        added_map = get_git_diff_added_lines(repo_path, staged=True)
        return self.scan_diff_lines(repo_path, added_map, staged=True)

    def scan_diff_lines(
        self,
        repo_path: Path,
        added_lines_map: Dict[str, set[int]],
        staged: bool = False,
    ) -> SecretScanOutcome:
        """Scan changed files using full-file AST context and keep only findings on added lines."""
        all_findings: List[SecretFinding] = []
        suppressed_count = 0
        suppressed_samples: List[Dict[str, Any]] = []
        lines_scanned = 0
        files_scanned = 0

        for rel_file, added_line_nums in added_lines_map.items():
            if not added_line_nums or is_path_excluded(rel_file, self.config.exclude_patterns):
                continue

            content: Optional[str] = None
            if staged:
                res = subprocess.run(
                    ["git", "show", f":{rel_file}"],
                    cwd=str(repo_path),
                    capture_output=True,
                )
                if res.returncode == 0 and b"\x00" not in res.stdout[:4096]:
                    content = res.stdout.decode("utf-8", errors="replace")

            if content is None:
                fpath = (repo_path / rel_file).resolve()
                if not fpath.is_file():
                    continue
                try:
                    raw_bytes = fpath.read_bytes()
                    if b"\x00" in raw_bytes[:4096]:
                        continue
                    content = raw_bytes.decode("utf-8", errors="replace")
                except OSError:
                    continue

            files_scanned += 1
            lines_scanned += len(added_line_nums)
            sub = self.scan_content(content, rel_file)
            for f in sub.findings:
                if f.line_number in added_line_nums:
                    all_findings.append(f)
            for s in sub.suppressed_samples:
                if s.get("line_number") in added_line_nums:
                    suppressed_count += 1
                    if len(suppressed_samples) < 25:
                        suppressed_samples.append(s)

        return SecretScanOutcome(
            findings=all_findings,
            suppressed_count=suppressed_count,
            suppressed_samples=suppressed_samples,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
        )

    def scan_content(
        self,
        content: str,
        file_path: str = "snippet.py",
        line_offset: int = 0,
        is_historical_only: bool = False,
        commit_hash: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_date: Optional[str] = None,
    ) -> SecretScanOutcome:
        """Execute the 3-Stage Hybrid Pipeline on raw text content."""
        lines = content.splitlines()
        is_python = file_path.lower().endswith(".py")
        py_contexts = analyze_python_source(content, file_path) if is_python else {}

        findings: List[SecretFinding] = []
        suppressed_samples: List[Dict[str, Any]] = []
        suppressed_count = 0
        seen_line_rule_hash: set[Tuple[int, str, str]] = set()

        for idx, line in enumerate(lines):
            if not line.strip() or len(line) > 2000:
                continue
            line_no = idx + 1 + line_offset
            ctx = (
                py_contexts.get(idx + 1, CodeLineContext())
                if is_python
                else analyze_generic_context(file_path, lines, idx)
            )

            # Fast path for inline suppression markers
            if ctx.inline_suppressed:
                continue

            for rule in self.rules:
                for m in rule.pattern.finditer(line):
                    try:
                        matched_value = m.group(rule.extract_group) if rule.extract_group > 0 else m.group(0)
                    except IndexError:
                        matched_value = m.group(0)

                    if not matched_value:
                        continue

                    raw_hash = hashlib.sha256(matched_value.encode("utf-8")).hexdigest()[:16]
                    dedup_key = (line_no, rule.rule_id, raw_hash)
                    if dedup_key in seen_line_rule_hash:
                        continue

                    accepted, confidence, ent, notes = self._evaluate_candidate(
                        rule=rule,
                        matched_value=matched_value,
                        full_line=line,
                        file_path=file_path,
                        ctx=ctx,
                    )

                    if not accepted:
                        suppressed_count += 1
                        if len(suppressed_samples) < 25:
                            suppressed_samples.append(
                                {
                                    "rule_id": rule.rule_id,
                                    "file_path": file_path,
                                    "line_number": line_no,
                                    "masked": mask_secret(matched_value),
                                    "reason": notes[-1] if notes else "low_confidence",
                                    "confidence": round(confidence, 2),
                                }
                            )
                        continue

                    seen_line_rule_hash.add(dedup_key)
                    # Mask matched secret in the snippet as well to guarantee zero plaintext leakage
                    masked = mask_secret(matched_value)
                    safe_snippet = line.strip()[:180].replace(matched_value, masked)

                    finding = SecretFinding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=(
                            FindingCategory.GIT_HISTORY_SECRET
                            if is_historical_only
                            else FindingCategory.SECRET
                        ),
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_no,
                        column=m.start() + 1,
                        matched_masked=masked,
                        raw_hash=raw_hash,
                        snippet=safe_snippet,
                        entropy=ent,
                        confidence=round(confidence, 3),
                        ast_context=ctx.summary_label,
                        filter_notes=notes,
                        remediation=rule.remediation,
                        runbook_steps=self._build_runbook_steps(rule, file_path, is_historical_only),
                        cwe_id=rule.cwe_id,
                        commit_hash=commit_hash,
                        commit_author=commit_author,
                        commit_date=commit_date,
                        is_historical_only=is_historical_only,
                    )
                    findings.append(finding)
                    # Break inner rules on high-specificity prefix match so generic rule doesn't double-report same value
                    if rule.category_tag in ("cloud", "ai", "scm", "private_key", "database"):
                        break

        return SecretScanOutcome(
            findings=findings,
            suppressed_count=suppressed_count,
            suppressed_samples=suppressed_samples,
            files_scanned=1,
            lines_scanned=len(lines),
        )

    def _evaluate_candidate(
        self,
        rule: SecretRule,
        matched_value: str,
        full_line: str,
        file_path: str,
        ctx: CodeLineContext,
    ) -> Tuple[bool, float, float, List[str]]:
        """Stage 1 Validator -> Stage 2 Entropy/Placeholder -> Stage 3 AST & Context Scoring."""
        notes: List[str] = []
        confidence = 0.72

        # Stage 1: Deterministic structural validator (JWT JSON, MOD 11-2, Luhn)
        if rule.validator is not None:
            if not rule.validator(matched_value):
                notes.append("failed_structural_checksum")
                return False, 0.05, 0.0, notes
            confidence += 0.18
            notes.append("passed_structural_validator")

        # Stage 2: Entropy & Placeholder rejection
        ent = shannon_entropy(matched_value)
        is_ph, ph_reason = is_likely_placeholder(matched_value)
        if is_ph and rule.category_tag != "private_key":
            notes.append(f"rejected_{ph_reason}")
            return False, 0.10, ent, notes

        # Reject standard regex characters embedded inside pattern strings
        if any(tok in matched_value for tok in ("[A-Za-z", "\\d{", "(?:", "(?i)", "{16,}")):
            notes.append("rejected_regex_metacharacters")
            return False, 0.05, ent, notes

        # Pure hex checksum strings (e.g. git SHA, sha256) in generic rules are high-FP unless secret var assigned
        if is_pure_hex_hash(matched_value) and rule.category_tag in ("generic_secret", "auth"):
            var_lower = (ctx.assigned_var or "").lower()
            if not any(h in var_lower for h in SECRET_VAR_HINTS):
                notes.append("rejected_unassigned_hex_hash")
                return False, 0.15, ent, notes

        if rule.min_entropy > 0 and ent < rule.min_entropy:
            # Allow slightly lower entropy only for explicit DB URI / passwords if diverse
            if not (rule.category_tag in ("password", "database") and ent >= rule.min_entropy - 0.35):
                notes.append(f"rejected_low_entropy:{ent:.2f}<{rule.min_entropy:.2f}")
                return False, 0.20, ent, notes

        diversity = character_class_diversity(matched_value)
        if diversity >= 3 and ent >= 3.6:
            confidence += 0.12
            notes.append("high_entropy_diverse_charset")

        # Stage 3: AST & Semantic Context Noise Reduction
        if ctx.is_regex_definition:
            notes.append("rejected_ast_regex_definition")
            return False, 0.05, ent, notes

        if ctx.is_env_lookup:
            # e.g., os.getenv("API_KEY", "") default parameter check
            notes.append("rejected_ast_env_lookup")
            return False, 0.15, ent, notes

        if ctx.in_docstring:
            confidence -= 0.40
            notes.append("penalized_ast_docstring")

        if ctx.in_comment:
            confidence -= 0.32
            notes.append("penalized_comment_line")

        if ctx.is_doc_file and rule.category_tag not in ("private_key",):
            confidence -= 0.30
            notes.append("penalized_documentation_file")

        if ctx.in_test_scope or ctx.is_test_file:
            # Keep high-specificity tokens only if not obviously fake, penalize generic ones heavily
            if rule.category_tag in ("generic_secret", "password", "auth", "pii", "internal_net"):
                confidence -= 0.40
                notes.append("penalized_test_context")
            else:
                confidence -= 0.15
                notes.append("slight_penalty_test_context")

        # Variable assignment boost or suppression
        var_name = (ctx.assigned_var or "").lower()
        if var_name:
            if any(non_sec in var_name for non_sec in NON_SECRET_VAR_HINTS):
                confidence -= 0.45
                notes.append(f"penalized_non_secret_var:{var_name}")
            elif any(sec in var_name for sec in SECRET_VAR_HINTS):
                confidence += 0.15
                notes.append(f"boosted_secret_var:{var_name}")

        # Environment config file boost (.env, config, settings, secrets)
        fname_lower = Path(file_path).name.lower()
        if fname_lower.startswith(".env") or any(k in fname_lower for k in ("secret", "cred", "config", "settings")):
            if not ctx.in_comment:
                confidence += 0.10
                notes.append("boosted_config_file")

        # Check URL/path context (avoid flagging URLs with dummy examples in query strings)
        if "example.com" in full_line.lower() or "localhost" in full_line.lower():
            if rule.category_tag in ("auth", "generic_secret"):
                confidence -= 0.25
                notes.append("penalized_example_domain")

        # Stage 3b: Offline Cryptographic Checksum Verification (GitGuardian / GitHub CRC32)
        if rule.checksum_verifier is not None:
            if rule.checksum_verifier(matched_value):
                confidence = max(confidence + 0.25, 0.96)
                notes.append("verified_crc32_checksum")
            elif ctx.in_test_scope or ctx.is_test_file or ctx.in_comment or ctx.in_docstring or ctx.is_doc_file:
                confidence -= 0.35
                notes.append("penalized_invalid_crc32_in_nonprod")
            else:
                notes.append("unverified_crc32_checksum")

        confidence = max(0.0, min(1.0, confidence))
        if confidence < self.config.min_confidence:
            notes.append(f"below_confidence_threshold:{confidence:.2f}")
            return False, confidence, ent, notes

        return True, confidence, ent, notes

    @staticmethod
    def _build_runbook_steps(rule: SecretRule, file_path: str, is_historical: bool) -> List[str]:
        """Generate a 3-step provider-specific incident response runbook."""
        tag_steps = {
            "cloud": "1. 立即登录对应云厂商控制台（AWS IAM / 阿里云 RAM / 腾讯云 CAM / GCP）吊销泄露密钥并核查近期调用审计日志。",
            "ai": "1. 立即前往大模型平台控制台（OpenAI / Anthropic / DashScope / HuggingFace）撤销泄露 API Key 并核查异常额度消耗。",
            "scm": "1. 立即在代码托管或包仓库设置（GitHub / GitLab / Gitee / PyPI / npm）吊销该 Token，检查近期异常推送或发布。",
            "webhook": "1. 立即在群聊机器人设置（飞书 / 钉钉 / 企业微信 / Slack）重置 Webhook URL 并开启加签/关键词校验。",
            "private_key": "1. 立即吊销对应公钥证书与服务器 authorized_keys 授权，重新生成高强度 Ed25519/RSA 密钥对。",
            "database": "1. 立即修改数据库/中间件口令，核查异常登录 IP，确保数据库端口不直接暴露公网。",
            "pii": "1. 立即清除源码与测试样本中的真实公民个人敏感信息，改用合规合成假数据替代。",
        }
        step1 = tag_steps.get(
            rule.category_tag,
            f"1. 立即轮换或吊销 `{rule.name}` 对应的泄露凭据，防止被未授权利用。",
        )
        if is_historical:
            step2 = (
                f"2. 使用 `git filter-repo --path {file_path} --invert-paths` 清理 Git 历史提交中的残留记录并强制推送。"
            )
        else:
            step2 = (
                f"2. 运行 `openguard autofix . --secrets --apply` 自动将 `{file_path}` 中的硬编码替换为环境变量并生成 `.env.example`。"
            )
        step3 = "3. 运行 `openguard hook install .` 启用提交前拦截防线，避免同类凭据再次进入仓库。"
        return [step1, step2, step3]

    # --- Baseline reference scanners used by Benchmarks to quantify AST+Entropy improvement ---

    def scan_baseline_regex_only(self, content: str, file_path: str = "sample.py") -> List[SecretFinding]:
        """Naive pure-regex scanner baseline without entropy, checksum, or AST filtering."""
        findings: List[SecretFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            for rule in self.rules:
                for m in rule.pattern.finditer(line):
                    val = m.group(rule.extract_group) if rule.extract_group > 0 else m.group(0)
                    if not val:
                        continue
                    findings.append(
                        SecretFinding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=idx,
                            matched_masked=mask_secret(val),
                            raw_hash=hashlib.sha256(val.encode("utf-8")).hexdigest()[:16],
                            entropy=shannon_entropy(val),
                            confidence=0.5,
                            ast_context="none(baseline_regex)",
                        )
                    )
                    if rule.category_tag in ("cloud", "ai", "scm", "private_key", "database"):
                        break
        return findings

    def scan_baseline_entropy_only(
        self,
        content: str,
        file_path: str = "sample.py",
        threshold: float = 3.7,
    ) -> List[SecretFinding]:
        """Naive pure-Shannon-entropy token scanner baseline."""
        token_re = re.compile(r"[\"']([A-Za-z0-9\-_+/=.]{14,128})[\"']")
        findings: List[SecretFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            for m in token_re.finditer(line):
                val = m.group(1)
                ent = shannon_entropy(val)
                if ent >= threshold:
                    findings.append(
                        SecretFinding(
                            rule_id="ENTROPY-ONLY",
                            rule_name="High Entropy String",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=idx,
                            matched_masked=mask_secret(val),
                            raw_hash=hashlib.sha256(val.encode("utf-8")).hexdigest()[:16],
                            entropy=ent,
                            confidence=min(1.0, ent / math.log2(64)),
                            ast_context="none(baseline_entropy)",
                        )
                    )
        return findings
