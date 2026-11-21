"""OpenSSF Scorecard & Zizmor-inspired CI/CD Supply-Chain Security Scanner.

Audits `.github/workflows/*.{yml,yaml}` and `.gitlab-ci.yml` for:
- Unpinned third-party GitHub Actions (floating tags instead of 40-char commit SHA)
- Excessive or missing least-privilege GITHUB_TOKEN `permissions`
- Dangerous `pull_request_target` + untrusted PR head checkout
- GitHub Actions expression script injection (`${{ github.event.* }}` inside `run:`)
- Unverified remote pipe-to-shell commands (`curl | sh`, `wget | bash`)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity

ACTION_USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"#\s]+)['\"]?")
SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SCRIPT_INJECTION_RE = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|discussion|review|head_commit|commits|pages)\."
    r"(?:title|body|name|message|email|label\.name|page_name)|head_ref)\s*\}\}"
)
PIPE_TO_SHELL_RE = re.compile(r"(?:curl|wget)\s+[^|\n]*\|\s*(?:sh|bash|zsh|pwsh|powershell)\b", re.I)
PERMISSIONS_TOP_RE = re.compile(r"^permissions\s*:", re.M)
PERMISSIONS_WRITE_ALL_RE = re.compile(r"^\s*permissions\s*:\s*write-all\b", re.I)
PRT_TRIGGER_RE = re.compile(r"\bpull_request_target\b")
UNTRUSTED_PR_REF_RE = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)")


class CIWorkflowScanner:
    """Static security analyzer for GitHub Actions and GitLab CI pipelines."""

    def scan_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[CodeSecurityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            if self._is_ci_file(root):
                return self.scan_file(root, root.parent)
            return []

        excludes = exclude_patterns or []
        findings: List[CodeSecurityFinding] = []

        # 1. .github/workflows/*.yml / *.yaml
        wf_dir = root / ".github" / "workflows"
        if wf_dir.is_dir():
            for fpath in sorted(wf_dir.iterdir()):
                if fpath.is_file() and fpath.suffix.lower() in (".yml", ".yaml"):
                    rel = fpath.relative_to(root).as_posix()
                    if not is_path_excluded(rel, excludes):
                        findings.extend(self._scan_github_workflow(fpath, rel))

        # 2. .gitlab-ci.yml (root or nested)
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in DEFAULT_EXCLUDE_DIRS
                and not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", excludes)
            ]
            for fname in sorted(filenames):
                if fname.lower() == ".gitlab-ci.yml":
                    fpath = Path(dirpath) / fname
                    rel = fpath.relative_to(root).as_posix()
                    if not is_path_excluded(rel, excludes):
                        findings.extend(self._scan_gitlab_ci(fpath, rel))

        return findings

    @staticmethod
    def _is_ci_file(fpath: Path) -> bool:
        low = fpath.name.lower()
        if low == ".gitlab-ci.yml":
            return True
        parts = [p.lower() for p in fpath.parts]
        return ".github" in parts and "workflows" in parts and fpath.suffix.lower() in (".yml", ".yaml")

    def scan_file(self, fpath: Path, root: Path) -> List[CodeSecurityFinding]:
        rel = fpath.resolve().relative_to(root.resolve()).as_posix()
        if fpath.name.lower() == ".gitlab-ci.yml":
            return self._scan_gitlab_ci(fpath, rel)
        return self._scan_github_workflow(fpath, rel)

    def _scan_github_workflow(self, fpath: Path, rel: str) -> List[CodeSecurityFinding]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        has_prt = bool(PRT_TRIGGER_RE.search(content))

        # Rule OG-CI-002: Missing top-level least-privilege permissions block
        if not PERMISSIONS_TOP_RE.search(content):
            findings.append(
                CodeSecurityFinding(
                    rule_id="OG-CI-002",
                    rule_name="Missing Explicit GITHUB_TOKEN Least-Privilege Permissions",
                    cwe_id="CWE-250",
                    severity=Severity.MEDIUM,
                    file_path=rel,
                    line_number=1,
                    snippet=lines[0].strip()[:180] if lines else "",
                    description="GitHub Actions 工作流未在顶层显式声明 `permissions:`，默认可能继承过宽的仓库写入权限。",
                    remediation="在工作流顶层添加最小权限声明（例如 `permissions: { contents: read }`），仅在需要的 Job 中按需提权。",
                )
            )

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "openguard: ignore" in stripped.lower():
                continue

            # Rule OG-CI-002 (write-all)
            if PERMISSIONS_WRITE_ALL_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-CI-002",
                        rule_name="Overly Broad GITHUB_TOKEN permissions: write-all",
                        cwe_id="CWE-250",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="工作流授予了 `permissions: write-all`，一旦依赖 Action 被劫持将直接危及整个代码仓与发布产物。",
                        remediation="遵循最小权限原则，将 `write-all` 替换为精确作用域（如 `contents: read`）。",
                    )
                )

            # Rule OG-CI-001: Unpinned third-party Action
            m_uses = ACTION_USES_RE.match(raw)
            if m_uses:
                action_ref = m_uses.group(1)
                if not action_ref.startswith("./") and not action_ref.startswith("docker://"):
                    if "@" in action_ref:
                        _, ref = action_ref.rsplit("@", 1)
                        if not SHA40_RE.match(ref):
                            findings.append(
                                CodeSecurityFinding(
                                    rule_id="OG-CI-001",
                                    rule_name="Unpinned Third-Party GitHub Action (Mutable Tag/Branch)",
                                    cwe_id="CWE-829",
                                    severity=Severity.MEDIUM,
                                    file_path=rel,
                                    line_number=idx,
                                    snippet=stripped[:180],
                                    description=f"第三方 Action `{action_ref}` 引用了可变标签/分支 `@{ref}`，易遭上游 Tag 篡改投毒（OpenSSF Pinned-Dependencies）。",
                                    remediation="将该 Action 锁定至不可变的 40 位完整 Commit SHA（如 `actions/checkout@<40-char-sha> # v4`）。",
                                )
                            )

            # Rule OG-CI-003: pull_request_target + untrusted PR head checkout
            if has_prt and UNTRUSTED_PR_REF_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-CI-003",
                        rule_name="Dangerous pull_request_target Checkout of Untrusted PR Head",
                        cwe_id="CWE-94",
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="工作流在具备写权限与 Secrets 的 `pull_request_target` 上下文中检出外部 PR 代码，可导致任意代码执行与密钥窃取。",
                        remediation="改用 `pull_request` 触发器，或严禁在 `pull_request_target` 中检出并执行来自 Fork PR 的不可信代码。",
                    )
                )

            # Rule OG-CI-004: Expression injection into shell commands
            if SCRIPT_INJECTION_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-CI-004",
                        rule_name="GitHub Actions Expression Script Injection",
                        cwe_id="CWE-78",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="工作流直接插值外部可控的 `${{ github.event.* }}` 字段，攻击者可通过构造 Issue/PR 标题注入 Shell 命令。",
                        remediation="通过中间 `env:` 环境变量传递表达式值，在脚本中引用 `\"$VAR\"` 而非直接 `${{ ... }}` 插值。",
                    )
                )

            # Rule OG-CI-005: Remote pipe-to-shell in CI
            if PIPE_TO_SHELL_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-CI-005",
                        rule_name="Unverified Pipe-to-Shell Execution in CI Pipeline",
                        cwe_id="CWE-829",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="CI 流水线直接下载远程脚本并管道执行（`curl | sh`），缺少完整性哈希校验，存在供应链投毒风险。",
                        remediation="先下载脚本到本地并校验预期 SHA256 摘要，或改用锁定版本的官方包管理器/镜像。",
                    )
                )

        return findings

    def _scan_gitlab_ci(self, fpath: Path, rel: str) -> List[CodeSecurityFinding]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: List[CodeSecurityFinding] = []
        for idx, raw in enumerate(content.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "openguard: ignore" in stripped.lower():
                continue

            if PIPE_TO_SHELL_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-CI-005",
                        rule_name="Unverified Pipe-to-Shell Execution in GitLab CI",
                        cwe_id="CWE-829",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="GitLab CI 任务直接通过管道执行远程脚本，缺少完整性校验。",
                        remediation="下载后校验 SHA256 再执行，或使用内部受信任镜像源。",
                    )
                )

            if re.match(r"^\s*image\s*:\s*['\"]?[^'\":\s]+(?::latest)?['\"]?\s*$", raw, re.I):
                if ":latest" in raw.lower():
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-CI-006",
                            rule_name="Mutable :latest Container Image in GitLab CI",
                            cwe_id="CWE-1104",
                            severity=Severity.MEDIUM,
                            file_path=rel,
                            line_number=idx,
                            snippet=stripped[:180],
                            description="GitLab CI 使用了可变 `:latest` 基础镜像，无法保证构建可复现且可能自动拉取受污染镜像。",
                            remediation="锁定具体镜像版本标签或 `@sha256:` 摘要（如 `python:3.11-slim`）。",
                        )
                    )
        return findings
