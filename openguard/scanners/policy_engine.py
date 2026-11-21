"""Semgrep / FOSSA / OPA-inspired Declarative Policy-as-Code & Custom YAML Rule Engine.

Supports:
1. Custom YAML Code Rules loaded from `<repo>/.openguard/rules/*.{yml,yaml}` or
   `custom_sast_rules` inside `.openguard.yml` (regex patterns with path globs & exclusions).
2. Declarative Supply-Chain & License Governance Policy (`policy:` in `.openguard.yml`):
   - `denied_licenses`: block specific SPDX IDs (e.g. `["AGPL-3.0", "SSPL-1.0"]`)
   - `allowed_licenses`: optional strict allowlist (flag any known/unknown license outside list)
   - `denied_packages`: block banned third-party packages across any ecosystem
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from openguard.config import AuditConfig, DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import (
    CodeSecurityFinding,
    DependencyComponent,
    FindingCategory,
    LicenseCompatibility,
    LicenseConflict,
    Severity,
    VulnerabilityFinding,
)


def _parse_severity(raw: Any, default: Severity = Severity.HIGH) -> Severity:
    key = str(raw or "").upper().strip()
    return Severity[key] if key in Severity.__members__ else default


class PolicyEngine:
    """Evaluates zero-code YAML security rules and declarative supply-chain compliance policies."""

    def load_custom_code_rules(self, repo_root: Path, config: AuditConfig) -> List[Dict[str, Any]]:
        """Merge inline `custom_sast_rules` from config and `<repo>/.openguard/rules/*.{yml,yaml}`."""
        rules: List[Dict[str, Any]] = []
        for r in config.custom_sast_rules or []:
            if isinstance(r, dict) and r.get("pattern"):
                rules.append(r)

        rules_dir = repo_root / ".openguard" / "rules"
        if rules_dir.is_dir():
            for fpath in sorted(rules_dir.iterdir()):
                if not fpath.is_file() or fpath.suffix.lower() not in (".yml", ".yaml"):
                    continue
                try:
                    loaded = yaml.safe_load(fpath.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                if isinstance(loaded, dict) and isinstance(loaded.get("rules"), list):
                    for r in loaded["rules"]:
                        if isinstance(r, dict) and r.get("pattern"):
                            rules.append(r)
                elif isinstance(loaded, list):
                    for r in loaded:
                        if isinstance(r, dict) and r.get("pattern"):
                            rules.append(r)
        return rules

    def scan_custom_code_rules(
        self,
        root_path: Path,
        config: AuditConfig,
    ) -> List[CodeSecurityFinding]:
        """Run all loaded custom YAML code rules against matching repository files."""
        root = Path(root_path).resolve()
        repo_root = root.parent if root.is_file() else root
        raw_rules = self.load_custom_code_rules(repo_root, config)
        if not raw_rules:
            return []

        compiled: List[Tuple[str, str, str, Severity, re.Pattern[str], List[str], List[str], str, str]] = []
        for idx, r in enumerate(raw_rules, start=1):
            try:
                pat = re.compile(str(r["pattern"]))
            except re.error:
                continue
            rid = str(r.get("id") or r.get("rule_id") or f"OG-POLICY-CODE-{idx:03d}")
            name = str(r.get("name") or f"Custom Policy Rule {idx}")
            cwe = str(r.get("cwe") or r.get("cwe_id") or "CWE-710")
            sev = _parse_severity(r.get("severity"), Severity.HIGH)
            paths = [str(p).replace("\\", "/") for p in (r.get("paths") or ["*"])]
            excl_paths = [str(p).replace("\\", "/") for p in (r.get("exclude_paths") or [])]
            msg = str(r.get("message") or r.get("description") or f"命中自定义策略规则 `{rid}`。")
            rem = str(r.get("remediation") or "按照团队安全策略要求整改该代码片段。")
            compiled.append((rid, name, cwe, sev, pat, paths, excl_paths, msg, rem))

        if not compiled:
            return []

        files: List[Path] = []
        if root.is_file():
            files.append(root)
        else:
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
                dirnames[:] = [
                    d
                    for d in sorted(dirnames)
                    if d not in DEFAULT_EXCLUDE_DIRS
                    and not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", config.exclude_patterns)
                ]
                for fname in sorted(filenames):
                    fpath = Path(dirpath) / fname
                    rel = fpath.relative_to(root).as_posix()
                    # Never scan the rule definition files themselves
                    if rel.startswith(".openguard/rules/") or rel in (".openguard.yml", ".openguard.yaml"):
                        continue
                    if is_path_excluded(rel, config.exclude_patterns):
                        continue
                    try:
                        if fpath.stat().st_size > config.max_file_size_kb * 1024:
                            continue
                    except OSError:
                        continue
                    files.append(fpath)

        findings: List[CodeSecurityFinding] = []
        for fpath in files:
            rel = fpath.resolve().relative_to(repo_root).as_posix()
            fname = fpath.name
            applicable = [
                rule
                for rule in compiled
                if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(fname, p) for p in rule[5])
                and not any(fnmatch.fnmatch(rel, ep) or fnmatch.fnmatch(fname, ep) for ep in rule[6])
            ]
            if not applicable:
                continue

            try:
                raw_bytes = fpath.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw_bytes[:4096]:
                continue
            lines = raw_bytes.decode("utf-8", errors="replace").splitlines()

            for ln, line in enumerate(lines, start=1):
                if not line.strip() or "openguard: ignore" in line.lower():
                    continue
                for rid, name, cwe, sev, pat, _p, _ep, msg, rem in applicable:
                    if pat.search(line):
                        findings.append(
                            CodeSecurityFinding(
                                rule_id=rid,
                                rule_name=name,
                                cwe_id=cwe,
                                severity=sev,
                                file_path=rel,
                                line_number=ln,
                                snippet=line.strip()[:180],
                                description=msg,
                                remediation=rem,
                            )
                        )
        return findings

    def evaluate_supply_chain_policy(
        self,
        *,
        project_name: str,
        project_license: str,
        components: List[DependencyComponent],
        config: AuditConfig,
        existing_license_conflicts: List[LicenseConflict],
    ) -> Tuple[List[LicenseConflict], List[VulnerabilityFinding]]:
        """Enforce declarative FOSSA/OPA-style license denylist/allowlist and banned package policies."""
        policy = config.policy or {}
        if not isinstance(policy, dict) or not policy:
            return [], []

        denied_licenses = {str(x).strip().upper() for x in (policy.get("denied_licenses") or []) if str(x).strip()}
        allowed_licenses = {str(x).strip().upper() for x in (policy.get("allowed_licenses") or []) if str(x).strip()}
        denied_packages = {str(x).strip().lower() for x in (policy.get("denied_packages") or []) if str(x).strip()}

        existing_by_key = {(lc.component_name.lower(), lc.component_license.upper()): lc for lc in existing_license_conflicts}
        new_lic_conflicts: List[LicenseConflict] = []
        policy_pkg_blocks: List[VulnerabilityFinding] = []

        for comp in components:
            comp_lic = (comp.license_id or "UNKNOWN").strip()
            comp_lic_up = comp_lic.upper()
            lic_key = (comp.name.lower(), comp_lic_up)

            # 1. License Denylist (also escalates any existing REVIEW_REQUIRED entry to INCOMPATIBLE)
            if comp_lic_up in denied_licenses:
                if lic_key in existing_by_key:
                    ex = existing_by_key[lic_key]
                    ex.compatibility = LicenseCompatibility.INCOMPATIBLE.value
                    ex.severity = Severity.CRITICAL.value
                    ex.explanation = f"命中组织合规黑名单策略 (`policy.denied_licenses`)：禁止引入 `{comp_lic}` 许可证组件 `{comp.name}`。"
                else:
                    lc = LicenseConflict(
                        component_name=comp.name,
                        component_version=comp.version,
                        component_license=comp_lic,
                        project_license=project_license,
                        compatibility=LicenseCompatibility.INCOMPATIBLE,
                        severity=Severity.CRITICAL,
                        dependency_path=[project_name, comp.name],
                        explanation=f"命中组织合规黑名单策略 (`policy.denied_licenses`)：禁止引入 `{comp_lic}` 许可证组件 `{comp.name}`。",
                        remediation=f"移除 `{comp.name}` 或替换为符合组织白名单的宽松许可替代库。",
                    )
                    existing_by_key[lic_key] = lc
                    new_lic_conflicts.append(lc)
            # 2. Strict License Allowlist
            elif allowed_licenses and comp_lic_up != "UNKNOWN" and comp_lic_up not in allowed_licenses:
                if lic_key in existing_by_key:
                    ex = existing_by_key[lic_key]
                    ex.compatibility = LicenseCompatibility.INCOMPATIBLE.value
                    ex.severity = Severity.HIGH.value
                    ex.explanation = f"组件 `{comp.name}` 许可证 `{comp_lic}` 不在组织白名单 (`policy.allowed_licenses`) 范围内。"
                else:
                    lc = LicenseConflict(
                        component_name=comp.name,
                        component_version=comp.version,
                        component_license=comp_lic,
                        project_license=project_license,
                        compatibility=LicenseCompatibility.INCOMPATIBLE,
                        severity=Severity.HIGH,
                        dependency_path=[project_name, comp.name],
                        explanation=f"组件 `{comp.name}` 许可证 `{comp_lic}` 不在组织白名单 (`policy.allowed_licenses`) 范围内。",
                        remediation="向法务/安全团队申请许可证豁免，或替换为白名单允许的依赖组件。",
                    )
                    existing_by_key[lic_key] = lc
                    new_lic_conflicts.append(lc)

            # 3. Banned Package Denylist
            if comp.name.lower() in denied_packages:
                policy_pkg_blocks.append(
                    VulnerabilityFinding(
                        id=f"OG-POLICY-PKG-{comp.name.upper()}",
                        component_name=comp.name,
                        component_version=comp.version,
                        ecosystem=comp.ecosystem,
                        severity=Severity.CRITICAL,
                        cvss_score=9.5,
                        summary=f"命中组织禁用依赖策略 (`policy.denied_packages`)：禁止在项目中使用 `{comp.name}`。",
                        fixed_version="立即移除并替换为受批准组件",
                        source="policy_engine",
                        source_file=comp.source_file,
                        category=FindingCategory.VULNERABILITY,
                        remediation=f"从 `{comp.source_file}` 移除 `{comp.name}`，改用组织安全基准认可的替代库。",
                        reachable=True,
                        reachability_level="call_reachable",
                        priority_tier="P0",
                    )
                )

        return new_lic_conflicts, policy_pkg_blocks
