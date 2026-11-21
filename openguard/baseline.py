"""Semgrep/Gitleaks-inspired Baseline & Git Diff Incremental Scanning Utilities."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from openguard.models import (
    AuditReport,
    CodeSecurityFinding,
    LicenseConflict,
    SecretFinding,
    VulnerabilityFinding,
)


def _sha16(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def fingerprint_secret(f: SecretFinding) -> str:
    return f"sec:{_sha16(f'{f.rule_id}|{f.file_path}|{f.raw_hash}|{f.is_historical_only}')}"


def fingerprint_vuln(v: VulnerabilityFinding) -> str:
    return f"vuln:{_sha16(f'{v.id}|{v.ecosystem}|{v.component_name.lower()}|{v.component_version}')}"


def fingerprint_license(lc: LicenseConflict) -> str:
    return f"lic:{_sha16(f'{lc.component_name.lower()}|{lc.component_license}|{lc.project_license}')}"


def fingerprint_sast(cs: CodeSecurityFinding) -> str:
    norm_snip = re.sub(r"\s+", " ", cs.snippet.strip())
    return f"sast:{_sha16(f'{cs.rule_id}|{cs.file_path}|{norm_snip}')}"


def build_baseline(report: AuditReport) -> Dict[str, Any]:
    """Create a deterministic JSON baseline snapshot from an existing AuditReport."""
    entries: Set[str] = set()
    for s in [*report.secrets, *report.git_history_secrets]:
        entries.add(fingerprint_secret(s))
    for v in report.vulnerabilities:
        entries.add(fingerprint_vuln(v))
    for lc in report.license_conflicts:
        entries.add(fingerprint_license(lc))
    for cs in report.code_security_findings:
        entries.add(fingerprint_sast(cs))

    return {
        "schema_version": "1.0",
        "tool": "OpenGuard",
        "tool_version": report.tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target_name": report.target_name,
        "fingerprints": sorted(entries),
    }


def save_baseline(report: AuditReport, output_path: Path) -> Path:
    """Persist baseline JSON file to disk."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_baseline(report), indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_baseline(baseline_path: Path) -> Set[str]:
    """Load baseline fingerprints from disk."""
    p = Path(baseline_path)
    if not p.is_file():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        fps = data.get("fingerprints", [])
        return {str(fp) for fp in fps if isinstance(fp, str)}
    except Exception:
        return set()


def filter_by_baseline(
    *,
    secrets: List[SecretFinding],
    git_history_secrets: List[SecretFinding],
    vulnerabilities: List[VulnerabilityFinding],
    license_conflicts: List[LicenseConflict],
    code_security_findings: List[CodeSecurityFinding],
    baseline_fingerprints: Set[str],
) -> Tuple[
    List[SecretFinding],
    List[SecretFinding],
    List[VulnerabilityFinding],
    List[LicenseConflict],
    List[CodeSecurityFinding],
    int,
]:
    """Suppress findings already recorded in baseline; return filtered lists + suppressed count."""
    if not baseline_fingerprints:
        return secrets, git_history_secrets, vulnerabilities, license_conflicts, code_security_findings, 0

    suppressed = 0

    kept_secrets: List[SecretFinding] = []
    for f in secrets:
        if fingerprint_secret(f) in baseline_fingerprints:
            suppressed += 1
        else:
            kept_secrets.append(f)

    kept_hist: List[SecretFinding] = []
    for f in git_history_secrets:
        if fingerprint_secret(f) in baseline_fingerprints:
            suppressed += 1
        else:
            kept_hist.append(f)

    kept_vulns: List[VulnerabilityFinding] = []
    for v in vulnerabilities:
        if fingerprint_vuln(v) in baseline_fingerprints:
            suppressed += 1
        else:
            kept_vulns.append(v)

    kept_lics: List[LicenseConflict] = []
    for lc in license_conflicts:
        if fingerprint_license(lc) in baseline_fingerprints:
            suppressed += 1
        else:
            kept_lics.append(lc)

    kept_sast: List[CodeSecurityFinding] = []
    for cs in code_security_findings:
        if fingerprint_sast(cs) in baseline_fingerprints:
            suppressed += 1
        else:
            kept_sast.append(cs)

    return kept_secrets, kept_hist, kept_vulns, kept_lics, kept_sast, suppressed


def get_git_diff_added_lines(
    repo_root: Path,
    *,
    staged: bool = False,
    base_ref: Optional[str] = None,
) -> Dict[str, Set[int]]:
    """Return `{posix_rel_path: {added_1based_line_numbers}}` from `git diff`."""
    cmd = ["git", "diff", "-U0", "--no-color"]
    if staged:
        cmd.append("--cached")
    elif base_ref:
        cmd.append(f"{base_ref}...HEAD")
    else:
        return {}

    try:
        res = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return {}

    # Fallback if three-dot merge-base fails (e.g., single branch or commit ref)
    if res.returncode != 0 and base_ref and not staged:
        try:
            res = subprocess.run(
                ["git", "diff", "-U0", "--no-color", base_ref],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except Exception:
            return {}

    if res.returncode != 0:
        return {}

    added: Dict[str, Set[int]] = {}
    current_file = ""
    current_line = 0
    for raw_line in res.stdout.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            if m:
                current_line = int(m.group(1))
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            if current_file:
                added.setdefault(current_file, set()).add(current_line)
            current_line += 1
    return added
