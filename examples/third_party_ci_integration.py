"""Example 3rd-party DevSecOps CI Gatekeeper integrating OpenGuard via its Python SDK."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from openguard import AuditConfig, OpenGuardAuditor


def run_ci_release_gate(repo_path: Path, min_passing_score: float = 80.0) -> int:
    """Invoke OpenGuardAuditor programmatically as part of a third-party release pipeline."""
    config = AuditConfig(
        include_git_history=False,
        offline=True,
        min_confidence=0.45,
    )
    auditor = OpenGuardAuditor(config)
    report = auditor.audit(repo_path)

    gate_summary = {
        "repository": report.target_name,
        "scan_id": report.scan_id,
        "score": report.summary.total_score,
        "grade": report.summary.grade,
        "critical_count": report.summary.severity_counts.get("CRITICAL", 0),
        "high_count": report.summary.severity_counts.get("HIGH", 0),
        "license_conflicts": len(report.license_conflicts),
        "gate_passed": report.summary.total_score >= min_passing_score
        and report.summary.severity_counts.get("CRITICAL", 0) == 0,
    }
    print(json.dumps(gate_summary, indent=2, ensure_ascii=False))
    return 0 if gate_summary["gate_passed"] else 1


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[1]
    demo_repo = project_root / "examples" / "vulnerable_demo_repo"
    print(">>> Checking self repository with OpenGuard SDK...")
    rc_self = run_ci_release_gate(project_root, min_passing_score=85.0)
    print(f">>> Self repo gate exit code: {rc_self}\n")

    print(">>> Checking vulnerable_demo_repo with OpenGuard SDK...")
    rc_demo = run_ci_release_gate(demo_repo, min_passing_score=80.0)
    print(f">>> Demo repo gate exit code: {rc_demo} (expected 1 due to critical issues)")
    sys.exit(0 if (rc_self == 0 and rc_demo == 1) else 1)
