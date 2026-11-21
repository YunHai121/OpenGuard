"""SLSA v1.0 Provenance & in-toto Statement v1 Attestation Exporter & Verifier.

Generates standards-compliant in-toto v1 / SLSA Provenance v1.0 attestations
containing cryptographic SHA-256 digests of audited manifests & resolved SBOM
dependencies, plus local integrity verification against tampering.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from openguard.models import AuditReport

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def render_slsa_provenance(report: AuditReport) -> Dict[str, Any]:
    """Build an in-toto Statement v1 + SLSA Provenance v1.0 JSON attestation for an AuditReport."""
    root = Path(report.target_path)
    subjects: List[Dict[str, Any]] = []

    # 1. Include cryptographic SHA-256 digests of manifest/lockfiles present in the audited repo
    seen_files: set[str] = set()
    if root.is_dir():
        for comp in report.components:
            sf = (comp.source_file or "").strip()
            if not sf or sf in seen_files:
                continue
            fpath = (root / sf).resolve()
            if fpath.is_file() and fpath.is_relative_to(root.resolve()):
                seen_files.add(sf)
                subjects.append(
                    {
                        "name": sf,
                        "digest": {"sha256": _sha256_file(fpath)},
                    }
                )
        for key_file in ("LICENSE", "pyproject.toml", "package.json", "go.mod", "Cargo.toml"):
            if key_file in seen_files:
                continue
            fpath = root / key_file
            if fpath.is_file():
                seen_files.add(key_file)
                subjects.append(
                    {
                        "name": key_file,
                        "digest": {"sha256": _sha256_file(fpath)},
                    }
                )

    # Always include a deterministic audit-report subject digest
    report_digest = hashlib.sha256(
        json.dumps(
            {
                "scan_id": report.scan_id,
                "target_name": report.target_name,
                "total_score": report.summary.total_score,
                "grade": report.summary.grade,
                "quality_gate": report.summary.quality_gate.status if report.summary.quality_gate else "N/A",
                "components_count": len(report.components),
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    subjects.insert(
        0,
        {
            "name": f"{report.target_name}#{report.scan_id}",
            "digest": {
                "sha256": report_digest,
                **({"gitCommit": report.git_commit} if report.git_commit else {}),
            },
        },
    )

    resolved_deps: List[Dict[str, Any]] = []
    for comp in report.components[:200]:
        resolved_deps.append(
            {
                "uri": comp.purl or f"pkg:{comp.ecosystem.lower()}/{comp.name}@{comp.version}",
                "name": comp.name,
                "annotations": {
                    "ecosystem": comp.ecosystem,
                    "version": comp.version,
                    "license": comp.license_id,
                    "direct": comp.direct,
                },
            }
        )

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://openguard.dev/AuditAttestation/v1",
                "externalParameters": {
                    "target": report.target_name,
                    "gitBranch": report.git_branch or "",
                    "projectLicense": report.project_license,
                },
                "internalParameters": {
                    "toolVersion": report.tool_version,
                    "qualityGateStatus": report.summary.quality_gate.status if report.summary.quality_gate else "N/A",
                    "totalScore": report.summary.total_score,
                    "grade": report.summary.grade,
                },
                "resolvedDependencies": resolved_deps,
            },
            "runDetails": {
                "builder": {
                    "id": f"https://github.com/YunHai121/OpenGuard@v{report.tool_version}",
                    "version": {"openguard": report.tool_version},
                },
                "metadata": {
                    "invocationId": report.scan_id,
                    "startedOn": report.scanned_at,
                    "finishedOn": now_iso,
                },
            },
        },
    }


def verify_slsa_provenance(
    attestation_path: Path,
    repo_root: Optional[Path] = None,
) -> Tuple[bool, List[str]]:
    """Verify an in-toto/SLSA v1.0 provenance JSON attestation and check file SHA-256 integrity."""
    errors: List[str] = []
    p = Path(attestation_path)
    if not p.is_file():
        return False, [f"Attestation file not found: {p}"]
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return False, [f"Invalid JSON attestation: {exc}"]

    if data.get("_type") != IN_TOTO_STATEMENT_TYPE:
        errors.append(f"Unexpected _type: {data.get('_type')}")
    if data.get("predicateType") != SLSA_PROVENANCE_PREDICATE_TYPE:
        errors.append(f"Unexpected predicateType: {data.get('predicateType')}")

    subjects = data.get("subject")
    if not isinstance(subjects, list) or not subjects:
        errors.append("Missing or empty subject list.")
        return False, errors

    if repo_root is not None:
        root = Path(repo_root).resolve()
        for subj in subjects:
            name = str(subj.get("name", ""))
            expected_sha = (subj.get("digest") or {}).get("sha256")
            if "#" in name or not expected_sha:
                continue
            target = (root / name).resolve()
            if not target.is_file() or not target.is_relative_to(root):
                errors.append(f"Subject file missing: {name}")
                continue
            actual_sha = _sha256_file(target)
            if actual_sha != expected_sha:
                errors.append(f"Digest mismatch (tampered!) for {name}: expected {expected_sha[:12]}..., got {actual_sha[:12]}...")

    return len(errors) == 0, errors
