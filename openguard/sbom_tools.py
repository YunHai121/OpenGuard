"""GitHub Dependency Review & Interlynk sbomqs-inspired SBOM Diff, License Drift & NTIA Quality Scorer.

Provides:
- `diff_cyclonedx_sboms(before, after)`: detects added/removed/changed components,
  license drift (especially newly introduced copyleft GPL/AGPL/LGPL), and newly
  introduced vs. remediated vulnerabilities.
- `score_sbom_quality(sbom)`: grades any CycloneDX JSON SBOM on a 0.0–10.0 scale
  against the 7 NTIA/CISA Minimum Elements (spec validity, author/timestamp,
  component names & versions, PURL identifiers, dependency graph, license coverage,
  and VEX/vulnerability enrichment).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

COPYLEFT_MARKERS = ("GPL", "AGPL", "LGPL", "SSPL", "EUPL")


@dataclass
class SBOMDiffResult:
    """Structured diff between two CycloneDX SBOMs."""

    added_components: List[Dict[str, str]] = field(default_factory=list)
    removed_components: List[Dict[str, str]] = field(default_factory=list)
    version_changes: List[Dict[str, str]] = field(default_factory=list)
    license_drifts: List[Dict[str, str]] = field(default_factory=list)
    new_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    fixed_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_risky_drift(self) -> bool:
        return bool(self.new_vulnerabilities) or any(d.get("is_copyleft_intro") == "true" for d in self.license_drifts)


@dataclass
class SBOMQualityReport:
    """NTIA/CISA Minimum Elements quality evaluation (0.0 - 10.0, sbomqs style)."""

    overall_score: float
    grade: str
    component_count: int
    checks: List[Dict[str, Any]] = field(default_factory=list)


def _extract_comp_license(comp: Dict[str, Any]) -> str:
    lics = comp.get("licenses") or []
    if isinstance(lics, list) and lics:
        first = lics[0]
        if isinstance(first, dict):
            lic_obj = first.get("license") or {}
            if isinstance(lic_obj, dict):
                return str(lic_obj.get("id") or lic_obj.get("name") or "UNKNOWN")
            if first.get("expression"):
                return str(first["expression"])
    return "UNKNOWN"


def _extract_comp_ecosystem(comp: Dict[str, Any]) -> str:
    for prop in comp.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "openguard:ecosystem":
            return str(prop.get("value") or "")
    purl = str(comp.get("purl") or "")
    if purl.startswith("pkg:") and "/" in purl:
        return purl[4:].split("/", 1)[0]
    return "generic"


def _is_copyleft(lic: str) -> bool:
    up = lic.upper()
    return any(m in up for m in COPYLEFT_MARKERS)


def load_cyclonedx_json(path: Path) -> Dict[str, Any]:
    """Load a CycloneDX JSON document from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))


def diff_cyclonedx_sboms(before: Dict[str, Any], after: Dict[str, Any]) -> SBOMDiffResult:
    """Compare two CycloneDX SBOM dicts and identify dependency, license, and CVE drift."""
    res = SBOMDiffResult()

    def index_comps(sbom: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, str]]:
        idx: Dict[Tuple[str, str], Dict[str, str]] = {}
        for c in sbom.get("components") or []:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            eco = _extract_comp_ecosystem(c)
            name = str(c["name"])
            idx[(eco.lower(), name.lower())] = {
                "name": name,
                "ecosystem": eco,
                "version": str(c.get("version") or "unspecified"),
                "license": _extract_comp_license(c),
                "purl": str(c.get("purl") or ""),
            }
        return idx

    b_comps = index_comps(before)
    a_comps = index_comps(after)

    for key, ac in sorted(a_comps.items()):
        if key not in b_comps:
            res.added_components.append(ac)
            if _is_copyleft(ac["license"]):
                res.license_drifts.append(
                    {
                        "component": ac["name"],
                        "before_license": "(new)",
                        "after_license": ac["license"],
                        "is_copyleft_intro": "true",
                    }
                )
        else:
            bc = b_comps[key]
            if bc["version"] != ac["version"]:
                res.version_changes.append(
                    {
                        "name": ac["name"],
                        "ecosystem": ac["ecosystem"],
                        "before_version": bc["version"],
                        "after_version": ac["version"],
                    }
                )
            if bc["license"] != ac["license"] and ac["license"] != "UNKNOWN":
                res.license_drifts.append(
                    {
                        "component": ac["name"],
                        "before_license": bc["license"],
                        "after_license": ac["license"],
                        "is_copyleft_intro": "true" if (_is_copyleft(ac["license"]) and not _is_copyleft(bc["license"])) else "false",
                    }
                )

    for key, bc in sorted(b_comps.items()):
        if key not in a_comps:
            res.removed_components.append(bc)

    def index_vulns(sbom: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
        vmap: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for v in sbom.get("vulnerabilities") or []:
            if not isinstance(v, dict) or not v.get("id"):
                continue
            vid = str(v["id"])
            affects = v.get("affects") or []
            ref = str(affects[0].get("ref", "")) if (isinstance(affects, list) and affects and isinstance(affects[0], dict)) else ""
            ratings = v.get("ratings") or []
            sev = str(ratings[0].get("severity", "unknown")).upper() if (isinstance(ratings, list) and ratings and isinstance(ratings[0], dict)) else "UNKNOWN"
            vmap[(vid, ref)] = {"id": vid, "ref": ref, "severity": sev, "description": str(v.get("description") or "")}
        return vmap

    b_vulns = index_vulns(before)
    a_vulns = index_vulns(after)

    for vk, av in sorted(a_vulns.items()):
        if vk not in b_vulns:
            res.new_vulnerabilities.append(av)
    for vk, bv in sorted(b_vulns.items()):
        if vk not in a_vulns:
            res.fixed_vulnerabilities.append(bv)

    return res


def render_sbom_diff_markdown(diff: SBOMDiffResult) -> str:
    """Render a PR-friendly Dependency Review / SBOM Diff summary in Markdown."""
    status = "RISK DRIFT DETECTED" if diff.has_risky_drift else "CLEAN"
    lines: List[str] = [
        f"## OpenGuard SBOM Diff & Supply-Chain Drift — **{status}**",
        "",
        f"- **Added Components**: `{len(diff.added_components)}` | **Removed**: `{len(diff.removed_components)}` | **Version Changes**: `{len(diff.version_changes)}`",
        f"- **License Drifts**: `{len(diff.license_drifts)}` | **New Vulnerabilities**: `{len(diff.new_vulnerabilities)}` | **Fixed Vulnerabilities**: `{len(diff.fixed_vulnerabilities)}`",
        "",
    ]
    if diff.new_vulnerabilities:
        lines.extend(["### Newly Introduced Vulnerabilities", "", "| CVE / ID | Severity | Component Ref | Summary |", "| :--- | :---: | :--- | :--- |"])
        for v in diff.new_vulnerabilities:
            lines.append(f"| `{v['id']}` | **{v['severity']}** | `{v['ref']}` | {v['description'][:120]} |")
        lines.append("")
    if diff.license_drifts:
        lines.extend(["### License Drift Alerts", "", "| Component | Before | After | Copyleft Risk |", "| :--- | :---: | :---: | :---: |"])
        for d in diff.license_drifts:
            lines.append(f"| `{d['component']}` | `{d['before_license']}` | `{d['after_license']}` | **{d['is_copyleft_intro'].upper()}** |")
        lines.append("")
    if diff.added_components:
        lines.extend(["### Added Components", "", "| Component | Ecosystem | Version | License |", "| :--- | :--- | :---: | :---: |"])
        for c in diff.added_components[:30]:
            lines.append(f"| `{c['name']}` | {c['ecosystem']} | `{c['version']}` | `{c['license']}` |")
        lines.append("")
    return "\n".join(lines)


def score_sbom_quality(sbom: Dict[str, Any]) -> SBOMQualityReport:
    """Evaluate CycloneDX SBOM quality (0.0-10.0) against NTIA/CISA Minimum Elements."""
    comps = [c for c in (sbom.get("components") or []) if isinstance(c, dict)]
    n = len(comps)
    meta = sbom.get("metadata") if isinstance(sbom.get("metadata"), dict) else {}
    deps = sbom.get("dependencies") if isinstance(sbom.get("dependencies"), list) else []
    vulns = sbom.get("vulnerabilities") if isinstance(sbom.get("vulnerabilities"), list) else []

    checks: List[Dict[str, Any]] = []

    # 1. Spec format & version (1.5 pts)
    spec_ok = sbom.get("bomFormat") == "CycloneDX" and str(sbom.get("specVersion", "")) >= "1.4" and bool(sbom.get("serialNumber"))
    checks.append({"id": "NTIA-1", "name": "CycloneDX Spec & Serial Number", "score": 1.5 if spec_ok else 0.0, "max": 1.5, "passed": spec_ok})

    # 2. Author / Tool & Timestamp (1.5 pts)
    meta_ok = bool(meta.get("timestamp")) and bool(meta.get("tools"))
    checks.append({"id": "NTIA-2", "name": "Author Tool & ISO-8601 Timestamp", "score": 1.5 if meta_ok else 0.0, "max": 1.5, "passed": meta_ok})

    # 3. Component names & explicit versions (2.0 pts)
    if n > 0:
        ver_ratio = sum(1 for c in comps if c.get("name") and str(c.get("version") or "unspecified") not in ("", "unspecified", "*")) / n
    else:
        ver_ratio = 1.0
    ver_pts = round(2.0 * ver_ratio, 2)
    checks.append({"id": "NTIA-3", "name": "Component Name & Pinned Version Coverage", "score": ver_pts, "max": 2.0, "passed": ver_ratio >= 0.8})

    # 4. Unique Identifiers / PURLs (2.0 pts)
    purl_ratio = (sum(1 for c in comps if str(c.get("purl") or "").startswith("pkg:")) / n) if n > 0 else 1.0
    purl_pts = round(2.0 * purl_ratio, 2)
    checks.append({"id": "NTIA-4", "name": "Unique Package URL (PURL) Identifiers", "score": purl_pts, "max": 2.0, "passed": purl_ratio >= 0.9})

    # 5. Dependency Relationships (1.0 pt)
    dep_ok = (len(deps) > 0) if n > 0 else True
    checks.append({"id": "NTIA-5", "name": "Dependency Relationship Graph", "score": 1.0 if dep_ok else 0.0, "max": 1.0, "passed": dep_ok})

    # 6. License Coverage (1.0 pt)
    lic_ratio = (sum(1 for c in comps if _extract_comp_license(c) != "UNKNOWN") / n) if n > 0 else 1.0
    lic_pts = round(1.0 * lic_ratio, 2)
    checks.append({"id": "NTIA-6", "name": "Component SPDX License Coverage", "score": lic_pts, "max": 1.0, "passed": lic_ratio >= 0.5})

    # 7. VEX / Vulnerability Enrichment (1.0 pt)
    if vulns:
        vex_ratio = sum(1 for v in vulns if isinstance(v, dict) and isinstance(v.get("analysis"), dict)) / len(vulns)
    else:
        vex_ratio = 1.0
    vex_pts = round(1.0 * vex_ratio, 2)
    checks.append({"id": "NTIA-7", "name": "CycloneDX VEX Exploitability Enrichment", "score": vex_pts, "max": 1.0, "passed": vex_ratio >= 0.7})

    total = round(min(10.0, sum(c["score"] for c in checks)), 2)
    grade = "A+" if total >= 9.5 else ("A" if total >= 8.5 else ("B" if total >= 7.0 else ("C" if total >= 5.5 else "D")))
    return SBOMQualityReport(overall_score=total, grade=grade, component_count=n, checks=checks)
