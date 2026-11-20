"""Standards-compliant SARIF 2.1.0, CycloneDX 1.5 SBOM, and SPDX 2.3 JSON exporters."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from openguard.models import AuditReport, Severity


def _sarif_level(sev: str) -> str:
    if sev in (Severity.CRITICAL.value, Severity.HIGH.value):
        return "error"
    if sev == Severity.MEDIUM.value:
        return "warning"
    return "note"


def render_sarif(report: AuditReport) -> Dict[str, Any]:
    """Export findings in OASIS SARIF 2.1.0 format for IDE / GitLab / GitHub integration."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    def add_rule(rule_id: str, name: str, short_desc: str, cwe: str = "") -> None:
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": short_desc[:200]},
                "properties": {"tags": [cwe] if cwe else ["security"]},
            }

    for sec in [*report.secrets, *report.git_history_secrets]:
        add_rule(sec.rule_id, sec.rule_name, sec.remediation or sec.rule_name, sec.cwe_id)
        results.append(
            {
                "ruleId": sec.rule_id,
                "level": _sarif_level(str(sec.severity)),
                "message": {
                    "text": f"{sec.rule_name} ({sec.matched_masked}) detected; confidence={sec.confidence:.2f}, context={sec.ast_context}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": sec.file_path},
                            "region": {"startLine": max(1, sec.line_number), "startColumn": max(1, sec.column)},
                        }
                    }
                ],
            }
        )

    for cs in report.code_security_findings:
        add_rule(cs.rule_id, cs.rule_name, cs.description, cs.cwe_id)
        results.append(
            {
                "ruleId": cs.rule_id,
                "level": _sarif_level(str(cs.severity)),
                "message": {"text": f"[{cs.cwe_id}] {cs.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": cs.file_path},
                            "region": {"startLine": max(1, cs.line_number)},
                        }
                    }
                ],
            }
        )

    for v in report.vulnerabilities:
        add_rule(v.id, f"Dependency Vulnerability {v.id}", v.summary, "CWE-1104")
        results.append(
            {
                "ruleId": v.id,
                "level": _sarif_level(str(v.severity)),
                "message": {"text": f"{v.component_name}@{v.component_version}: {v.summary}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "dependencies"}, "region": {"startLine": 1}}}
                ],
            }
        )

    for lc in report.license_conflicts:
        rid = f"OG-LIC-{lc.component_license}"
        add_rule(rid, f"License Compatibility Alert ({lc.component_license})", lc.explanation, "compliance")
        results.append(
            {
                "ruleId": rid,
                "level": _sarif_level(str(lc.severity)),
                "message": {
                    "text": f"{lc.component_name} ({lc.component_license}) vs project ({lc.project_license}): {lc.explanation}"
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "LICENSE"}, "region": {"startLine": 1}}}
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenGuard",
                        "version": report.tool_version,
                        "informationUri": "https://git.hust.edu.cn/",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_cyclonedx(report: AuditReport) -> Dict[str, Any]:
    """Export Software Bill of Materials (SBOM) in CycloneDX 1.5 JSON specification."""
    components_json: List[Dict[str, Any]] = []
    deps_map: Dict[str, List[str]] = {}

    for comp in report.components:
        bom_ref = comp.purl or f"{comp.ecosystem}:{comp.name}@{comp.version}"
        entry: Dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "properties": [
                {"name": "openguard:ecosystem", "value": comp.ecosystem},
                {"name": "openguard:source_file", "value": comp.source_file},
                {"name": "openguard:direct", "value": str(comp.direct).lower()},
            ],
        }
        if comp.license_id and comp.license_id != "UNKNOWN":
            entry["licenses"] = [{"license": {"id": comp.license_id}}]
        components_json.append(entry)

    comp_ref_by_name = {c.name: (c.purl or c.name) for c in report.components}
    for src, dst in report.dependency_edges:
        src_ref = comp_ref_by_name.get(src, src)
        dst_ref = comp_ref_by_name.get(dst, dst)
        deps_map.setdefault(src_ref, [])
        if dst_ref not in deps_map[src_ref]:
            deps_map[src_ref].append(dst_ref)

    vulns_json: List[Dict[str, Any]] = []
    for v in report.vulnerabilities:
        vulns_json.append(
            {
                "id": v.id,
                "source": {"name": v.source},
                "ratings": [{"severity": str(v.severity).lower(), "score": v.cvss_score}],
                "description": v.summary,
                "recommendation": v.remediation,
                "affects": [{"ref": comp_ref_by_name.get(v.component_name, v.component_name)}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"vendor": "OpenGuard", "name": "OpenGuard SBOM Engine", "version": report.tool_version}],
            "component": {
                "type": "application",
                "name": report.target_name,
                "licenses": [{"license": {"id": report.project_license}}] if report.project_license != "UNKNOWN" else [],
            },
        },
        "components": components_json,
        "dependencies": [{"ref": k, "dependsOn": v} for k, v in deps_map.items()],
        "vulnerabilities": vulns_json,
    }


def render_spdx(report: AuditReport) -> Dict[str, Any]:
    """Export SBOM in SPDX 2.3 JSON specification."""
    packages: List[Dict[str, Any]] = [
        {
            "SPDXID": "SPDXRef-RootPackage",
            "name": report.target_name,
            "versionInfo": "HEAD",
            "downloadLocation": "NOASSERTION",
            "licenseDeclared": report.project_license if report.project_license != "UNKNOWN" else "NOASSERTION",
            "licenseConcluded": report.project_license if report.project_license != "UNKNOWN" else "NOASSERTION",
        }
    ]
    relationships: List[Dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-RootPackage",
        }
    ]

    for idx, comp in enumerate(report.components, start=1):
        spdx_id = f"SPDXRef-Package-{idx}"
        lic = comp.license_id if comp.license_id != "UNKNOWN" else "NOASSERTION"
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "licenseDeclared": lic,
                "licenseConcluded": lic,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl,
                    }
                ]
                if comp.purl
                else [],
            }
        )
        if comp.direct:
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-RootPackage",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": spdx_id,
                }
            )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{report.target_name}-sbom",
        "documentNamespace": f"https://openguard.local/spdx/{report.scan_id}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [f"Tool: OpenGuard-{report.tool_version}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
