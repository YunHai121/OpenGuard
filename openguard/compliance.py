"""EU Cyber Resilience Act (CRA), NIST SSDF (SP 800-218) & OWASP SCVS Regulatory Compliance Mapper.

Maps OpenGuard audit findings, CycloneDX 1.5 SBOM quality scores, Call-Graph VEX statements,
SLSA provenance readiness, and governance checks into an auditor-ready compliance dossier.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List

from openguard.models import AuditReport, FindingCategory, LicenseCompatibility
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx
from openguard.sbom_tools import score_sbom_quality


def _val(x: Any) -> str:
    return str(x.value) if isinstance(x, Enum) else str(x)


def evaluate_compliance(report: AuditReport) -> Dict[str, Any]:
    """Evaluate 8 deterministic supply-chain regulatory controls across EU CRA, NIST SSDF & OWASP SCVS."""
    cdx = render_cyclonedx(report)
    sbom_qr = score_sbom_quality(cdx)

    # VEX exploitability breakdown across CVE findings
    cve_findings = [
        v for v in report.vulnerabilities if _val(v.category) == FindingCategory.VULNERABILITY.value
    ]
    call_reachable_cves = [v for v in cve_findings if v.reachability_level == "call_reachable"]
    import_only_cves = [v for v in cve_findings if v.reachability_level == "import_only"]
    unreachable_cves = [v for v in cve_findings if v.reachability_level == "unreachable"]
    kev_or_p0_cves = [
        v
        for v in cve_findings
        if v.in_cisa_kev
        or v.priority_tier == "P0"
        or (v.reachability_level == "call_reachable" and _val(v.severity).upper() in ("CRITICAL", "HIGH"))
    ]

    supply_attacks = [
        v
        for v in report.vulnerabilities
        if _val(v.category) in (FindingCategory.SUPPLY_CHAIN_SCRIPT.value, FindingCategory.TYPOSQUATTING.value)
    ]
    incompat_licenses = [
        lc for lc in report.license_conflicts if _val(lc.compatibility) == LicenseCompatibility.INCOMPATIBLE.value
    ]
    high_code_issues = [
        cs for cs in report.code_security_findings if _val(cs.severity).upper() in ("CRITICAL", "HIGH")
    ]
    gov_by_id = {g.check_id: g for g in report.governance_checks}
    sec_policy_ok = bool(gov_by_id.get("OG-GOV-005") and gov_by_id["OG-GOV-005"].passed)

    controls: List[Dict[str, Any]] = []

    def _add(
        cid: str,
        name: str,
        cra_ref: str,
        ssdf_ref: str,
        scvs_ref: str,
        passed: bool,
        evidence: str,
        remediation: str,
    ) -> None:
        controls.append(
            {
                "id": cid,
                "name": name,
                "eu_cra": cra_ref,
                "nist_ssdf": ssdf_ref,
                "owasp_scvs": scvs_ref,
                "status": "PASS" if passed else "FAIL",
                "passed": passed,
                "evidence": evidence,
                "remediation": "" if passed else remediation,
            }
        )

    # 1. SBOM Inventory & NTIA Minimum Elements
    sbom_pass = (len(report.components) == 0) or (sbom_qr.overall_score >= 7.0)
    _add(
        "OG-CMP-01",
        "机器可读 SBOM 清单与 NTIA 最小要素完整度",
        "CRA Annex I Part II (1)",
        "NIST SSDF PW.1",
        "OWASP SCVS V1",
        sbom_pass,
        f"CycloneDX 1.5 已覆盖 {len(report.components)} 个组件，NTIA 质量分 {sbom_qr.overall_score:.2f}/10.0 ({sbom_qr.grade})。",
        "补齐锁文件版本锁定与 SPDX 许可证元数据，执行 `openguard sbom-score . --min-score 7.0` 验证。",
    )

    # 2. Zero Known Exploited / Reachable Critical-High Vulnerabilities
    _add(
        "OG-CMP-02",
        "零在野利用 (CISA KEV) 与函数级可达高危漏洞",
        "CRA Annex I Part I (2)(a)",
        "NIST SSDF RV.1",
        "OWASP SCVS V2",
        len(kev_or_p0_cves) == 0,
        f"检出 {len(kev_or_p0_cves)} 项 P0/KEV 或函数级可达高危 CVE（总 CVE {len(cve_findings)} 项）。",
        "优先执行 `openguard autofix . --deps --apply` 升级所有 P0/KEV 与函数级可达漏洞依赖。",
    )

    # 3. VEX Exploitability Triage Documentation
    vex_pass = len(kev_or_p0_cves) == 0
    _add(
        "OG-CMP-03",
        "VEX 可利用性研判证明 (24h/72h 漏洞披露就绪)",
        "CRA Art. 14",
        "NIST SSDF RV.1 / RV.2",
        "OWASP SCVS V3",
        vex_pass,
        f"Call-Graph VEX 研判：exploitable={len(call_reachable_cves)}, in_triage={len(import_only_cves)}, not_affected(code_not_reachable)={len(unreachable_cves)}。",
        "针对 exploitable 漏洞立即处置，并通过 `--format cyclonedx` 导出带 VEX analysis 声明的合规证明。",
    )

    # 4. Coordinated Vulnerability Disclosure Policy (SECURITY.md)
    _add(
        "OG-CMP-04",
        "协调式安全漏洞披露政策 (SECURITY.md)",
        "CRA Annex I Part II (5)",
        "NIST SSDF RV.1.3",
        "OWASP SCVS V1",
        sec_policy_ok,
        "已提供标准 `SECURITY.md` 安全响应与私密上报渠道。" if sec_policy_ok else "仓库缺失 `SECURITY.md` 安全漏洞披露政策文档。",
        "执行 `openguard autofix . --docs --apply` 自动补齐标准 `SECURITY.md`。",
    )

    # 5. Zero Hardcoded Secrets & Git History Hygiene
    total_secrets = len(report.secrets) + len(report.git_history_secrets)
    _add(
        "OG-CMP-05",
        "零硬编码凭据泄露与 Git 历史洁净度",
        "CRA Annex I Part I (2)(c)",
        "NIST SSDF PS.1 / PW.4",
        "OWASP SCVS V5",
        total_secrets == 0,
        f"工作区命中 {len(report.secrets)} 处凭据，Git 历史残留 {len(report.git_history_secrets)} 处。",
        "轮换泄露凭据并执行 `openguard autofix . --secrets --apply` 重构为环境变量。",
    )

    # 6. License & IP Legal Compliance
    lic_pass = report.project_license != "UNKNOWN" and len(incompat_licenses) == 0
    _add(
        "OG-CMP-06",
        "开源许可证合规与零强传染性冲突",
        "CRA Technical Docs / OSS IP",
        "NIST SSDF PW.4",
        "OWASP SCVS V1",
        lic_pass,
        f"主许可证 `{report.project_license}`，检出 {len(incompat_licenses)} 项强传染性冲突（INCOMPATIBLE）。",
        "明确声明项目主 SPDX 许可证并替换或隔离强传染性（GPL/AGPL）冲突依赖。",
    )

    # 7. Secure Coding, Taint & Cloud/CI/AI Hardening
    _add(
        "OG-CMP-07",
        "安全编码、污点分析与云原生/CI/AI 配置加固",
        "CRA Annex I Part I (2)",
        "NIST SSDF PW.7 / PW.8",
        "OWASP SCVS V4 / V5",
        len(high_code_issues) == 0,
        f"检出 {len(high_code_issues)} 项 CRITICAL/HIGH 级 SAST/污点/CI/Dockerfile/IaC/AI 配置隐患。",
        "优先修复高危污点注入、未锁 SHA 工作流、特权容器及敏感提交文件。",
    )

    # 8. Supply-Chain Integrity (Zero Malicious Hooks / Lockfile Tampering)
    _add(
        "OG-CMP-08",
        "供应链构建完整度与零恶意安装脚本/锁文件篡改",
        "CRA Annex I Part I (2)(f)",
        "NIST SSDF PS.3",
        "OWASP SCVS V4",
        len(supply_attacks) == 0,
        f"检出 {len(supply_attacks)} 项恶意生命周期脚本、.pth 后门、仿冒包或锁文件篡改告警。",
        "立即移除恶意安装钩子/仿冒包，修复锁文件 integrity 并通过 `openguard attest generate` 产出 SLSA v1.0 证明。",
    )

    passed_count = sum(1 for c in controls if c["passed"])
    total_controls = len(controls)
    rate = round((passed_count / total_controls) * 100.0, 1) if total_controls else 100.0
    status = "COMPLIANT" if passed_count == total_controls else ("PARTIAL" if passed_count >= 5 else "NON_COMPLIANT")

    return {
        "target_name": report.target_name,
        "scan_id": report.scan_id,
        "status": status,
        "passed_count": passed_count,
        "total_controls": total_controls,
        "compliance_rate": rate,
        "sbom_quality_score": sbom_qr.overall_score,
        "sbom_quality_grade": sbom_qr.grade,
        "vex_summary": {
            "total_cves": len(cve_findings),
            "exploitable_call_reachable": len(call_reachable_cves),
            "in_triage_import_only": len(import_only_cves),
            "not_affected_unreachable": len(unreachable_cves),
        },
        "controls": controls,
    }


def render_compliance_markdown(data: Dict[str, Any]) -> str:
    """Render an auditor-ready Markdown compliance mapping report."""
    vex = data["vex_summary"]
    lines = [
        f"# OpenGuard 合规映射审计报告 (EU CRA / NIST SSDF / OWASP SCVS) — `{data['target_name']}`",
        "",
        f"> **合规状态**: **{data['status']}** ({data['passed_count']}/{data['total_controls']} 项通过 · "
        f"达标率 **{data['compliance_rate']:.1f}%**) | "
        f"**NTIA SBOM 质量分**: `{data['sbom_quality_score']:.2f}/10.0 ({data['sbom_quality_grade']})` | "
        f"**VEX 研判**: `exploitable={vex['exploitable_call_reachable']}`, `in_triage={vex['in_triage_import_only']}`, `not_affected={vex['not_affected_unreachable']}`",
        "",
        "| 控制编号 | 合规控制项 | EU CRA | NIST SSDF | OWASP SCVS | 状态 | 审计证据 |",
        "| :--- | :--- | :--- | :--- | :--- | :---: | :--- |",
    ]
    for c in data["controls"]:
        badge = "**PASS**" if c["passed"] else "**FAIL**"
        lines.append(
            f"| `{c['id']}` | {c['name']} | {c['eu_cra']} | {c['nist_ssdf']} | {c['owasp_scvs']} | {badge} | {c['evidence']} |"
        )
    failed = [c for c in data["controls"] if not c["passed"]]
    if failed:
        lines.extend(["", "## 需整改项与合规补齐指引", ""])
        for c in failed:
            lines.append(f"- **`{c['id']}` {c['name']}** ({c['eu_cra']} / {c['nist_ssdf']}): {c['remediation']}")
    lines.append("")
    return "\n".join(lines)
