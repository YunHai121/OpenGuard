"""5-Dimension Weighted Health Scoring & Prioritized Remediation Roadmap Engine."""

from __future__ import annotations

import math
from typing import Any, Dict, List

from openguard.config import DEFAULT_WEIGHTS
from openguard.models import (
    AuditSummary,
    CodeSecurityFinding,
    DimensionScore,
    GovernanceCheckItem,
    LicenseCompatibility,
    LicenseConflict,
    SecretFinding,
    Severity,
    VulnerabilityFinding,
)

SEVERITY_PENALTIES: Dict[str, float] = {
    Severity.CRITICAL.value: 28.0,
    Severity.HIGH.value: 16.0,
    Severity.MEDIUM.value: 8.0,
    Severity.LOW.value: 3.0,
    Severity.INFO.value: 0.0,
}


def _dim_score_from_penalties(penalties: List[float]) -> float:
    """Apply smooth saturating decay so severe issues hit hard without collapsing everything to zero immediately."""
    if not penalties:
        return 100.0
    total_penalty = sum(penalties)
    # Smooth exponential-like saturation curve combined with linear floor penalty
    score = 100.0 * math.exp(-total_penalty / 75.0)
    return round(max(0.0, min(100.0, score)), 1)


def _compute_grade(score: float) -> str:
    if score >= 95.0:
        return "A+"
    if score >= 90.0:
        return "A"
    if score >= 85.0:
        return "B+"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C"
    if score >= 60.0:
        return "D"
    return "F"


class ScoringEngine:
    """Computes transparent multi-dimensional compliance scores and remediation roadmaps."""

    def __init__(self, weights: Dict[str, float] | None = None) -> None:
        raw_w = weights or DEFAULT_WEIGHTS
        total_w = sum(raw_w.values()) or 1.0
        self.weights = {k: v / total_w for k, v in raw_w.items()}

    def evaluate(
        self,
        secrets: List[SecretFinding],
        git_history_secrets: List[SecretFinding],
        vulnerabilities: List[VulnerabilityFinding],
        license_conflicts: List[LicenseConflict],
        code_security_findings: List[CodeSecurityFinding],
        governance_checks: List[GovernanceCheckItem],
        files_scanned: int = 0,
        lines_scanned: int = 0,
        scan_duration_ms: float = 0.0,
    ) -> AuditSummary:
        # 1. Secret Security Dimension
        sec_penalties = [SEVERITY_PENALTIES.get(str(f.severity), 10.0) for f in secrets]
        # Historical ghost secrets also carry significant penalty (75% of active penalty)
        sec_penalties.extend(SEVERITY_PENALTIES.get(str(f.severity), 10.0) * 0.75 for f in git_history_secrets)
        sec_score = _dim_score_from_penalties(sec_penalties)
        sec_count = len(secrets) + len(git_history_secrets)

        # 2. Supply Chain Vulnerability Dimension
        vuln_penalties = [SEVERITY_PENALTIES.get(str(v.severity), 10.0) for v in vulnerabilities]
        vuln_score = _dim_score_from_penalties(vuln_penalties)

        # 3. License Compliance Dimension
        lic_penalties: List[float] = []
        for lc in license_conflicts:
            if str(lc.compatibility) == LicenseCompatibility.INCOMPATIBLE.value:
                lic_penalties.append(SEVERITY_PENALTIES.get(str(lc.severity), 18.0))
            elif str(lc.compatibility) == LicenseCompatibility.REVIEW_REQUIRED.value:
                lic_penalties.append(6.0)
        lic_score = _dim_score_from_penalties(lic_penalties)

        # 4. Code Security (SAST) Dimension
        sast_penalties = [SEVERITY_PENALTIES.get(str(c.severity), 8.0) for c in code_security_findings]
        sast_score = _dim_score_from_penalties(sast_penalties)

        # 5. Governance & Documentation Dimension
        max_gov = sum(g.max_score for g in governance_checks) or 100.0
        earned_gov = sum(g.score for g in governance_checks)
        gov_score = round((earned_gov / max_gov) * 100.0, 1)
        gov_issues = sum(1 for g in governance_checks if not g.passed)

        dimensions = [
            DimensionScore(
                name="密钥与敏感信息防护",
                key="secret_security",
                score=sec_score,
                weight=round(self.weights.get("secret_security", 0.30), 2),
                weighted_score=round(sec_score * self.weights.get("secret_security", 0.30), 2),
                issue_count=sec_count,
                summary=f"工作区命中 {len(secrets)} 处，Git 历史残留 {len(git_history_secrets)} 处",
            ),
            DimensionScore(
                name="供应链漏洞与投毒防护",
                key="supply_chain_vuln",
                score=vuln_score,
                weight=round(self.weights.get("supply_chain_vuln", 0.20), 2),
                weighted_score=round(vuln_score * self.weights.get("supply_chain_vuln", 0.20), 2),
                issue_count=len(vulnerabilities),
                summary=f"发现 {len(vulnerabilities)} 项已知 CVE 或仿冒包隐患",
            ),
            DimensionScore(
                name="开源许可证合规",
                key="license_compliance",
                score=lic_score,
                weight=round(self.weights.get("license_compliance", 0.20), 2),
                weighted_score=round(lic_score * self.weights.get("license_compliance", 0.20), 2),
                issue_count=len(license_conflicts),
                summary=f"存在 {len(license_conflicts)} 项许可证冲突或需人工复核传染条款",
            ),
            DimensionScore(
                name="静态代码安全 (SAST)",
                key="code_security",
                score=sast_score,
                weight=round(self.weights.get("code_security", 0.15), 2),
                weighted_score=round(sast_score * self.weights.get("code_security", 0.15), 2),
                issue_count=len(code_security_findings),
                summary=f"AST/规则检出 {len(code_security_findings)} 处高危编码模式",
            ),
            DimensionScore(
                name="开源工程治理与文档",
                key="governance",
                score=gov_score,
                weight=round(self.weights.get("governance", 0.15), 2),
                weighted_score=round(gov_score * self.weights.get("governance", 0.15), 2),
                issue_count=gov_issues,
                summary=f"12 项开源工程规范通过 {len(governance_checks) - gov_issues} 项",
            ),
        ]

        total_score = round(sum(d.weighted_score for d in dimensions), 1)
        grade = _compute_grade(total_score)

        # Severity breakdown
        severity_counts: Dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for item in [*secrets, *git_history_secrets, *vulnerabilities, *license_conflicts, *code_security_findings]:
            sev = str(item.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        severity_counts[Severity.LOW.value] += gov_issues

        roadmap = self._build_roadmap(
            secrets, git_history_secrets, vulnerabilities, license_conflicts, code_security_findings, governance_checks
        )

        return AuditSummary(
            total_score=total_score,
            grade=grade,
            dimensions=dimensions,
            severity_counts=severity_counts,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            scan_duration_ms=round(scan_duration_ms, 2),
            roadmap=roadmap,
        )

    @staticmethod
    def _build_roadmap(
        secrets: List[SecretFinding],
        git_history_secrets: List[SecretFinding],
        vulnerabilities: List[VulnerabilityFinding],
        license_conflicts: List[LicenseConflict],
        code_security_findings: List[CodeSecurityFinding],
        governance_checks: List[GovernanceCheckItem],
    ) -> List[Dict[str, Any]]:
        roadmap: List[Dict[str, Any]] = []

        if secrets:
            roadmap.append(
                {
                    "priority": "P0 - 立即阻断",
                    "title": f"轮换并清理工作区 {len(secrets)} 处明文敏感凭据",
                    "action": "运行 `openguard autofix <target> --secrets --dry-run` 预览脱敏重构补丁并轮换对应云端/平台 Key。",
                    "impact": "直接消除凭据泄露与盗刷风险，显著提升密钥安全得分。",
                }
            )
        if git_history_secrets:
            roadmap.append(
                {
                    "priority": "P0 - 历史净化",
                    "title": f"清理 Git 提交历史中的 {len(git_history_secrets)} 处幽灵密钥",
                    "action": "轮换凭据后使用 `git filter-repo` 重写历史并强制推送，防止公开仓库回溯窃取。",
                    "impact": "彻底消除历史 Commit 中的隐藏泄密面。",
                }
            )
        incompat = [c for c in license_conflicts if str(c.compatibility) == LicenseCompatibility.INCOMPATIBLE.value]
        if incompat:
            roadmap.append(
                {
                    "priority": "P1 - 法务合规",
                    "title": f"解决 {len(incompat)} 项强传染性开源许可证冲突",
                    "action": "替换冲突的 GPL/AGPL 依赖库（如 " + ", ".join(c.component_name for c in incompat[:3]) + "），或统一项目许可证。",
                    "impact": "避免开源项目分发时的版权传染侵权纠纷。",
                }
            )
        if vulnerabilities:
            roadmap.append(
                {
                    "priority": "P1 - 供应链加固",
                    "title": f"升级或核验 {len(vulnerabilities)} 个存在已知 CVE/仿冒风险的依赖包",
                    "action": "依据漏洞报告中的安全版本号升级依赖清单并重新锁定版本。",
                    "impact": "阻断已知 RCE、原型链污染与供应链投毒风险。",
                }
            )
        if code_security_findings:
            roadmap.append(
                {
                    "priority": "P2 - 代码安全",
                    "title": f"重构 {len(code_security_findings)} 处高危代码模式 (SAST)",
                    "action": "替换 `yaml.load`、`eval`、`shell=True`、`verify=False` 等高危调用为安全 API。",
                    "impact": "提高静态代码健壮性与纵深防御能力。",
                }
            )
        missing_docs = [g for g in governance_checks if not g.passed]
        if missing_docs:
            roadmap.append(
                {
                    "priority": "P3 - 工程规范",
                    "title": f"补齐 {len(missing_docs)} 项开源文档与自动化防线",
                    "action": "运行 `openguard autofix <target> --docs --apply` 与 `openguard hook install <target>`。",
                    "impact": "全面达标开源项目规范度清单与持续防泄露门禁。",
                }
            )
        return roadmap
