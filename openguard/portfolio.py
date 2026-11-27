"""Snyk Org / Dependency-Track-inspired Multi-Repository Portfolio Batch Auditor & JSONL Streamer.

Audits multiple repositories under a parent directory (or explicit list of targets),
streams compact per-repository records as newline-delimited JSONL (`.jsonl`) for
SIEM/BI ingestion, and generates a ranked Markdown compliance portfolio report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig, DEFAULT_EXCLUDE_DIRS, load_config

REPO_MARKER_FILES = (
    ".git",
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "CMakeLists.txt",
)


@dataclass
class PortfolioRepoSummary:
    """Compact portfolio-level record for one audited repository."""

    repo_name: str
    repo_path: str
    total_score: float
    grade: str
    quality_gate: str
    project_license: str
    secrets_count: int
    p0_vulns_count: int
    kev_vulns_count: int
    license_conflicts_count: int
    code_security_count: int
    components_count: int
    scan_duration_ms: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "repo_path": self.repo_path,
            "total_score": self.total_score,
            "grade": self.grade,
            "quality_gate": self.quality_gate,
            "project_license": self.project_license,
            "secrets_count": self.secrets_count,
            "p0_vulns_count": self.p0_vulns_count,
            "kev_vulns_count": self.kev_vulns_count,
            "license_conflicts_count": self.license_conflicts_count,
            "code_security_count": self.code_security_count,
            "components_count": self.components_count,
            "scan_duration_ms": self.scan_duration_ms,
            "error": self.error,
        }


@dataclass
class PortfolioAuditResult:
    """Aggregate portfolio batch audit result."""

    audited_at: str
    total_repos: int = 0
    passed_gates: int = 0
    failed_gates: int = 0
    average_score: float = 0.0
    repos: List[PortfolioRepoSummary] = field(default_factory=list)


def discover_child_repositories(parent_dir: Path) -> List[Path]:
    """Discover immediate child project directories under `parent_dir`."""
    root = Path(parent_dir).resolve()
    if not root.is_dir():
        return []
    found: List[Path] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or child.name.startswith(".") or child.name in DEFAULT_EXCLUDE_DIRS:
            continue
        has_marker = any((child / m).exists() for m in REPO_MARKER_FILES)
        has_source = has_marker or any(
            f.is_file() and f.suffix.lower() in (".py", ".js", ".ts", ".go", ".java", ".rs", ".c", ".cpp")
            for f in child.iterdir()
        )
        if has_source:
            found.append(child)
    return found


class PortfolioAuditor:
    """Orchestrates batch security & compliance auditing across multiple repositories."""

    def audit_repositories(
        self,
        repo_paths: List[Path],
        *,
        offline: bool = True,
        use_cache: bool = False,
        jsonl_out: Optional[Path] = None,
        md_out: Optional[Path] = None,
    ) -> PortfolioAuditResult:
        result = PortfolioAuditResult(
            audited_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            total_repos=len(repo_paths),
        )

        jsonl_fp = None
        if jsonl_out is not None:
            out_p = Path(jsonl_out)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            jsonl_fp = out_p.open("w", encoding="utf-8")

        try:
            for rpath in repo_paths:
                rp = Path(rpath)
                cfg = load_config(rp if rp.is_dir() else rp.parent) if rp.exists() else AuditConfig()
                cfg.offline = offline
                cfg.use_cache = use_cache
                try:
                    rep = OpenGuardAuditor(cfg).audit(rpath)
                    qg = rep.summary.quality_gate.status if rep.summary.quality_gate else "N/A"
                    p0_cnt = sum(1 for v in rep.vulnerabilities if v.priority_tier == "P0")
                    kev_cnt = sum(1 for v in rep.vulnerabilities if v.in_cisa_kev)
                    entry = PortfolioRepoSummary(
                        repo_name=rep.target_name,
                        repo_path=str(Path(rpath).resolve()),
                        total_score=rep.summary.total_score,
                        grade=rep.summary.grade,
                        quality_gate=qg,
                        project_license=rep.project_license,
                        secrets_count=len(rep.secrets) + len(rep.git_history_secrets),
                        p0_vulns_count=p0_cnt,
                        kev_vulns_count=kev_cnt,
                        license_conflicts_count=len(rep.license_conflicts),
                        code_security_count=len(rep.code_security_findings),
                        components_count=len(rep.components),
                        scan_duration_ms=rep.summary.scan_duration_ms,
                    )
                    if qg == "PASSED":
                        result.passed_gates += 1
                    else:
                        result.failed_gates += 1
                except Exception as exc:
                    entry = PortfolioRepoSummary(
                        repo_name=Path(rpath).name,
                        repo_path=str(Path(rpath).resolve()),
                        total_score=0.0,
                        grade="F",
                        quality_gate="ERROR",
                        project_license="UNKNOWN",
                        secrets_count=0,
                        p0_vulns_count=0,
                        kev_vulns_count=0,
                        license_conflicts_count=0,
                        code_security_count=0,
                        components_count=0,
                        scan_duration_ms=0.0,
                        error=str(exc),
                    )
                    result.failed_gates += 1

                result.repos.append(entry)
                if jsonl_fp is not None:
                    jsonl_fp.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
                    jsonl_fp.flush()
        finally:
            if jsonl_fp is not None:
                jsonl_fp.close()

        valid_scores = [r.total_score for r in result.repos if r.error is None]
        result.average_score = round(sum(valid_scores) / len(valid_scores), 1) if valid_scores else 0.0
        result.repos.sort(key=lambda r: (r.quality_gate == "PASSED", r.total_score))

        if md_out is not None:
            mp = Path(md_out)
            mp.parent.mkdir(parents=True, exist_ok=True)
            mp.write_text(render_portfolio_markdown(result), encoding="utf-8")

        return result


def render_portfolio_markdown(result: PortfolioAuditResult) -> str:
    """Render a ranked organization/competition portfolio security report in Markdown."""
    pass_rate = (result.passed_gates / result.total_repos * 100.0) if result.total_repos else 0.0
    lines: List[str] = [
        "# OpenGuard 多仓库组合安全与合规审计汇总 (Portfolio Report)",
        "",
        f"> **审计仓库总数**: `{result.total_repos}` | **门禁通过率**: **{pass_rate:.1f}%** "
        f"(`PASSED {result.passed_gates}` / `FAILED {result.failed_gates}`) | "
        f"**平均合规得分**: **{result.average_score:.1f} / 100** | **时间**: `{result.audited_at}`",
        "",
        "| 仓库名称 | 综合评分 | 门禁状态 | 主许可证 | 密钥泄露 | P0 漏洞 (KEV) | 许可证冲突 | 代码/配置缺陷 | SBOM 组件 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for r in result.repos:
        lines.append(
            f"| `{r.repo_name}` | **{r.total_score:.1f}** (`{r.grade}`) | **{r.quality_gate}** | "
            f"`{r.project_license}` | {r.secrets_count} | {r.p0_vulns_count} ({r.kev_vulns_count}) | "
            f"{r.license_conflicts_count} | {r.code_security_count} | {r.components_count} |"
        )
    lines.append("")
    return "\n".join(lines)
