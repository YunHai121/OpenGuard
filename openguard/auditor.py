"""Top-level OpenGuard Auditor SDK orchestrating all engines, remediation, and exports."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from openguard.config import AuditConfig, load_config
from openguard.models import AuditReport
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.secret_remediator import RemediationResult, SecretRemediator
from openguard.reporters.badge_generator import render_badge_svg
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.markdown_reporter import render_markdown_report
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif, render_spdx
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.dependency_parser import DependencyParser
from openguard.scanners.git_history_scanner import GitHistoryScanner
from openguard.scanners.governance_checker import GovernanceChecker
from openguard.scanners.install_script_scanner import InstallScriptScanner
from openguard.scanners.license_analyzer import LicenseAnalyzer
from openguard.scanners.reachability_analyzer import ReachabilityAnalyzer
from openguard.scanners.secret_scanner import SecretScanner
from openguard.scanners.vuln_scanner import VulnScanner
from openguard.scoring.engine import ScoringEngine


def _is_remote_git_url(target: str) -> bool:
    t = target.strip()
    return t.startswith(("http://", "https://", "git@", "ssh://")) or t.endswith(".git") and "://" in t


class OpenGuardAuditor:
    """High-level SDK facade for running full OpenGuard supply-chain & compliance audits."""

    def __init__(self, config: Optional[AuditConfig] = None) -> None:
        self.base_config = config

    def audit(self, target: str | Path, config_path: Optional[Path] = None) -> AuditReport:
        """Audit a local directory, single file, or remote Git repository URL."""
        target_str = str(target).strip()
        if _is_remote_git_url(target_str):
            return self._audit_remote_repo(target_str, config_path=config_path)
        return self._audit_local_path(Path(target_str), config_path=config_path)

    def _audit_remote_repo(self, url: str, config_path: Optional[Path] = None) -> AuditReport:
        temp_dir = Path(tempfile.mkdtemp(prefix="openguard_clone_"))
        try:
            depth = "100" if (self.base_config and self.base_config.include_git_history) else "1"
            res = subprocess.run(
                ["git", "clone", "--depth", depth, url, str(temp_dir / "repo")],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
            )
            if res.returncode != 0:
                raise RuntimeError(f"克隆远程仓库失败: {res.stderr.strip() or res.stdout.strip()}")
            repo_dir = temp_dir / "repo"
            report = self._audit_local_path(repo_dir, config_path=config_path)
            report.target_path = url
            report.target_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            return report
        finally:
            def _rw_handler(func, path, _exc):
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except OSError:
                    pass

            shutil.rmtree(temp_dir, onexc=_rw_handler)

    def _audit_local_path(self, target_path: Path, config_path: Optional[Path] = None) -> AuditReport:
        resolved = target_path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"审计目标不存在: {resolved}")

        t0 = time.perf_counter()
        repo_root = resolved.parent if resolved.is_file() else resolved

        cfg = self.base_config or load_config(repo_root, config_path=config_path)
        if self.base_config and (repo_root / ".openguardignore").is_file():
            # Respect repo's .openguardignore even when explicit AuditConfig passed
            loaded_ignores = load_config(repo_root, config_path=config_path).exclude_patterns
            for pat in loaded_ignores:
                if pat not in cfg.exclude_patterns:
                    cfg.exclude_patterns.append(pat)

        # 1. Secret detection (3-Stage Hybrid Pipeline)
        secret_scanner = SecretScanner(cfg)
        secret_outcome = secret_scanner.scan_directory(resolved)
        head_hashes = {f.raw_hash for f in secret_outcome.findings}

        # 2. Git metadata & optional Git commit history ghost-secret scanning
        git_scanner = GitHistoryScanner(cfg, secret_scanner)
        git_branch, git_commit = git_scanner.get_git_metadata(repo_root)
        git_history_findings = []
        if cfg.include_git_history and not resolved.is_file():
            git_history_findings = git_scanner.scan_history(repo_root, head_secret_hashes=head_hashes)

        # 3. Multi-ecosystem Dependency Parsing -> SBOM + NetworkX Graph
        dep_parser = DependencyParser()
        components, edges, graph = dep_parser.parse_repository(resolved, exclude_patterns=cfg.exclude_patterns)

        # 4. SPDX License Detection & Copyleft Conflict Propagation
        license_analyzer = LicenseAnalyzer(override_project_license=cfg.project_license_override)
        project_license = license_analyzer.detect_project_license(repo_root)
        license_conflicts = license_analyzer.analyze_conflicts(
            project_name=repo_root.name,
            project_license=project_license,
            components=components,
            graph=graph,
        )

        # 5. Supply-Chain Vulnerabilities (Offline KB + OSV API + Typosquatting + Install Script Guard)
        vuln_scanner = VulnScanner(offline=cfg.offline)
        vulnerabilities = vuln_scanner.scan_components(components)
        install_script_alerts = InstallScriptScanner().scan_repository(resolved, exclude_patterns=cfg.exclude_patterns)
        vulnerabilities.extend(install_script_alerts)

        # 5b. Import-level CVE & Component Reachability Enrichment
        ReachabilityAnalyzer().enrich(
            resolved,
            components=components,
            vulnerabilities=vulnerabilities,
            exclude_patterns=cfg.exclude_patterns,
        )

        # 6. Static Application Security Testing (SAST)
        code_scanner = CodeSecurityScanner(cfg)
        code_findings = code_scanner.scan_directory(resolved)

        # 7. Open-Source Engineering Governance Checklist
        gov_checker = GovernanceChecker()
        governance_checks = gov_checker.check_repository(repo_root, project_license, components)

        duration_ms = (time.perf_counter() - t0) * 1000.0

        # 8. 5-Dimension Quantified Scoring Engine
        scorer = ScoringEngine(cfg.weights)
        summary = scorer.evaluate(
            secrets=secret_outcome.findings,
            git_history_secrets=git_history_findings,
            vulnerabilities=vulnerabilities,
            license_conflicts=license_conflicts,
            code_security_findings=code_findings,
            governance_checks=governance_checks,
            files_scanned=secret_outcome.files_scanned,
            lines_scanned=secret_outcome.lines_scanned,
            scan_duration_ms=duration_ms,
        )

        return AuditReport(
            target_path=str(resolved),
            target_name=resolved.name,
            project_license=project_license,
            git_branch=git_branch,
            git_commit=git_commit,
            summary=summary,
            secrets=secret_outcome.findings,
            git_history_secrets=git_history_findings,
            components=components,
            dependency_edges=edges,
            license_conflicts=license_conflicts,
            vulnerabilities=vulnerabilities,
            code_security_findings=code_findings,
            governance_checks=governance_checks,
            suppressed_count=secret_outcome.suppressed_count,
            suppressed_samples=secret_outcome.suppressed_samples,
        )

    def audit_snippet(self, code: str, filename: str = "snippet.py") -> AuditReport:
        """Run fast in-memory secret + SAST audit on a single code snippet (for IDE / Web Playground)."""
        t0 = time.perf_counter()
        cfg = self.base_config or AuditConfig(offline=True)
        sec_scanner = SecretScanner(cfg)
        sast_scanner = CodeSecurityScanner(cfg)

        sec_out = sec_scanner.scan_content(code, file_path=filename)
        sast_out = sast_scanner.scan_content(code, file_path=filename)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        scorer = ScoringEngine(cfg.weights)
        summary = scorer.evaluate(
            secrets=sec_out.findings,
            git_history_secrets=[],
            vulnerabilities=[],
            license_conflicts=[],
            code_security_findings=sast_out,
            governance_checks=[],
            files_scanned=1,
            lines_scanned=sec_out.lines_scanned,
            scan_duration_ms=duration_ms,
        )
        return AuditReport(
            target_path=filename,
            target_name=filename,
            project_license="N/A (Snippet)",
            summary=summary,
            secrets=sec_out.findings,
            code_security_findings=sast_out,
            suppressed_count=sec_out.suppressed_count,
            suppressed_samples=sec_out.suppressed_samples,
        )

    def autofix_secrets(self, target: str | Path, apply: bool = False) -> RemediationResult:
        """Preview or apply automated secret extraction into `.env.example` + env lookups."""
        root = Path(target).resolve()
        report = self.audit(root)
        return SecretRemediator().remediate(root, report, apply=apply)

    def autofix_docs(
        self,
        target: str | Path,
        license_id: str = "MIT",
        apply: bool = False,
        force: bool = False,
    ) -> Dict[str, str]:
        """Preview or create missing open-source governance documents."""
        return DocGenerator().generate(Path(target).resolve(), license_id=license_id, apply=apply, force=force)

    @staticmethod
    def export_report(report: AuditReport, fmt: str, output_path: Path) -> List[Path]:
        """Export an `AuditReport` into one or all supported formats (`html`, `pdf`, `json`, `sarif`, `md`, `cyclonedx`, `spdx`, `badge`, `all`)."""
        fmt_lower = fmt.lower().strip()
        out = Path(output_path)
        written: List[Path] = []

        if fmt_lower == "all":
            out.mkdir(parents=True, exist_ok=True)
            formats_to_files = {
                "json": out / "audit_report.json",
                "html": out / "audit_report.html",
                "pdf": out / "audit_report.pdf",
                "md": out / "audit_report.md",
                "sarif": out / "audit_report.sarif.json",
                "cyclonedx": out / "sbom.cyclonedx.json",
                "spdx": out / "sbom.spdx.json",
                "badge": out / "openguard_badge.svg",
            }
            for sub_fmt, target_file in formats_to_files.items():
                written.extend(OpenGuardAuditor.export_report(report, sub_fmt, target_file))
            return written

        out.parent.mkdir(parents=True, exist_ok=True)
        if fmt_lower == "json":
            out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        elif fmt_lower == "html":
            out.write_text(render_html_report(report), encoding="utf-8")
        elif fmt_lower == "pdf":
            out.write_bytes(render_pdf_bytes(report))
        elif fmt_lower in ("md", "markdown"):
            out.write_text(render_markdown_report(report), encoding="utf-8")
        elif fmt_lower == "sarif":
            out.write_text(json.dumps(render_sarif(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "cyclonedx":
            out.write_text(json.dumps(render_cyclonedx(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "spdx":
            out.write_text(json.dumps(render_spdx(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "badge":
            out.write_text(render_badge_svg(report), encoding="utf-8")
        else:
            raise ValueError(f"不支持的导出格式: {fmt}")

        written.append(out)
        return written
