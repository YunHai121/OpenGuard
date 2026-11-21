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

from openguard.baseline import filter_by_baseline, get_git_diff_added_lines, load_baseline
from openguard.config import AuditConfig, load_config
from openguard.models import AuditReport
from openguard.remediation.dep_remediator import DependencyRemediator, DepRemediationResult
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.secret_remediator import RemediationResult, SecretRemediator
from openguard.reporters.badge_generator import render_badge_svg
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.markdown_reporter import render_markdown_report, render_pr_comment
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif, render_spdx
from openguard.reporters.slsa_provenance import render_slsa_provenance
from openguard.scanners.ai_config_scanner import AIConfigSecurityScanner
from openguard.scanners.ci_workflow_scanner import CIWorkflowScanner
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.dependency_parser import DependencyParser
from openguard.scanners.dockerfile_scanner import DockerfileScanner
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

        # 0. Optional Diff-Aware Incremental Scope (--diff <base_ref>)
        diff_added_map = (
            get_git_diff_added_lines(repo_root, base_ref=cfg.diff_ref)
            if (cfg.diff_ref and not resolved.is_file())
            else None
        )

        # 1. Secret detection (3-Stage Hybrid Pipeline)
        secret_scanner = SecretScanner(cfg)
        if diff_added_map is not None:
            secret_outcome = secret_scanner.scan_diff_lines(repo_root, diff_added_map, staged=False)
        else:
            secret_outcome = secret_scanner.scan_directory(resolved)
        head_hashes = {f.raw_hash for f in secret_outcome.findings}

        # 2. Git metadata & optional Git commit history ghost-secret scanning
        git_scanner = GitHistoryScanner(cfg, secret_scanner)
        git_branch, git_commit = git_scanner.get_git_metadata(repo_root)
        git_history_findings = []
        if cfg.include_git_history and not resolved.is_file() and diff_added_map is None:
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

        # 5b. Import- & Call-Graph CVE Reachability Enrichment
        ReachabilityAnalyzer().enrich(
            resolved,
            components=components,
            vulnerabilities=vulnerabilities,
            exclude_patterns=cfg.exclude_patterns,
        )

        # 6. Static Application Security Testing (SAST + CI/CD Workflow + Dockerfile + AI Config/Unicode)
        code_scanner = CodeSecurityScanner(cfg)
        code_findings = code_scanner.scan_directory(resolved)
        code_findings.extend(CIWorkflowScanner().scan_repository(resolved, exclude_patterns=cfg.exclude_patterns))
        code_findings.extend(DockerfileScanner().scan_repository(resolved, exclude_patterns=cfg.exclude_patterns))
        code_findings.extend(AIConfigSecurityScanner().scan_repository(resolved, exclude_patterns=cfg.exclude_patterns))

        # Apply Diff-Aware filtering to SAST / CI / Docker & manifest findings when --diff is active
        if diff_added_map is not None:
            changed_files = set(diff_added_map.keys())
            code_findings = [
                cs
                for cs in code_findings
                if cs.file_path in diff_added_map
                and (cs.line_number in diff_added_map[cs.file_path] or cs.line_number == 1)
            ]
            vulnerabilities = [
                v for v in vulnerabilities if (not v.source_file) or (v.source_file in changed_files)
            ]

        # 6b. Optional Baseline Suppression (Semgrep/Gitleaks-style legacy debt suppression)
        baseline_suppressed = 0
        if cfg.baseline_path:
            bpath = Path(cfg.baseline_path)
            if not bpath.is_absolute():
                bpath = (repo_root / bpath).resolve()
            fps = load_baseline(bpath)
            (
                secret_outcome.findings,
                git_history_findings,
                vulnerabilities,
                license_conflicts,
                code_findings,
                baseline_suppressed,
            ) = filter_by_baseline(
                secrets=secret_outcome.findings,
                git_history_secrets=git_history_findings,
                vulnerabilities=vulnerabilities,
                license_conflicts=license_conflicts,
                code_security_findings=code_findings,
                baseline_fingerprints=fps,
            )

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
            diff_base_ref=cfg.diff_ref,
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
            baseline_suppressed_count=baseline_suppressed,
        )

    def audit_snippet(self, code: str, filename: str = "snippet.py") -> AuditReport:
        """Run fast in-memory secret + SAST audit on a single code snippet (for IDE / Web Playground)."""
        t0 = time.perf_counter()
        cfg = self.base_config or AuditConfig(offline=True)
        sec_scanner = SecretScanner(cfg)
        sast_scanner = CodeSecurityScanner(cfg)

        sec_out = sec_scanner.scan_content(code, file_path=filename)
        sast_out = sast_scanner.scan_content(code, file_path=filename)
        sast_out.extend(AIConfigSecurityScanner().scan_content(code, filename))
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

    def autofix_deps(self, target: str | Path, apply: bool = False) -> DepRemediationResult:
        """Preview or apply safe minimum dependency upgrades for vulnerable manifest entries."""
        root = Path(target).resolve()
        report = self.audit(root)
        return DependencyRemediator().remediate(root, report, apply=apply)

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
                "slsa": out / "slsa_provenance.json",
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
        elif fmt_lower in ("pr-comment", "pr_comment"):
            out.write_text(render_pr_comment(report), encoding="utf-8")
        elif fmt_lower == "sarif":
            out.write_text(json.dumps(render_sarif(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "cyclonedx":
            out.write_text(json.dumps(render_cyclonedx(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "spdx":
            out.write_text(json.dumps(render_spdx(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "slsa":
            out.write_text(json.dumps(render_slsa_provenance(report), indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt_lower == "badge":
            out.write_text(render_badge_svg(report), encoding="utf-8")
        else:
            raise ValueError(f"不支持的导出格式: {fmt}")

        written.append(out)
        return written
