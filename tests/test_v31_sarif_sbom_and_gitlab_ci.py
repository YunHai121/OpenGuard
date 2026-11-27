"""Regression tests for Round #21: CycloneDX bom-ref consistency & GitLab CI untagged/log-dump guards."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.models import AuditReport, AuditSummary, DependencyComponent, Severity, VulnerabilityFinding
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif
from openguard.scanners.ci_workflow_scanner import CIWorkflowScanner


class TestSarifSbomAndGitLabCI(unittest.TestCase):
    def test_cyclonedx_bom_ref_matches_dependencies_and_vulns_when_purl_empty(self) -> None:
        comp = DependencyComponent(
            name="custom-lib",
            version="1.2.3",
            ecosystem="PyPI",
            purl="",
            source_file="requirements.txt",
            direct=True,
        )
        vuln = VulnerabilityFinding(
            id="CVE-2026-0001",
            component_name="custom-lib",
            component_version="1.2.3",
            ecosystem="PyPI",
            severity=Severity.HIGH,
            cvss_score=7.5,
            summary="Test vulnerability",
            source="test",
        )
        report = AuditReport(
            target_path=".",
            target_name="demo",
            summary=AuditSummary(total_score=80.0, grade="B", files_scanned=1, lines_scanned=10),
            components=[comp],
            dependency_edges=[("demo", "custom-lib")],
            vulnerabilities=[vuln],
        )
        cdx = render_cyclonedx(report)
        comp_ref = cdx["components"][0]["bom-ref"]
        self.assertEqual(comp_ref, "PyPI:custom-lib@1.2.3")
        self.assertEqual(cdx["dependencies"][0]["dependsOn"][0], comp_ref)
        self.assertEqual(cdx["vulnerabilities"][0]["affects"][0]["ref"], comp_ref)

        sarif = render_sarif(report)
        self.assertIn("git.hust.edu.cn/U202414594/openguard", sarif["runs"][0]["tool"]["driver"]["informationUri"])

    def test_gitlab_ci_detects_untagged_image_and_env_log_dump_while_allowing_pinned_or_var(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitlab-ci.yml").write_text(
                "stages:\n"
                "  - test\n"
                "bad_job:\n"
                "  image: python\n"
                "  script:\n"
                "    - printenv | base64\n"
                "good_job:\n"
                "  image: registry.example.com/team/python:3.11-slim\n"
                "  script:\n"
                "    - pytest\n"
                "var_job:\n"
                "  image: $CI_REGISTRY_IMAGE/runner\n"
                "  script:\n"
                "    - echo ok\n",
                encoding="utf-8",
            )
            findings = CIWorkflowScanner().scan_repository(repo)
            ids = [f.rule_id for f in findings]
            self.assertIn("OG-CI-006", ids)
            self.assertIn("OG-CI-008", ids)
            self.assertEqual(ids.count("OG-CI-006"), 1)


if __name__ == "__main__":
    unittest.main()
