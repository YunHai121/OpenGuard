"""Regression tests for Round #25: PEP 503 typosquatting zero-FP & DependencyRemediator path guard."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.models import AuditReport, AuditSummary, DependencyComponent, Severity, VulnerabilityFinding
from openguard.remediation.dep_remediator import DependencyRemediator
from openguard.scanners.vuln_scanner import VulnScanner


class TestVulnTyposquatPep503AndDepGuard(unittest.TestCase):
    def test_py_pep503_equivalent_name_not_flagged_as_typosquat(self) -> None:
        comps = [
            DependencyComponent(
                name="python_dotenv",
                version="1.0.1",
                ecosystem="PyPI",
                source_file="requirements.txt",
                direct=True,
            ),
            DependencyComponent(
                name="reqeusts",
                version="2.31.0",
                ecosystem="PyPI",
                source_file="requirements.txt",
                direct=True,
            ),
        ]
        findings = VulnScanner(offline=True).scan_components(comps)
        typo_pkgs = {f.component_name for f in findings if f.id.startswith("OG-TYPO-")}
        self.assertNotIn("python_dotenv", typo_pkgs)
        self.assertIn("reqeusts", typo_pkgs)

    def test_dep_remediator_blocks_parent_traversal_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = base / "requirements.txt"
            outside.write_text("pyyaml==5.3.1\n", encoding="utf-8")
            repo = base / "repo"
            repo.mkdir()

            rep = AuditReport(
                target_path=str(repo),
                target_name="repo",
                summary=AuditSummary(total_score=70.0, grade="C", files_scanned=1, lines_scanned=1),
                components=[
                    DependencyComponent(
                        name="pyyaml",
                        version="5.3.1",
                        ecosystem="PyPI",
                        source_file="../requirements.txt",
                        direct=True,
                    )
                ],
                vulnerabilities=[
                    VulnerabilityFinding(
                        id="CVE-2020-14343",
                        component_name="pyyaml",
                        component_version="5.3.1",
                        ecosystem="PyPI",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        summary="unsafe yaml",
                        fixed_version="5.4.1",
                        source="offline_db",
                        source_file="../requirements.txt",
                    )
                ],
            )
            res = DependencyRemediator().remediate(repo, rep, apply=True)
            self.assertEqual(res.files_modified, 0)
            self.assertEqual(outside.read_text(encoding="utf-8"), "pyyaml==5.3.1\n")


if __name__ == "__main__":
    unittest.main()
