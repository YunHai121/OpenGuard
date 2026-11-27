"""Regression tests for Round #31: --staged pre-commit wiring in OpenGuardAuditor & HTML category labels."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.models import AuditReport, AuditSummary, CodeSecurityFinding, Severity
from openguard.reporters.html_reporter import render_html_report


class TestStagedOnlyAndHtmlLabels(unittest.TestCase):
    def test_auditor_staged_only_scans_only_staged_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)

            (repo / "README.md").write_text("# Clean\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)

            # Unstaged secret in working tree must be ignored in --staged mode
            (repo / "unstaged.py").write_text(
                'KEY_U = "sk-proj-K9mP4xR7vN2qL8wZ5cT1yB6hJ3fD0sA9eG4uW"\n',
                encoding="utf-8",
            )
            # Staged secret must be caught in --staged mode
            (repo / "staged.py").write_text(
                'KEY_S = "sk-proj-Q8rT3wY6uI9oP2aS5dF7gH4jK1lZ0xC8vB3nM"\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "staged.py"], cwd=repo, capture_output=True, check=True)

            rep = OpenGuardAuditor(AuditConfig(offline=True, staged_only=True)).audit(repo)
            files = {s.file_path for s in rep.secrets}
            self.assertEqual(files, {"staged.py"})

    def test_html_reporter_renders_ml_and_hygiene_labels(self) -> None:
        rep = AuditReport(
            target_path=".",
            target_name="demo",
            summary=AuditSummary(total_score=80.0, grade="B", files_scanned=2, lines_scanned=10),
            code_security_findings=[
                CodeSecurityFinding(
                    rule_id="OG-ML-001",
                    rule_name="Malicious Pickle",
                    cwe_id="CWE-502",
                    severity=Severity.CRITICAL,
                    file_path="m.pkl",
                    line_number=1,
                    snippet="os.system",
                    description="bad pickle",
                    remediation="use safetensors",
                ),
                CodeSecurityFinding(
                    rule_id="OG-HYG-001",
                    rule_name="Private Key File",
                    cwe_id="CWE-312",
                    severity=Severity.CRITICAL,
                    file_path="id_rsa",
                    line_number=1,
                    snippet="id_rsa",
                    description="private key",
                    remediation="remove",
                ),
            ],
        )
        html_out = render_html_report(rep)
        self.assertIn("ML 模型安全", html_out)
        self.assertIn("敏感产物卫生", html_out)


if __name__ == "__main__":
    unittest.main()
