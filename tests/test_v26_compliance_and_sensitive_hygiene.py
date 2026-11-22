"""Unit tests for Round #16: EU CRA / NIST SSDF / OWASP SCVS compliance mapper & sensitive artifact hygiene."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from openguard.auditor import OpenGuardAuditor
from openguard.cli import app as cli_app
from openguard.compliance import evaluate_compliance, render_compliance_markdown
from openguard.config import AuditConfig
from openguard.models import Severity
from openguard.reporters.markdown_reporter import render_markdown_report
from openguard.scanners.dockerfile_scanner import DockerfileScanner
from openguard.scanners.iac_scanner import IaCScanner
from openguard.web.app import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_REPO = REPO_ROOT / "examples" / "vulnerable_demo_repo"
runner = CliRunner()


class TestComplianceAndSensitiveArtifactHygiene(unittest.TestCase):
    def test_compliance_mapper_passes_on_openguard_and_flags_demo_repo(self) -> None:
        auditor = OpenGuardAuditor(AuditConfig(offline=True))
        clean_report = auditor.audit(REPO_ROOT)
        clean_comp = evaluate_compliance(clean_report)
        self.assertEqual(clean_comp["status"], "COMPLIANT")
        self.assertEqual(clean_comp["passed_count"], 8)
        self.assertEqual(clean_comp["compliance_rate"], 100.0)

        # Markdown report embeds Section 9 EU CRA / NIST SSDF / OWASP SCVS summary
        md_full = render_markdown_report(clean_report)
        self.assertIn("EU CRA / NIST SSDF / OWASP SCVS", md_full)
        self.assertIn("OG-CMP-01", md_full)

        # Vulnerable demo repo fails compliance controls & renders remediation markdown
        vuln_report = auditor.audit(DEMO_REPO)
        vuln_comp = evaluate_compliance(vuln_report)
        self.assertNotEqual(vuln_comp["status"], "COMPLIANT")
        self.assertLess(vuln_comp["passed_count"], 8)
        comp_md = render_compliance_markdown(vuln_comp)
        self.assertIn("需整改项与合规补齐指引", comp_md)

    def test_cli_compliance_and_web_api_compliance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_md = Path(tmp) / "cra_compliance.md"
            res_ok = runner.invoke(
                cli_app,
                ["compliance", str(REPO_ROOT), "--offline", "--json", "-o", str(out_md), "--fail-on-noncompliant"],
            )
            self.assertEqual(res_ok.exit_code, 0, msg=res_ok.output)
            parsed = json.loads(res_ok.stdout)
            self.assertEqual(parsed["status"], "COMPLIANT")
            self.assertTrue(out_md.is_file())
            self.assertIn("CRA Annex I", out_md.read_text(encoding="utf-8"))

            res_fail = runner.invoke(
                cli_app,
                ["compliance", str(DEMO_REPO), "--offline", "--json", "--fail-on-noncompliant"],
            )
            self.assertEqual(res_fail.exit_code, 1)

            # Web API /api/compliance/{scan_id}
            web_app = create_app(db_path=Path(tmp) / "hist.db")
            client = TestClient(web_app)
            scan_resp = client.post("/api/scan", json={"target": str(REPO_ROOT), "offline": True})
            self.assertEqual(scan_resp.status_code, 200)
            sid = scan_resp.json()["scan_id"]

            c_resp = client.get(f"/api/compliance/{sid}")
            self.assertEqual(c_resp.status_code, 200)
            self.assertEqual(c_resp.json()["status"], "COMPLIANT")
            self.assertEqual(client.get("/api/compliance/missing-id").status_code, 404)

    def test_sensitive_committed_files_and_dockerfile_secret_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Dangerous committed binary keystore, SSH key, and live .env
            (root / "release.p12").write_bytes(b"\x30\x82\x01\x00binary-keystore")
            (root / "id_rsa").write_text("dummy", encoding="utf-8")
            (root / ".env").write_text("PORT=8080\n", encoding="utf-8")
            # Benign templates must NOT trigger
            (root / ".env.example").write_text("PORT=8080\n", encoding="utf-8")
            (root / ".env.openguard.local").write_text("PORT=8080\n", encoding="utf-8")

            hyg_findings = IaCScanner().scan_repository(root)
            ids = [f.rule_id for f in hyg_findings]
            self.assertEqual(ids.count("OG-HYG-001"), 2)
            self.assertEqual(ids.count("OG-HYG-002"), 1)
            self.assertTrue(any(f.severity == Severity.CRITICAL and f.file_path == "release.p12" for f in hyg_findings))

            # Dockerfile COPY .env vs safe COPY .env.example
            df = (
                "FROM python:3.12-slim\n"
                "COPY .env.example /app/.env.example\n"
                "COPY .env /app/.env\n"
                "COPY server.pem /etc/ssl/server.pem\n"
                "USER appuser\n"
            )
            df_findings = DockerfileScanner().scan_content(df, "Dockerfile")
            copy_hits = [f for f in df_findings if f.rule_id == "OG-DOCKER-006"]
            self.assertEqual(len(copy_hits), 2)


if __name__ == "__main__":
    unittest.main()
