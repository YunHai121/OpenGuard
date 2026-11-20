"""Integration tests for FastAPI Web Workbench, SQLite Diff Store, LOC counter, and CLI."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from openguard.cli import app as cli_app
from openguard.utils.loc_counter import count_repository_loc
from openguard.web.app import create_app


class TestWebAndCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_history.db"
        self.client = TestClient(create_app(db_path=self.db_path))
        self.demo_src = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_health_presets_and_homepage(self) -> None:
        r_home = self.client.get("/")
        self.assertEqual(r_home.status_code, 200)
        self.assertIn("OpenGuard", r_home.text)

        self.assertEqual(self.client.get("/static/styles.css").status_code, 200)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)

        r_health = self.client.get("/api/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.json()["status"], "ok")

        r_presets = self.client.get("/api/presets")
        self.assertEqual(r_presets.status_code, 200)
        self.assertGreaterEqual(len(r_presets.json()), 1)

    def test_snippet_scan_endpoint(self) -> None:
        payload = {
            "filename": "snippet.py",
            "code": 'AWS = "AKIA7F4K9P2M8Q3X6Z1W"\nAPI_KEY = "sk-your_api_key_placeholder"\n',
        }
        res = self.client.post("/api/scan/snippet", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["secrets"]), 1)
        self.assertGreaterEqual(data["suppressed_count"], 1)

    def test_scan_history_diff_autofix_and_exports(self) -> None:
        work_repo = Path(self.tmp_dir.name) / "work_demo"
        shutil.copytree(self.demo_src, work_repo)

        # Scan 1 (before)
        r1 = self.client.post("/api/scan", json={"target": str(work_repo), "offline": True})
        self.assertEqual(r1.status_code, 200)
        scan1 = r1.json()
        sid1 = scan1["scan_id"]

        # Export PDF, HTML, SARIF, CycloneDX, Badge
        for fmt, expected_ct in [
            ("html", "text/html"),
            ("pdf", "application/pdf"),
            ("sarif", "application/json"),
            ("cyclonedx", "application/json"),
            ("badge", "image/svg+xml"),
        ]:
            exp = self.client.get(f"/api/export/{sid1}/{fmt}")
            self.assertEqual(exp.status_code, 200)
            self.assertIn(expected_ct, exp.headers.get("content-type", ""))

        # Preview & Apply autofix via API
        r_prev = self.client.post(
            "/api/autofix/preview",
            json={"target": str(work_repo), "fix_secrets": True, "fix_docs": True, "license_id": "MIT"},
        )
        self.assertEqual(r_prev.status_code, 200)
        self.assertFalse(r_prev.json()["applied"])

        r_app = self.client.post(
            "/api/autofix/apply",
            json={"target": str(work_repo), "fix_secrets": True, "fix_docs": True, "license_id": "MIT"},
        )
        self.assertEqual(r_app.status_code, 200)
        self.assertTrue(r_app.json()["applied"])
        (work_repo / ".openguardignore").write_text(".env.openguard.local\n", encoding="utf-8")

        # Scan 2 (after)
        r2 = self.client.post("/api/scan", json={"target": str(work_repo), "offline": True})
        self.assertEqual(r2.status_code, 200)
        sid2 = r2.json()["scan_id"]

        # Diff Before vs After
        r_diff = self.client.get(f"/api/diff/{sid1}/{sid2}")
        self.assertEqual(r_diff.status_code, 200)
        diff = r_diff.json()
        self.assertGreater(diff["score_delta"], 0)
        self.assertGreater(diff["resolved_count"], 0)

    def test_cli_commands_and_loc_counter(self) -> None:
        runner = CliRunner()
        res_ver = runner.invoke(cli_app, ["version"])
        self.assertEqual(res_ver.exit_code, 0)
        self.assertIn("OpenGuard", res_ver.stdout)

        res_scan = runner.invoke(cli_app, ["scan", str(self.demo_src), "--offline", "--fail-on", "critical"])
        self.assertEqual(res_scan.exit_code, 1)

        proj_root = Path(__file__).resolve().parents[1]
        loc = count_repository_loc(proj_root, exclude_subpaths=["examples/vulnerable_demo_repo"])
        self.assertGreater(loc["totals"]["code"], 2000)

    def test_cli_sbom_cloc_and_autofix_dry_run(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            sbom_out = Path(tmp) / "bom.cdx.json"
            r_sbom = runner.invoke(cli_app, ["sbom", str(self.demo_src), "--spec", "cyclonedx", "-o", str(sbom_out)])
            self.assertEqual(r_sbom.exit_code, 0)
            self.assertTrue(sbom_out.is_file())

            loc_out = Path(tmp) / "loc.json"
            r_cloc = runner.invoke(cli_app, ["cloc", str(self.demo_src), "--json-out", str(loc_out)])
            self.assertEqual(r_cloc.exit_code, 0)
            self.assertTrue(loc_out.is_file())

            r_fix = runner.invoke(cli_app, ["autofix", str(self.demo_src), "--secrets", "--docs"])
            self.assertEqual(r_fix.exit_code, 0)

    def test_api_error_handling_for_missing_targets_and_ids(self) -> None:
        r1 = self.client.post("/api/scan", json={"target": "/nonexistent/path/xyz123", "offline": True})
        self.assertEqual(r1.status_code, 404)

        r2 = self.client.get("/api/history/OG-DOESNOTEXIST")
        self.assertEqual(r2.status_code, 404)

        r3 = self.client.get("/api/diff/NOPE1/NOPE2")
        self.assertEqual(r3.status_code, 404)

        r4 = self.client.get("/api/export/OG-DOESNOTEXIST/pdf")
        self.assertEqual(r4.status_code, 404)

    def test_auditor_snippet_and_missing_target(self) -> None:
        from openguard import AuditConfig, OpenGuardAuditor

        auditor = OpenGuardAuditor(AuditConfig(offline=True))
        rep = auditor.audit_snippet('GH = "ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"\neval("1+1")\n', "x.py")
        self.assertEqual(len(rep.secrets), 1)
        self.assertEqual(len(rep.code_security_findings), 1)
        with self.assertRaises(FileNotFoundError):
            auditor.audit("/definitely/not/existing/path/99999")

    def test_single_file_audit_and_cli_hook_status(self) -> None:
        from openguard import AuditConfig, OpenGuardAuditor

        single_file = self.demo_src / "auth_service.py"
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(single_file)
        self.assertEqual(report.target_name, "auth_service.py")
        self.assertGreaterEqual(len(report.secrets), 3)

        runner = CliRunner()
        res_st = runner.invoke(cli_app, ["hook", "status", str(self.demo_src)])
        self.assertEqual(res_st.exit_code, 0)

    def test_cli_export_all_and_history_endpoints(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "cli_out"
            res = runner.invoke(
                cli_app,
                ["scan", str(self.demo_src), "--offline", "--format", "all", "--output", str(out_dir)],
            )
            self.assertEqual(res.exit_code, 0)
            self.assertTrue((out_dir / "audit_report.pdf").is_file())
            self.assertTrue((out_dir / "audit_report.html").is_file())

        r_hist = self.client.get("/api/history")
        self.assertEqual(r_hist.status_code, 200)
        self.assertIsInstance(r_hist.json(), list)

    def test_autofix_missing_target_returns_404(self) -> None:
        r = self.client.post(
            "/api/autofix/preview",
            json={"target": "/missing/repo/xyz", "fix_secrets": True, "fix_docs": True},
        )
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
