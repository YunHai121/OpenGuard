"""Unit tests for v1.3+ Round #11 DX: `openguard init`, `openguard doctor`, `--json`, `--audit-mode`, and exit codes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from openguard.auditor import OpenGuardAuditor
from openguard.cli import app
from openguard.config import AuditConfig, load_config
from openguard.dx import EXIT_POLICY_VIOLATION, EXIT_USER_ERROR, detect_repo_stack, init_repository, run_doctor

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parent.parent


class TestDxInitDoctorAndCliContract(unittest.TestCase):
    def test_detect_stack_and_idempotent_init(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
            (root / "package.json").write_text('{"name": "demo-web", "version": "1.0.0"}\n', encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12-slim\nUSER nonroot\n", encoding="utf-8")
            (root / ".cursorrules").write_text("# Be helpful\n", encoding="utf-8")

            stack = detect_repo_stack(root)
            self.assertIn("PyPI", stack["ecosystems"])
            self.assertIn("npm", stack["ecosystems"])
            self.assertIn("Docker", stack["ecosystems"])
            self.assertIn("AI Coding Rules", stack["ecosystems"])

            first = init_repository(root, force=False)
            self.assertEqual(first["files"][".openguard.yml"], "created")
            self.assertEqual(first["files"][".openguardignore"], "created")
            self.assertEqual(first["files"][".openguard/rules/starter_policy.yml"], "created")

            # Tailored ignore must include both Python & npm patterns
            ignore_text = (root / ".openguardignore").read_text(encoding="utf-8")
            self.assertIn(".venv/", ignore_text)
            self.assertIn("node_modules/", ignore_text)

            # Generated .openguard.yml must parse cleanly via load_config
            cfg = load_config(root)
            self.assertTrue(cfg.use_cache)
            self.assertEqual(cfg.max_workers, 4)

            # Second run without force is strictly idempotent
            second = init_repository(root, force=False)
            self.assertEqual(second["files"][".openguard.yml"], "skipped (already exists)")

            # Force overwrites cleanly
            third = init_repository(root, force=True)
            self.assertEqual(third["files"][".openguard.yml"], "overwritten")

            # Starter policy creates zero false positives on clean repo
            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(root)
            self.assertEqual(len(report.code_security_findings), 0)

    def test_doctor_on_openguard_and_bare_and_broken_repo(self) -> None:
        self_diag = run_doctor(REPO_ROOT)
        self.assertTrue(self_diag["healthy"])
        self.assertEqual(self_diag["error_count"], 0)
        by_id = {c["id"]: c for c in self_diag["checks"]}
        self.assertEqual(by_id["OG-DOC-01"]["status"], "OK")
        self.assertEqual(by_id["OG-DOC-05"]["status"], "OK")
        self.assertEqual(by_id["OG-DOC-06"]["status"], "OK")

        with tempfile.TemporaryDirectory() as tmp:
            bare = Path(tmp)
            bare_diag = run_doctor(bare)
            self.assertTrue(bare_diag["healthy"])
            self.assertEqual(bare_diag["status"], "DEGRADED")
            self.assertGreaterEqual(bare_diag["warn_count"], 3)
            bare_by_id = {c["id"]: c for c in bare_diag["checks"]}
            self.assertIn("openguard init", bare_by_id["OG-DOC-03"]["fix_hint"])

            # Malformed YAML should trigger ERROR
            (bare / ".openguard.yml").write_text(":::invalid: [yaml\n", encoding="utf-8")
            broken_diag = run_doctor(bare)
            self.assertFalse(broken_diag["healthy"])
            self.assertEqual(broken_diag["status"], "ERROR")
            self.assertGreaterEqual(broken_diag["error_count"], 1)

    def test_cli_scan_pure_json_audit_mode_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Clean Python file
            (root / "hello.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")

            res_json = runner.invoke(app, ["scan", str(root), "--offline", "--json"])
            self.assertEqual(res_json.exit_code, 0, msg=res_json.output)
            parsed = json.loads(res_json.stdout)
            self.assertIn("summary", parsed)
            self.assertIn("total_score", parsed["summary"])

            # Add a high-severity SAST finding to test fail-on vs audit-mode
            (root / "danger.py").write_text(
                "import subprocess\ndef run(cmd):\n    subprocess.Popen(cmd, shell=True)\n",
                encoding="utf-8",
            )
            res_fail = runner.invoke(app, ["scan", str(root), "--offline", "--fail-on", "high", "--json"])
            self.assertEqual(res_fail.exit_code, EXIT_POLICY_VIOLATION)
            # Even when failing threshold, stdout stays valid pure JSON
            parsed_fail = json.loads(res_fail.stdout)
            self.assertGreaterEqual(len(parsed_fail["code_security_findings"]), 1)

            res_audit = runner.invoke(
                app, ["scan", str(root), "--offline", "--fail-on", "high", "--audit-mode", "--json"]
            )
            self.assertEqual(res_audit.exit_code, 0)

            # User / input errors must return exit code 2
            res_missing = runner.invoke(app, ["scan", str(root / "does_not_exist_12345")])
            self.assertEqual(res_missing.exit_code, EXIT_USER_ERROR)

            res_bad_thr = runner.invoke(app, ["scan", str(root), "--offline", "--fail-on", "bogus_level"])
            self.assertEqual(res_bad_thr.exit_code, EXIT_USER_ERROR)

            # CLI init & doctor --json
            res_init = runner.invoke(app, ["init", str(root), "--json"])
            self.assertEqual(res_init.exit_code, 0)
            init_data = json.loads(res_init.stdout)
            self.assertEqual(init_data["files"][".openguard.yml"], "created")

            res_doc = runner.invoke(app, ["doctor", str(root), "--json"])
            self.assertEqual(res_doc.exit_code, 0)
            doc_data = json.loads(res_doc.stdout)
            self.assertTrue(doc_data["healthy"])


if __name__ == "__main__":
    unittest.main()
