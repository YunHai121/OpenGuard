"""Regression tests for Round #19: config/auditor reliability, CI templates, CLI exit codes & Web API polish."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from openguard.auditor import OpenGuardAuditor, _safe_rmtree
from openguard.cli import app as cli_app
from openguard.config import AuditConfig, load_config
from openguard.remediation.hook_installer import PRE_COMMIT_SCRIPT, HookInstaller
from openguard.scanners.ci_workflow_scanner import CIWorkflowScanner
from openguard.web.app import create_app


class TestReliabilityCompatAndCI(unittest.TestCase):
    def test_load_config_accepts_str_and_auditor_does_not_mutate_base_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".openguardignore").write_text("ignored_dir/\n", encoding="utf-8")
            (repo / ".openguard.yml").write_text(
                "offline: true\npolicy:\n  denied_packages:\n    - evil-pkg\n",
                encoding="utf-8",
            )
            cfg = load_config(str(repo))
            self.assertIn("ignored_dir/", cfg.exclude_patterns)
            self.assertEqual(cfg.policy.get("denied_packages"), ["evil-pkg"])

            shared_cfg = AuditConfig(offline=True)
            orig_len = len(shared_cfg.exclude_patterns)
            OpenGuardAuditor(shared_cfg).audit(repo)
            self.assertEqual(len(shared_cfg.exclude_patterns), orig_len)
            self.assertEqual(shared_cfg.policy, {})

    def test_safe_rmtree_cleans_readonly_files(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="og_rm_"))
        ro_file = tmp / "readonly.txt"
        ro_file.write_text("locked", encoding="utf-8")
        os.chmod(ro_file, stat.S_IREAD)
        _safe_rmtree(tmp)
        self.assertFalse(tmp.exists())

    def test_hook_installer_github_template_passes_ci_scanner_and_precommit_has_no_dry_run(self) -> None:
        self.assertNotIn("--dry-run", PRE_COMMIT_SCRIPT)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            HookInstaller.generate_ci_config(repo, platform="github")
            HookInstaller.generate_ci_config(repo, platform="gitlab")
            findings = CIWorkflowScanner().scan_repository(repo)
            self.assertEqual(len(findings), 0, f"Unexpected CI findings: {findings}")
            self.assertNotIn("|| true", (repo / ".gitlab-ci.yml").read_text(encoding="utf-8"))

    def test_web_api_validation_compliance_export_and_autofix_major_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = tmp_path / "sample_repo"
            repo.mkdir()
            (repo / "README.md").write_text("# Sample\n", encoding="utf-8")
            (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

            client = TestClient(create_app(db_path=tmp_path / "test_og.db"))
            self.assertEqual(client.get("/api/doctor", params={"target": "   "}).status_code, 400)
            self.assertEqual(client.get("/api/aibom", params={"target": ""}).status_code, 400)

            scan_resp = client.post("/api/scan", json={"target": str(repo), "offline": True})
            self.assertEqual(scan_resp.status_code, 200)
            scan_id = scan_resp.json()["scan_id"]

            comp_resp = client.get(f"/api/export/{scan_id}/compliance")
            self.assertEqual(comp_resp.status_code, 200)
            self.assertIn("controls", comp_resp.json())

            slsa_resp = client.get(f"/api/export/{scan_id}/slsa")
            self.assertEqual(slsa_resp.status_code, 200)

            fix_resp = client.post(
                "/api/autofix/preview",
                json={"target": str(repo), "fix_secrets": False, "fix_docs": False, "fix_deps": True, "allow_major": False},
            )
            self.assertEqual(fix_resp.status_code, 200)
            deps = fix_resp.json()["deps"]
            self.assertIn("breaking_warnings", deps)
            self.assertIn("skipped_breaking", deps)

    def test_cli_nonexistent_paths_return_exit_code_2(self) -> None:
        runner = CliRunner()
        missing = str(Path(tempfile.gettempdir()) / "openguard_definitely_missing_dir_xyz")
        for args in (
            ["autofix", missing],
            ["sbom", missing],
            ["compliance", missing],
            ["aibom", missing],
        ):
            res = runner.invoke(cli_app, args)
            self.assertEqual(res.exit_code, 2, f"Expected exit 2 for {args}, got {res.exit_code}: {res.output}")


if __name__ == "__main__":
    unittest.main()
