"""Regression tests for Round #23: SecretRemediator RHS key-preserving fix & IaC private key hygiene."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.remediation.secret_remediator import SecretRemediator
from openguard.scanners.iac_scanner import IaCScanner


class TestRemediatorRhsAndHygiene(unittest.TestCase):
    def test_secret_remediator_preserves_dict_json_key_and_handles_unquoted_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            py_file = repo / "cfg.py"
            py_file.write_text(
                'CFG = {\n    "openai_api_key": "sk-proj-K9mP4xR7vN2qL8wZ5cT1yB6hJ3fD0sA9eG4uW",\n}\n',
                encoding="utf-8",
            )
            env_file = repo / ".env.prod"
            env_file.write_text(
                "OPENAI_API_KEY=sk-proj-Q8rT3wY6uI9oP2aS5dF7gH4jK1lZ0xC8vB3nM\n",
                encoding="utf-8",
            )

            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(repo)
            res = SecretRemediator().remediate(repo, report, apply=True)
            self.assertEqual(res.files_modified, 2)

            fixed_py = py_file.read_text(encoding="utf-8")
            self.assertIn('"openai_api_key": os.getenv("OPENAI_API_KEY', fixed_py)

            fixed_env = env_file.read_text(encoding="utf-8")
            self.assertIn('OPENAI_API_KEY="${OPENAI_API_KEY', fixed_env)

    def test_iac_hygiene_flags_privkey_pem_and_ovpn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "privkey.pem").write_text("dummy", encoding="utf-8")
            (repo / "vpn.ovpn").write_text("dummy", encoding="utf-8")
            (repo / "ca.pem").write_text("public cert", encoding="utf-8")

            hits = IaCScanner().scan_repository(repo)
            paths = {h.file_path for h in hits if h.rule_id == "OG-HYG-001"}
            self.assertIn("privkey.pem", paths)
            self.assertIn("vpn.ovpn", paths)
            self.assertNotIn("ca.pem", paths)


if __name__ == "__main__":
    unittest.main()
