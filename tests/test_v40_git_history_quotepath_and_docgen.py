"""Regression tests for Round #30: GitHistoryScanner quotepath/deleted-file safety & DocGenerator gitignore."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.config import AuditConfig
from openguard.remediation.doc_generator import GITIGNORE_TEMPLATE
from openguard.scanners.git_history_scanner import GitHistoryScanner
from openguard.scanners.secret_scanner import SecretScanner


class TestGitHistoryQuotepathAndDocGen(unittest.TestCase):
    def test_git_history_scanner_handles_unicode_filename_and_deleted_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)

            secret_file = repo / "历史密钥.py"
            secret_file.write_text(
                'OPENAI_API_KEY = "sk-proj-K9mP4xR7vN2qL8wZ5cT1yB6hJ3fD0sA9eG4uW"\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "add secret"], cwd=repo, capture_output=True, check=True)

            secret_file.unlink()
            (repo / "clean.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "remove secret"], cwd=repo, capture_output=True, check=True)

            cfg = AuditConfig(offline=True, include_git_history=True)
            gh = GitHistoryScanner(cfg, SecretScanner(cfg))
            findings = gh.scan_history(repo)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file_path, "历史密钥.py")
            self.assertTrue(findings[0].is_historical_only)

    def test_doc_generator_gitignore_covers_keystore_and_registry_creds(self) -> None:
        for pat in (".pypirc", ".netrc", "*.jks", "*.ovpn"):
            self.assertIn(pat, GITIGNORE_TEMPLATE)


if __name__ == "__main__":
    unittest.main()
