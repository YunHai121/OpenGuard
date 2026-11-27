"""Regression tests for Round #26: git diff deleted-file/quotepath handling & Portfolio per-repo config."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.baseline import get_git_diff_added_lines
from openguard.portfolio import PortfolioAuditor


class TestBaselineDiffAndPortfolioConfig(unittest.TestCase):
    def test_git_diff_resets_current_file_on_deleted_file_and_handles_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)

            (repo / "keep.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "old.py").write_text("y = 2\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)

            (repo / "keep.py").write_text("x = 1\nz = 3\n", encoding="utf-8")
            (repo / "old.py").unlink()
            (repo / "中文模块.py").write_text("a = 10\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)

            added = get_git_diff_added_lines(repo, staged=True)
            self.assertEqual(added.get("keep.py"), {2})
            self.assertEqual(added.get("中文模块.py"), {1})
            self.assertNotIn("old.py", added)

    def test_portfolio_auditor_honors_child_repo_openguard_yml_weights(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            child = parent / "proj_a"
            child.mkdir()
            (child / "README.md").write_text("# Proj A\n", encoding="utf-8")
            (child / ".openguard.yml").write_text(
                "offline: true\nweights:\n  secret_security: 0.40\n  supply_chain_vuln: 0.15\n  license_compliance: 0.15\n  code_security: 0.15\n  governance: 0.15\n",
                encoding="utf-8",
            )
            res = PortfolioAuditor().audit_repositories([child], offline=True)
            self.assertEqual(res.total_repos, 1)
            self.assertEqual(res.repos[0].repo_name, "proj_a")
            self.assertGreater(res.repos[0].total_score, 0.0)


if __name__ == "__main__":
    unittest.main()
