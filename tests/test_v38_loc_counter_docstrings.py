"""Regression tests for Round #28: Python triple-quote docstring counting & .github inclusion in loc_counter."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.utils.loc_counter import count_file_loc, count_repository_loc


class TestLocCounterDocstrings(unittest.TestCase):
    def test_python_single_and_multiline_docstrings_counted_accurately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py_file = Path(tmp) / "mod.py"
            py_file.write_text(
                '"""Single line module docstring."""\n'
                "\n"
                "def foo():\n"
                "    '''\n"
                "    Multi-line single-quote docstring.\n"
                "    '''\n"
                "    return 42\n"
                "\n"
                "x = 1\n",
                encoding="utf-8",
            )
            res = count_file_loc(py_file)
            self.assertEqual(res["total"], 9)
            self.assertEqual(res["blank"], 2)
            self.assertEqual(res["comment"], 4)
            self.assertEqual(res["code"], 3)

    def test_repository_loc_excludes_dot_git_but_counts_dot_github(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".git").mkdir()
            (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
            wf_dir = repo / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text("name: CI\non: [push]\n", encoding="utf-8")

            stats = count_repository_loc(repo)
            self.assertEqual(stats["totals"]["files"], 1)
            self.assertEqual(stats["by_language"]["YAML"]["code"], 2)


if __name__ == "__main__":
    unittest.main()
