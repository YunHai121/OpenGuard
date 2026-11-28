import json
import tempfile
import unittest
from pathlib import Path

from openguard.scanners.dependency_parser import DependencyParser


class TestDepParserExcludesAndVersions(unittest.TestCase):
    def test_strips_comma_bound_from_python_versions_and_parses_dict_license_in_package_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("fastapi>=0.115.0,<1.0.0\nrequests==2.31.0,!=2.31.1\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["pydantic>=2.9.0,<3.0"]\n\n'
                '[tool.poetry.dependencies]\npython = "^3.10"\nhttpx = ">=0.27.0, <1.0"\n',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodash": {
                                "version": "4.17.21",
                                "license": {"type": "MIT"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            excluded_dir = root / "ignored_vendor"
            excluded_dir.mkdir()
            (excluded_dir / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")

            comps, _edges, _graph = DependencyParser().parse_repository(root, exclude_patterns=["ignored_vendor/**"])
            by_name = {c.name.lower(): c for c in comps}

            self.assertEqual(by_name["fastapi"].version, "0.115.0")
            self.assertEqual(by_name["fastapi"].purl, "pkg:pypi/fastapi@0.115.0")
            self.assertEqual(by_name["requests"].version, "2.31.0")
            self.assertEqual(by_name["pydantic"].version, "2.9.0")
            self.assertEqual(by_name["httpx"].version, "0.27.0")
            self.assertEqual(by_name["httpx"].purl, "pkg:pypi/httpx@0.27.0")
            self.assertEqual(by_name["lodash"].license_id, "MIT")
            self.assertNotIn("flask", by_name)


if __name__ == "__main__":
    unittest.main()
