"""Tests for Round #3 upgrades:
- OSV-SCALIBR / Syft 10-ecosystem SBOM parity:
  GitHub Actions (pkg:githubactions), go.sum, Gemfile.lock (RubyGems),
  composer.lock (Packagist with licenses), and .csproj (.NET NuGet)
- Web Workbench API parity: fix_deps autofix preview/apply & pr-comment export
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from openguard.scanners.dependency_parser import DependencyParser
from openguard.web.app import create_app


class TestTenEcosystemSBOMExpansion(unittest.TestCase):
    def test_parses_github_actions_go_sum_gemfile_composer_lock_and_csproj(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text(
                "name: CI\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
                "      - uses: ./local/action\n",
                encoding="utf-8",
            )
            (root / "go.sum").write_text(
                "github.com/gin-gonic/gin v1.9.1 h1:abc=\n"
                "github.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n",
                encoding="utf-8",
            )
            (root / "Gemfile.lock").write_text(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rack (3.0.9)\n"
                "    rails (7.1.3)\n"
                "      rack (>= 3.0.0)\n"
                "\nPLATFORMS\n  ruby\n",
                encoding="utf-8",
            )
            (root / "composer.lock").write_text(
                json.dumps(
                    {
                        "packages": [
                            {
                                "name": "symfony/http-foundation",
                                "version": "v6.4.2",
                                "license": ["MIT"],
                                "require": {"php": ">=8.1", "symfony/deprecation-contracts": "^3"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (root / "App.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                '  <ItemGroup>\n'
                '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
                '  </ItemGroup>\n'
                '</Project>\n',
                encoding="utf-8",
            )

            comps, edges, _ = DependencyParser().parse_repository(root)
            by_key = {(c.ecosystem, c.name): c for c in comps}

            self.assertIn(("GitHub Actions", "actions/checkout"), by_key)
            self.assertEqual(
                by_key[("GitHub Actions", "actions/checkout")].purl,
                "pkg:githubactions/actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            )
            self.assertIn(("Go", "github.com/gin-gonic/gin"), by_key)
            self.assertEqual(by_key[("Go", "github.com/gin-gonic/gin")].version, "1.9.1")

            self.assertIn(("RubyGems", "rails"), by_key)
            self.assertEqual(by_key[("RubyGems", "rails")].purl, "pkg:gem/rails@7.1.3")
            self.assertIn(("rails", "rack"), edges)

            self.assertIn(("Packagist", "symfony/http-foundation"), by_key)
            self.assertEqual(by_key[("Packagist", "symfony/http-foundation")].license_id, "MIT")

            self.assertIn(("NuGet", "Newtonsoft.Json"), by_key)
            self.assertEqual(by_key[("NuGet", "Newtonsoft.Json")].purl, "pkg:nuget/Newtonsoft.Json@13.0.3")


class TestWebWorkbenchV13Parity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.client = TestClient(create_app(db_path=Path(self.tmp.name) / "v13.db"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_web_autofix_deps_and_pr_comment_export(self) -> None:
        repo = Path(self.tmp.name) / "proj"
        repo.mkdir()
        (repo / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")
        (repo / "app.py").write_text("import yaml\nyaml.load('a: 1')\n", encoding="utf-8")

        scan_res = self.client.post("/api/scan", json={"target": str(repo), "offline": True})
        self.assertEqual(scan_res.status_code, 200)
        scan_id = scan_res.json()["scan_id"]

        pr_res = self.client.get(f"/api/export/{scan_id}/pr-comment")
        self.assertEqual(pr_res.status_code, 200)
        self.assertIn("openguard-pr-comment", pr_res.text)
        self.assertIn("call_reachable", pr_res.text)

        prev_res = self.client.post(
            "/api/autofix/preview",
            json={"target": str(repo), "fix_secrets": False, "fix_docs": False, "fix_deps": True},
        )
        self.assertEqual(prev_res.status_code, 200)
        self.assertEqual(prev_res.json()["deps"]["packages_upgraded"], 1)

        apply_res = self.client.post(
            "/api/autofix/apply",
            json={"target": str(repo), "fix_secrets": False, "fix_docs": False, "fix_deps": True},
        )
        self.assertEqual(apply_res.status_code, 200)
        self.assertIn("PyYAML==5.4.1", (repo / "requirements.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
