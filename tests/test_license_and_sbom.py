"""Tests for multi-ecosystem SBOM dependency parser and SPDX license conflict analyzer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.models import LicenseCompatibility
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_spdx
from openguard.scanners.dependency_parser import DependencyParser
from openguard.scanners.license_analyzer import LicenseAnalyzer, normalize_spdx_id


class TestDependencyAndLicense(unittest.TestCase):
    def test_parses_seven_ecosystems_and_transitive_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("fastapi==0.115.0\nrequests>=2.32.0\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nlicense = {text = "MIT"}\ndependencies = ["PyYAML==5.3"]\n',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"name": "fe", "license": "MIT", "dependencies": {"axios": "^1.7.0"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/axios": {"version": "1.7.0", "license": "MIT", "dependencies": {"follow-redirects": "^1.15.0"}},
                            "node_modules/follow-redirects": {"version": "1.15.6", "license": "MIT"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "go.mod").write_text("module example.com/app\ngo 1.21\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n)\n", encoding="utf-8")
            (root / "pom.xml").write_text(
                "<project><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version></dependency></dependencies></project>",
                encoding="utf-8",
            )
            (root / "Cargo.toml").write_text('[package]\nname="rs"\n[dependencies]\nserde = "1.0.210"\n', encoding="utf-8")
            (root / "vcpkg.json").write_text('{"dependencies": ["zlib"]}', encoding="utf-8")
            (root / "composer.json").write_text('{"require": {"monolog/monolog": "^3.0"}}', encoding="utf-8")

            comps, edges, _ = DependencyParser().parse_repository(root)
            ecosystems = {c.ecosystem for c in comps}
            self.assertEqual(ecosystems, {"PyPI", "npm", "Go", "Maven", "crates.io", "C/C++", "Packagist"})
            self.assertIn(("axios", "follow-redirects"), edges)

    def test_detects_mulan_psl_and_mit_licenses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE").write_text(
                "Mulan Permissive Software License, Version 2\n木兰宽松许可证，第2版\n",
                encoding="utf-8",
            )
            lic = LicenseAnalyzer().detect_project_license(root)
            self.assertEqual(lic, "MulanPSL-2.0")

    def test_detects_copyleft_conflicts_with_dependency_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE").write_text(
                "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy",
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("PyQt5==5.15.10\nchardet==5.2.0\nrequests==2.32.3\n", encoding="utf-8")

            comps, _, graph = DependencyParser().parse_repository(root)
            analyzer = LicenseAnalyzer()
            proj_lic = analyzer.detect_project_license(root)
            self.assertEqual(proj_lic, "MIT")

            conflicts = analyzer.analyze_conflicts(root.name, proj_lic, comps, graph)
            by_name = {c.component_name: c for c in conflicts}
            self.assertIn("PyQt5", by_name)
            self.assertEqual(by_name["PyQt5"].compatibility, LicenseCompatibility.INCOMPATIBLE)
            self.assertEqual(by_name["PyQt5"].dependency_path, [root.name, "PyQt5"])

            self.assertIn("chardet", by_name)
            self.assertEqual(by_name["chardet"].compatibility, LicenseCompatibility.REVIEW_REQUIRED)
            self.assertNotIn("requests", by_name)

    def test_cyclonedx_and_spdx_export_structure(self) -> None:
        demo_dir = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(demo_dir)
        cdx = render_cyclonedx(report)
        spdx = render_spdx(report)

        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.5")
        self.assertGreaterEqual(len(cdx["components"]), 10)
        self.assertGreaterEqual(len(cdx["vulnerabilities"]), 3)

        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertGreaterEqual(len(spdx["packages"]), 11)

    def test_normalize_spdx_variants(self) -> None:
        self.assertEqual(normalize_spdx_id("Apache Software License 2.0"), "Apache-2.0")
        self.assertEqual(normalize_spdx_id("GNU General Public License v3"), "GPL-3.0")
        self.assertEqual(normalize_spdx_id("BSD 3-Clause License"), "BSD-3-Clause")
        self.assertEqual(normalize_spdx_id("GNU Lesser General Public License v2.1"), "LGPL-2.1")
        self.assertEqual(normalize_spdx_id("MulanPSL2"), "MulanPSL-2.0")

    def test_agpl_conflict_marked_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge", encoding="utf-8")
            (root / "requirements.txt").write_text("PyMuPDF==1.24.0\n", encoding="utf-8")
            comps, _, graph = DependencyParser().parse_repository(root)
            conflicts = LicenseAnalyzer().analyze_conflicts(root.name, "MIT", comps, graph)
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(str(conflicts[0].severity), "CRITICAL")

    def test_dual_or_license_is_compatible(self) -> None:
        from openguard.models import DependencyComponent
        import networkx as nx

        g = nx.DiGraph()
        g.add_edge("proj", "dualpkg")
        comp = DependencyComponent(name="dualpkg", version="1.0.0", ecosystem="npm", source_file="package.json", license_id="MIT OR GPL-3.0")
        conflicts = LicenseAnalyzer().analyze_conflicts("proj", "MIT", [comp], g)
        self.assertEqual(len(conflicts), 0)

    def test_parses_gradle_cmake_and_cargo_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle").write_text('implementation("org.slf4j:slf4j-api:2.0.12")\n', encoding="utf-8")
            (root / "CMakeLists.txt").write_text("find_package(OpenSSL REQUIRED)\nfind_package(Boost REQUIRED)\n", encoding="utf-8")
            (root / "Cargo.lock").write_text('[[package]]\nname = "tokio"\nversion = "1.40.0"\ndependencies = ["mio 1.0.0"]\n', encoding="utf-8")
            comps, edges, _ = DependencyParser().parse_repository(root)
            names = {c.name for c in comps}
            self.assertIn("org.slf4j:slf4j-api", names)
            self.assertIn("OpenSSL", names)
            self.assertIn("tokio", names)
            self.assertIn(("tokio", "mio"), edges)

    def test_detects_license_from_pyproject_and_package_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r1 = Path(tmp) / "py"
            r1.mkdir()
            (r1 / "pyproject.toml").write_text('[project]\nname="a"\nlicense="Apache-2.0"\n', encoding="utf-8")
            self.assertEqual(LicenseAnalyzer().detect_project_license(r1), "Apache-2.0")

            r2 = Path(tmp) / "js"
            r2.mkdir()
            (r2 / "package.json").write_text('{"name":"b","license":"BSD-3-Clause"}', encoding="utf-8")
            self.assertEqual(LicenseAnalyzer().detect_project_license(r2), "BSD-3-Clause")


if __name__ == "__main__":
    unittest.main()
