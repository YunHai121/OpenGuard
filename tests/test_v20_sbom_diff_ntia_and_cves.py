"""Tests for Round #10 upgrades:
- SBOM Diff & License Drift detection (GitHub Dependency Review / CycloneDX diff parity)
- NTIA Minimum Elements SBOM Quality Scorer (0.0-10.0, sbomqs parity)
- 2025-2026 Critical CVEs & CISA KEV expansion (React RSC, Next.js, Brotli HTTP2Shell, Axios)
"""

from __future__ import annotations

import unittest

from openguard.models import DependencyComponent
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx
from openguard.sbom_tools import diff_cyclonedx_sboms, render_sbom_diff_markdown, score_sbom_quality
from openguard.scanners.vuln_scanner import VulnScanner
from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from pathlib import Path


class TestSBOMDiffAndNTIAQuality(unittest.TestCase):
    def test_sbom_diff_catches_added_components_license_drift_and_new_cves(self) -> None:
        before = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:1",
            "metadata": {"timestamp": "2026-11-20T00:00:00Z", "tools": [{"name": "OpenGuard"}]},
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                    "properties": [{"name": "openguard:ecosystem", "value": "PyPI"}],
                }
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["pkg:pypi/requests@2.31.0"]}],
            "vulnerabilities": [],
        }
        after = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:2",
            "metadata": {"timestamp": "2026-11-22T00:00:00Z", "tools": [{"name": "OpenGuard"}]},
            "components": [
                {
                    "name": "requests",
                    "version": "2.32.3",
                    "purl": "pkg:pypi/requests@2.32.3",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                    "properties": [{"name": "openguard:ecosystem", "value": "PyPI"}],
                },
                {
                    "name": "scapy",
                    "version": "2.5.0",
                    "purl": "pkg:pypi/scapy@2.5.0",
                    "licenses": [{"license": {"id": "GPL-2.0"}}],
                    "properties": [{"name": "openguard:ecosystem", "value": "PyPI"}],
                },
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["pkg:pypi/requests@2.32.3", "pkg:pypi/scapy@2.5.0"]}],
            "vulnerabilities": [
                {
                    "id": "CVE-2025-55182",
                    "ratings": [{"severity": "critical", "score": 10.0}],
                    "description": "React RSC RCE",
                    "affects": [{"ref": "pkg:npm/react@19.1.0"}],
                    "analysis": {"state": "exploitable"},
                }
            ],
        }

        diff = diff_cyclonedx_sboms(before, after)
        self.assertTrue(diff.has_risky_drift)
        self.assertEqual(len(diff.added_components), 1)
        self.assertEqual(len(diff.version_changes), 1)
        self.assertEqual(len(diff.license_drifts), 1)
        self.assertEqual(diff.license_drifts[0]["is_copyleft_intro"], "true")
        self.assertEqual(len(diff.new_vulnerabilities), 1)

        md = render_sbom_diff_markdown(diff)
        self.assertIn("RISK DRIFT DETECTED", md)
        self.assertIn("CVE-2025-55182", md)
        self.assertIn("GPL-2.0", md)

    def test_ntia_quality_scorer_grades_openguard_sbom_high(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        rep = OpenGuardAuditor(AuditConfig(offline=True)).audit(repo_root)
        cdx = render_cyclonedx(rep)
        qr = score_sbom_quality(cdx)
        self.assertGreaterEqual(qr.overall_score, 8.0)
        self.assertEqual(len(qr.checks), 7)

        # Bare invalid SBOM scores very low
        bad_qr = score_sbom_quality({"components": [{"name": "foo"}]})
        self.assertLess(bad_qr.overall_score, 4.0)


class TestRecent2025To2026CVEs(unittest.TestCase):
    def test_detects_react_rsc_nextjs_brotli_and_axios_2025_2026_cves(self) -> None:
        comps = [
            DependencyComponent(name="react", version="19.1.0", ecosystem="npm", source_file="package.json"),
            DependencyComponent(name="next", version="15.4.0", ecosystem="npm", source_file="package.json"),
            DependencyComponent(name="brotli", version="1.1.0", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="axios", version="1.7.7", ecosystem="npm", source_file="package.json"),
        ]
        hits = VulnScanner(offline=True).scan_components(comps)
        by_id = {v.id: v for v in hits}
        self.assertIn("CVE-2025-55182", by_id)
        self.assertTrue(by_id["CVE-2025-55182"].in_cisa_kev)
        self.assertIn("CVE-2025-66478", by_id)
        self.assertTrue(by_id["CVE-2025-66478"].in_cisa_kev)
        self.assertIn("CVE-2026-111497", by_id)
        self.assertIn("CVE-2026-67313", by_id)
        self.assertIn("CVE-2026-67319", by_id)


if __name__ == "__main__":
    unittest.main()
