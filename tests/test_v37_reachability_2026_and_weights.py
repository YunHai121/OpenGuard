"""Regression tests for Round #27: 2025-2026 CVE Call-Graph VEX symbols & safe partial/negative weights."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.models import DependencyComponent, Severity, VulnerabilityFinding
from openguard.scanners.reachability_analyzer import ReachabilityAnalyzer
from openguard.scoring.engine import ScoringEngine


class TestReachability2026AndWeights(unittest.TestCase):
    def test_axios_2026_cve_is_call_reachable_when_axios_get_invoked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "api.js").write_text(
                "import axios from 'axios';\nexport async function ping() { return axios.get('/health'); }\n",
                encoding="utf-8",
            )
            comp = DependencyComponent(
                name="axios",
                version="1.7.0",
                ecosystem="npm",
                source_file="package.json",
                direct=True,
            )
            vuln = VulnerabilityFinding(
                id="CVE-2026-67319",
                component_name="axios",
                component_version="1.7.0",
                ecosystem="npm",
                severity=Severity.HIGH,
                cvss_score=7.5,
                summary="Axios vulnerability",
                source="offline_db",
                source_file="package.json",
            )
            ReachabilityAnalyzer().enrich(repo, components=[comp], vulnerabilities=[vuln])
            self.assertEqual(vuln.reachability_level, "call_reachable")
            self.assertTrue(vuln.reachable)

    def test_scoring_engine_normalizes_partial_and_negative_weights_safely(self) -> None:
        eng_partial = ScoringEngine({"secret_security": 0.6})
        self.assertAlmostEqual(sum(eng_partial.weights.values()), 1.0, places=6)
        self.assertIn("governance", eng_partial.weights)

        eng_bad = ScoringEngine({"secret_security": -1.0, "supply_chain_vuln": 0.0, "license_compliance": 0.0, "code_security": 0.0, "governance": 0.0})
        self.assertAlmostEqual(sum(eng_bad.weights.values()), 1.0, places=6)
        self.assertGreater(eng_bad.weights["secret_security"], 0.0)


if __name__ == "__main__":
    unittest.main()
