"""Tests for Round #6 upgrades:
- Declarative Policy-as-Code & Custom YAML Rule Engine (.openguard/rules/*.yml + policy denylist/allowlist)
- Executive HTML & PDF Report parity (Quality Gate banner, P0-P3 KEV/EPSS, Call-Graph reachability)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import load_config
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.pdf_reporter import render_pdf_bytes


class TestPolicyEngineAndExecutiveReports(unittest.TestCase):
    def test_custom_yaml_rules_and_declarative_license_package_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Custom YAML rule pack in .openguard/rules/corp.yml
            rules_dir = root / ".openguard" / "rules"
            rules_dir.mkdir(parents=True)
            (rules_dir / "corp.yml").write_text(
                "rules:\n"
                "  - id: CORP-SEC-001\n"
                "    name: Ban plaintext internal HTTP\n"
                "    severity: HIGH\n"
                "    cwe: CWE-319\n"
                "    pattern: 'http://internal\\.corp\\.local'\n"
                "    paths: ['*.py']\n"
                "    exclude_paths: ['tests/*']\n"
                "    message: '禁止明文 HTTP 访问内部服务'\n",
                encoding="utf-8",
            )
            # 2. Declarative license & package denylist in .openguard.yml
            (root / ".openguard.yml").write_text(
                "offline: true\n"
                "policy:\n"
                "  denied_licenses:\n"
                "    - MPL-2.0\n"
                "  denied_packages:\n"
                "    - pycrypto\n",
                encoding="utf-8",
            )
            (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
            (root / "requirements.txt").write_text("tqdm==4.66.0\npycrypto==2.6.1\n", encoding="utf-8")
            (root / "client.py").write_text('URL = "http://internal.corp.local/api"\n', encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_client.py").write_text('URL = "http://internal.corp.local/mock"\n', encoding="utf-8")

            cfg = load_config(root)
            report = OpenGuardAuditor(cfg).audit(root)

            # Custom rule fires on client.py but respects exclude_paths on tests/test_client.py
            corp_hits = [c for c in report.code_security_findings if c.rule_id == "CORP-SEC-001"]
            self.assertEqual(len(corp_hits), 1)
            self.assertEqual(corp_hits[0].file_path, "client.py")

            # License denylist catches tqdm (MPL-2.0)
            denied_lic = [lc for lc in report.license_conflicts if lc.component_name.lower() == "tqdm"]
            self.assertEqual(len(denied_lic), 1)
            self.assertEqual(denied_lic[0].compatibility, "INCOMPATIBLE")

            # Package denylist catches pycrypto as P0 CRITICAL policy block
            blocked_pkgs = [v for v in report.vulnerabilities if v.id == "OG-POLICY-PKG-PYCRYPTO"]
            self.assertEqual(len(blocked_pkgs), 1)
            self.assertEqual(blocked_pkgs[0].priority_tier, "P0")

            # Executive HTML & PDF render cleanly with new badges & Quality Gate
            html_out = render_html_report(report)
            self.assertIn("[P0] POLICY BLOCK", html_out)
            self.assertIn("自定义策略", html_out)

            pdf_bytes = render_pdf_bytes(report)
            self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
            self.assertGreater(len(pdf_bytes), 2000)


if __name__ == "__main__":
    unittest.main()
