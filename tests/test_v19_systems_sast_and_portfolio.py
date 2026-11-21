"""Tests for Round #9 upgrades:
- Multi-Language Systems SAST rules: Java (ObjectInputStream/Runtime.exec/XXE),
  C/C++ (gets/strcpy/system), and Rust (mem::transmute/Command sh/undocumented unsafe)
- Multi-Repository Portfolio Batch Auditor + JSONL streaming + Markdown leaderboard
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openguard.config import AuditConfig
from openguard.portfolio import PortfolioAuditor, discover_child_repositories
from openguard.scanners.code_security_scanner import CodeSecurityScanner


class TestSystemsLanguageSAST(unittest.TestCase):
    def test_java_sast_detects_deserialization_exec_and_xxe(self) -> None:
        java_code = (
            "import java.io.*;\n"
            "import javax.xml.parsers.*;\n"
            "class Demo {\n"
            "  void bad(InputStream in, String cmd) throws Exception {\n"
            "    ObjectInputStream ois = new ObjectInputStream(in);\n"
            "    ois.readObject();\n"
            "    Runtime.getRuntime().exec(cmd);\n"
            "    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "  }\n"
            "}\n"
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(java_code, "Demo.java")
        ids = {h.rule_id for h in hits}
        self.assertEqual(ids, {"OG-SAST-JAVA-001", "OG-SAST-JAVA-002", "OG-SAST-JAVA-003"})

    def test_cpp_and_rust_sast_rules_and_safety_comment_guard(self) -> None:
        cpp_code = (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "void f(char *in) {\n"
            "  char buf[32];\n"
            "  strcpy(buf, in);\n"
            "  system(buf);\n"
            "}\n"
        )
        cpp_hits = CodeSecurityScanner(AuditConfig()).scan_content(cpp_code, "vuln.c")
        self.assertEqual({h.rule_id for h in cpp_hits}, {"OG-SAST-CPP-001", "OG-SAST-CPP-002"})

        rust_code = (
            "use std::process::Command;\n"
            "fn demo(x: u32) {\n"
            "    let _ = unsafe { std::mem::transmute::<u32, f32>(x) };\n"
            '    let _ = Command::new("sh").arg("-c").arg("ls").status();\n'
            "    // SAFETY: pointer is guaranteed non-null and aligned\n"
            "    unsafe { /* documented ok */ }\n"
            "}\n"
        )
        rs_hits = CodeSecurityScanner(AuditConfig()).scan_content(rust_code, "lib.rs")
        rs_ids = {h.rule_id for h in rs_hits}
        self.assertEqual(rs_ids, {"OG-SAST-RS-001", "OG-SAST-RS-002", "OG-SAST-RS-003"})
        # Only line 3 unsafe should flag OG-SAST-RS-003; line 6 has // SAFETY: comment
        unsafe_lines = [h.line_number for h in rs_hits if h.rule_id == "OG-SAST-RS-003"]
        self.assertEqual(unsafe_lines, [3])


class TestPortfolioBatchAuditor(unittest.TestCase):
    def test_discovers_and_audits_multiple_repos_with_jsonl_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Clean repo
            r_clean = root / "clean_service"
            r_clean.mkdir()
            (r_clean / "LICENSE").write_text("MIT License\n", encoding="utf-8")
            (r_clean / "app.py").write_text("print('ok')\n", encoding="utf-8")

            # Vulnerable repo
            r_bad = root / "risky_service"
            r_bad.mkdir()
            (r_bad / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")
            (r_bad / "main.py").write_text(
                'import yaml\nAWS = "AKIA' + '7F4K9P2M8Q3X6Z1W"\nyaml.load("a: 1")\n',
                encoding="utf-8",
            )

            discovered = discover_child_repositories(root)
            self.assertEqual(len(discovered), 2)

            jsonl_path = root / "out" / "portfolio.jsonl"
            md_path = root / "out" / "portfolio.md"
            res = PortfolioAuditor().audit_repositories(
                discovered,
                offline=True,
                jsonl_out=jsonl_path,
                md_out=md_path,
            )

            self.assertEqual(res.total_repos, 2)
            self.assertEqual(res.passed_gates, 1)
            self.assertEqual(res.failed_gates, 1)

            jsonl_lines = [json.loads(ln) for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(len(jsonl_lines), 2)
            by_name = {row["repo_name"]: row for row in jsonl_lines}
            self.assertEqual(by_name["clean_service"]["quality_gate"], "PASSED")
            self.assertEqual(by_name["risky_service"]["quality_gate"], "FAILED")
            self.assertGreaterEqual(by_name["risky_service"]["p0_vulns_count"], 1)

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("Portfolio Report", md_text)
            self.assertIn("risky_service", md_text)


if __name__ == "__main__":
    unittest.main()
