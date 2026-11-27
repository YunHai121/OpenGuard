"""Regression tests for Round #29: UTF-8 cache key on non-ASCII paths & .mjs/.cjs SAST/taint coverage."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig


class TestCacheUnicodeAndMjsSast(unittest.TestCase):
    def test_cached_audit_handles_chinese_filename_and_mjs_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "中文接口.mjs").write_text(
                "import { exec } from 'child_process';\n"
                "export function handle(req) {\n"
                "  const cmd = req.query.cmd;\n"
                "  exec(cmd);\n"
                "}\n",
                encoding="utf-8",
            )
            cfg = AuditConfig(offline=True, use_cache=True)
            rep1 = OpenGuardAuditor(cfg).audit(repo)
            ids1 = {c.rule_id for c in rep1.code_security_findings}
            self.assertIn("OG-TAINT-JS-001", ids1)

            # Second run hits incremental cache with non-ASCII path
            rep2 = OpenGuardAuditor(cfg).audit(repo)
            ids2 = {c.rule_id for c in rep2.code_security_findings}
            self.assertIn("OG-TAINT-JS-001", ids2)


if __name__ == "__main__":
    unittest.main()
