"""Tests for Round #8 upgrades:
- JavaScript / TypeScript Cross-Statement Taint Analyzer (RCE, XSS, SSRF, Path Traversal, Prototype Pollution + Sanitizers)
- Content-Hash Incremental File Scan Cache (SHA-256 + Config Fingerprint Invalidation)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.utils.scan_cache import IncrementalScanCache


class TestJSTaintAnalyzer(unittest.TestCase):
    def test_detects_express_rce_xss_ssrf_path_traversal_and_prototype_pollution(self) -> None:
        js_code = (
            "const { exec } = require('child_process');\n"
            "const fs = require('fs');\n"
            "app.post('/run', async (req, res) => {\n"
            "  const { cmd, targetUrl, file, propKey } = req.body;\n"
            "  exec(`ls ${cmd}`);\n"
            "  await fetch(targetUrl);\n"
            "  const raw = fs.readFileSync('/data/' + file, 'utf8');\n"
            "  const obj = {};\n"
            "  obj[propKey] = req.body.val;\n"
            "  res.send(`<div>${cmd}</div>`);\n"
            "});\n"
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(js_code, "server.js")
        ids = {h.rule_id for h in hits}
        self.assertEqual(
            ids,
            {
                "OG-TAINT-JS-001",  # RCE
                "OG-TAINT-JS-002",  # XSS
                "OG-TAINT-JS-003",  # SSRF
                "OG-TAINT-JS-004",  # Path Traversal
                "OG-TAINT-JS-005",  # Prototype Pollution
            },
        )

    def test_js_sanitizers_and_guards_suppress_false_positives(self) -> None:
        safe_js = (
            "app.get('/safe', (req, res) => {\n"
            "  const cleanHtml = DOMPurify.sanitize(req.query.msg);\n"
            "  res.send(cleanHtml);\n"
            "  const fname = path.basename(req.query.file);\n"
            "  fs.readFileSync(fname);\n"
            "  const k = req.body.key;\n"
            "  if (k === '__proto__' || k === 'constructor') return;\n"
            "  const out = {};\n"
            "  out[k] = 1;\n"
            "});\n"
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(safe_js, "safe.ts")
        taint_ids = {h.rule_id for h in hits if h.rule_id.startswith("OG-TAINT-JS-")}
        self.assertEqual(taint_ids, set(), f"Sanitized JS should yield 0 taint findings, got: {hits}")


class TestContentHashIncrementalScanCache(unittest.TestCase):
    def test_cache_hits_on_unchanged_and_invalidates_on_edit_or_config_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_py = root / "app.py"
            app_py.write_text('import pickle\npickle.loads(b"x")\n', encoding="utf-8")

            cfg = AuditConfig(offline=True, use_cache=True)
            rep1 = OpenGuardAuditor(cfg).audit(root)
            self.assertEqual(len(rep1.code_security_findings), 1)
            cache_file = root / ".openguard_cache" / "scan_cache.json"
            self.assertTrue(cache_file.is_file())

            # Second run with unchanged file must produce identical result from cache
            rep2 = OpenGuardAuditor(cfg).audit(root)
            self.assertEqual(len(rep2.code_security_findings), 1)

            # Verify cache object actually loads existing entries cleanly
            cache_check = IncrementalScanCache(root, cfg)
            self.assertGreaterEqual(len(cache_check._entries), 2)

            # Edit file to remove vulnerability -> SHA-256 content hash changes -> 0 findings!
            app_py.write_text('import json\njson.loads("{}")\n', encoding="utf-8")
            rep3 = OpenGuardAuditor(cfg).audit(root)
            self.assertEqual(len(rep3.code_security_findings), 0)

            # Changing config fingerprint invalidates cached entries automatically
            cfg2 = AuditConfig(offline=True, use_cache=True, min_confidence=0.60)
            cache_invalidated = IncrementalScanCache(root, cfg2)
            self.assertEqual(len(cache_invalidated._entries), 0)


if __name__ == "__main__":
    unittest.main()
