"""Tests for Round #4 upgrades:
- Semgrep-Taint-inspired Intra-Procedural Python AST Taint Analyzer (SQLi, RCE, SSRF, Path Traversal + Sanitizers)
- SLSA v1.0 Provenance / in-toto v1 Attestation Exporter & Tamper-Detection Verifier
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.reporters.slsa_provenance import (
    IN_TOTO_STATEMENT_TYPE,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    render_slsa_provenance,
    verify_slsa_provenance,
)
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.web.app import create_app


class TestPythonTaintAnalyzer(unittest.TestCase):
    def test_detects_multiline_tainted_sqli_ssrf_and_path_traversal(self) -> None:
        code = (
            "import requests\n"
            "def handler(request, cursor):\n"
            "    uid = request.args.get('id')\n"
            "    sql = 'SELECT * FROM users WHERE id = ' + uid\n"
            "    cursor.execute(sql)\n"
            "    target_url = request.form['webhook']\n"
            "    requests.get(target_url)\n"
            "    fname = request.values.get('file')\n"
            "    full_path = f'/var/data/{fname}'\n"
            "    return open(full_path).read()\n"
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(code, "views.py")
        rule_ids = {h.rule_id for h in hits}
        self.assertIn("OG-TAINT-PY-001", rule_ids)  # multi-line SQLi
        self.assertIn("OG-TAINT-PY-003", rule_ids)  # SSRF
        self.assertIn("OG-TAINT-PY-004", rule_ids)  # Path Traversal

    def test_sanitizers_and_is_relative_to_suppress_false_positives(self) -> None:
        safe_code = (
            "import os\n"
            "from pathlib import Path\n"
            "def safe_handler(request, cursor):\n"
            "    uid = int(request.args.get('id'))\n"
            "    sql = f'SELECT * FROM users WHERE id = {uid}'\n"
            "    cursor.execute(sql)\n"
            "    fname = os.path.basename(request.args.get('file'))\n"
            "    return open('/var/data/' + fname).read()\n"
            "\n"
            "def guarded_handler(request, root):\n"
            "    raw = request.args['p']\n"
            "    cand = (Path(root) / raw).resolve()\n"
            "    if not cand.is_relative_to(Path(root)):\n"
            "        raise PermissionError()\n"
            "    return cand.read_text()\n"
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(safe_code, "safe_views.py")
        taint_ids = {h.rule_id for h in hits if h.rule_id.startswith("OG-TAINT-")}
        self.assertEqual(taint_ids, set(), f"Sanitized code should yield 0 taint findings, got: {hits}")


class TestSLSAProvenanceAttestation(unittest.TestCase):
    def test_generate_and_verify_slsa_provenance_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            root.mkdir()
            (root / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
            (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")

            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(root)
            prov = render_slsa_provenance(report)
            self.assertEqual(prov["_type"], IN_TOTO_STATEMENT_TYPE)
            self.assertEqual(prov["predicateType"], SLSA_PROVENANCE_PREDICATE_TYPE)
            dep_uris = [d["uri"] for d in prov["predicate"]["buildDefinition"]["resolvedDependencies"]]
            self.assertTrue(any("pkg:pypi/requests@2.32.3" in u for u in dep_uris))

            att_file = Path(tmp) / "slsa_provenance.json"
            att_file.write_text(json.dumps(prov, indent=2), encoding="utf-8")

            ok, errs = verify_slsa_provenance(att_file, repo_root=root)
            self.assertTrue(ok, f"Expected clean verification, got errors: {errs}")

            # Tamper with requirements.txt -> verifier MUST detect digest mismatch!
            (root / "requirements.txt").write_text("requests==2.32.3\nevil-pkg==0.0.1\n", encoding="utf-8")
            ok_after, errs_after = verify_slsa_provenance(att_file, repo_root=root)
            self.assertFalse(ok_after)
            self.assertTrue(any("Digest mismatch" in e for e in errs_after))

            # Web API /api/export/{scan_id}/slsa endpoint check
            client = TestClient(create_app(db_path=Path(tmp) / "slsa.db"))
            scan_id = client.post("/api/scan", json={"target": str(root), "offline": True}).json()["scan_id"]
            r = client.get(f"/api/export/{scan_id}/slsa")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["predicateType"], SLSA_PROVENANCE_PREDICATE_TYPE)


if __name__ == "__main__":
    unittest.main()
