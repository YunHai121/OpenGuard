"""Unit tests for Round #12: 6-tool MCP Server (posture + SBOM quality) & Web Workbench API parity."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.mcp_server import MCP_TOOLS, handle_jsonrpc_request
from openguard.web.app import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestMcpPostureAndWebSbomQuality(unittest.TestCase):
    def test_mcp_lists_six_tools_and_runs_posture_and_sbom_quality(self) -> None:
        list_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert list_resp is not None
        names = {t["name"] for t in list_resp["result"]["tools"]}
        self.assertGreaterEqual(len(MCP_TOOLS), 6)
        self.assertIn("diagnose_repo_posture", names)
        self.assertIn("evaluate_sbom_quality", names)

        # Call diagnose_repo_posture on OpenGuard itself
        doc_resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "diagnose_repo_posture", "arguments": {"target_path": str(REPO_ROOT)}},
            }
        )
        assert doc_resp is not None
        doc_payload = json.loads(doc_resp["result"]["content"][0]["text"])
        self.assertTrue(doc_payload["healthy"])
        self.assertEqual(len(doc_payload["checks"]), 7)
        self.assertIn(str(len(MCP_TOOLS)), next(c["details"] for c in doc_payload["checks"] if c["id"] == "OG-DOC-06"))

        # Call evaluate_sbom_quality on directory AND on exported CycloneDX file
        sbom_resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "evaluate_sbom_quality", "arguments": {"target_path": str(REPO_ROOT)}},
            }
        )
        assert sbom_resp is not None
        sbom_payload = json.loads(sbom_resp["result"]["content"][0]["text"])
        self.assertGreaterEqual(sbom_payload["overall_score"], 8.0)
        self.assertEqual(len(sbom_payload["checks"]), 7)

        with tempfile.TemporaryDirectory() as tmp:
            cdx_path = Path(tmp) / "sbom.cdx.json"
            rep = OpenGuardAuditor(AuditConfig(offline=True)).audit(REPO_ROOT)
            OpenGuardAuditor.export_report(rep, "cyclonedx", cdx_path)

            file_resp = handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "evaluate_sbom_quality", "arguments": {"target_path": str(cdx_path)}},
                }
            )
            assert file_resp is not None
            file_payload = json.loads(file_resp["result"]["content"][0]["text"])
            self.assertEqual(file_payload["overall_score"], sbom_payload["overall_score"])

    def test_web_api_doctor_and_sbom_quality_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(db_path=Path(tmp) / "history.db")
            client = TestClient(app)

            # 1. Homepage contains new posture & SBOM quality containers
            home = client.get("/")
            self.assertEqual(home.status_code, 200)
            self.assertIn("doctor-posture-container", home.text)
            self.assertIn("sbom-quality-container", home.text)

            # 2. /api/doctor on valid repo & missing path
            doc_ok = client.get("/api/doctor", params={"target": str(REPO_ROOT)})
            self.assertEqual(doc_ok.status_code, 200)
            doc_data = doc_ok.json()
            self.assertTrue(doc_data["healthy"])
            self.assertEqual(len(doc_data["checks"]), 7)

            doc_404 = client.get("/api/doctor", params={"target": str(Path(tmp) / "nonexistent_dir_xyz")})
            self.assertEqual(doc_404.status_code, 404)

            # 3. /api/sbom-quality/{scan_id} after scan & 404 on unknown id
            scan_resp = client.post("/api/scan", json={"target": str(REPO_ROOT), "offline": True})
            self.assertEqual(scan_resp.status_code, 200)
            scan_id = scan_resp.json()["scan_id"]

            sq_ok = client.get(f"/api/sbom-quality/{scan_id}")
            self.assertEqual(sq_ok.status_code, 200)
            sq_data = sq_ok.json()
            self.assertGreaterEqual(sq_data["overall_score"], 8.0)
            self.assertEqual(len(sq_data["checks"]), 7)

            sq_404 = client.get("/api/sbom-quality/nonexistent-scan-id")
            self.assertEqual(sq_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()
