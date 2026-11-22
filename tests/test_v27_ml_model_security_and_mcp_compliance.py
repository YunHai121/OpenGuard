"""Unit tests for Round #17: ML Model Pickle/PyTorch opcode scanner, ML SAST rules & MCP evaluate_compliance."""

from __future__ import annotations

import json
import os
import pickle
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from openguard.config import AuditConfig, DEFAULT_EXCLUDE_PATTERNS
from openguard.mcp_server import MCP_TOOLS, handle_jsonrpc_request
from openguard.models import Severity
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.ml_model_scanner import MLModelScanner, inspect_pickle_bytes

REPO_ROOT = Path(__file__).resolve().parent.parent


class _EvilOsSystemPayload:
    def __reduce__(self):
        return (os.system, ("echo harmless_test_payload",))


class _EvilSubprocessPayload:
    def __reduce__(self):
        return (subprocess.Popen, (["echo", "harmless"],))


class TestMlModelSecurityAndMcpCompliance(unittest.TestCase):
    def test_raw_and_zip_pytorch_pickle_opcodes_detected_without_execution(self) -> None:
        # 1. Benign pickle produces 0 hits
        benign_bytes = pickle.dumps({"layer1.weight": [0.1, 0.2, 0.3], "epoch": 10}, protocol=4)
        self.assertEqual(inspect_pickle_bytes(benign_bytes), [])

        # 2. Protocol 0 (GLOBAL) & Protocol 4 (STACK_GLOBAL) malicious payloads detected
        p0_bytes = pickle.dumps(_EvilOsSystemPayload(), protocol=0)
        p4_bytes = pickle.dumps(_EvilOsSystemPayload(), protocol=4)
        self.assertTrue(any("system" in g for g in inspect_pickle_bytes(p0_bytes)))
        self.assertTrue(any("system" in g for g in inspect_pickle_bytes(p4_bytes)))

        # 3. Repository scan catches raw .pkl AND ZIP-packaged PyTorch .pt / .bin (even with default excludes!)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "clean_weights.pkl").write_bytes(benign_bytes)
            (root / "poisoned_model.pkl").write_bytes(p4_bytes)

            # Simulate standard torch.save() ZIP archive saved as pytorch_model.bin
            zip_payload = pickle.dumps(_EvilSubprocessPayload(), protocol=4)
            with zipfile.ZipFile(root / "pytorch_model.bin", "w") as zf:
                zf.writestr("archive/data.pkl", zip_payload)

            findings = MLModelScanner().scan_repository(root, exclude_patterns=list(DEFAULT_EXCLUDE_PATTERNS))
            self.assertEqual(len(findings), 2)
            paths = {f.file_path for f in findings}
            self.assertEqual(paths, {"poisoned_model.pkl", "pytorch_model.bin"})
            self.assertTrue(all(f.rule_id == "OG-ML-001" and f.severity == Severity.CRITICAL for f in findings))

    def test_python_ml_framework_sast_rules(self) -> None:
        scanner = CodeSecurityScanner(AuditConfig(offline=True))

        risky_code = (
            "import torch, numpy as np\n"
            "from transformers import AutoModel\n"
            "m1 = torch.load('ckpt.pt')\n"
            "m2 = torch.load('ckpt.pt', weights_only=False)\n"
            "hf = AutoModel.from_pretrained('org/model', trust_remote_code=True)\n"
            "arr = np.load('data.npy', allow_pickle=True)\n"
        )
        hits = scanner.scan_content(risky_code, "train/inference.py")
        ids = [h.rule_id for h in hits]
        self.assertEqual(ids.count("OG-SAST-ML-001"), 2)
        self.assertEqual(ids.count("OG-SAST-ML-002"), 1)
        self.assertEqual(ids.count("OG-SAST-ML-003"), 1)

        safe_code = (
            "import torch, numpy as np\n"
            "from transformers import AutoModel\n"
            "m_safe = torch.load('ckpt.pt', weights_only=True)\n"
            "hf_safe = AutoModel.from_pretrained('org/model', trust_remote_code=False)\n"
            "arr_safe = np.load('data.npy')\n"
        )
        self.assertEqual(len(scanner.scan_content(safe_code, "train/safe.py")), 0)

    def test_mcp_seventh_tool_evaluate_compliance(self) -> None:
        self.assertEqual(len(MCP_TOOLS), 7)
        resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "evaluate_compliance", "arguments": {"target_path": str(REPO_ROOT), "offline": True}},
            }
        )
        assert resp is not None
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "COMPLIANT")
        self.assertEqual(payload["passed_count"], 8)
        self.assertEqual(payload["compliance_rate"], 100.0)


if __name__ == "__main__":
    unittest.main()
