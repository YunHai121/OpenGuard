"""Regression tests for Round #20: Pickle memoized STACK_GLOBAL, PyTorch .bin AIBOM & Web AIBOM export."""

from __future__ import annotations

import pickletools
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from openguard.aibom import discover_ai_assets
from openguard.config import load_config
from openguard.scanners.ml_model_scanner import inspect_pickle_bytes
from openguard.web.app import create_app


class TestAIBOMPickleMemoAndWeb(unittest.TestCase):
    def test_pickle_memoized_stack_global_and_marshal_detected(self) -> None:
        # Protocol 4 pickle pushing 'os' -> MEMOIZE(0) -> POP -> 'system' -> BINGET(0) -> 'system' -> STACK_GLOBAL
        # Build manually using opcodes: PROTO 4, SHORT_BINUNICODE 'os', MEMOIZE, POP, BINGET 0, SHORT_BINUNICODE 'system', STACK_GLOBAL, STOP
        payload = (
            b"\x80\x04"  # PROTO 4
            b"\x8c\x02os"  # SHORT_BINUNICODE 'os'
            b"\x94"  # MEMOIZE (idx 0 = 'os')
            b"0"  # POP
            b"h\x00"  # BINGET 0 -> pushes 'os'
            b"\x8c\x06system"  # SHORT_BINUNICODE 'system'
            b"\x93"  # STACK_GLOBAL
            b"."  # STOP
        )
        # Sanity check that pickletools can disassemble our synthetic stream
        list(pickletools.genops(payload))
        hits = inspect_pickle_bytes(payload)
        self.assertIn("os.system", hits)

        # Also check marshal.loads via STACK_GLOBAL
        marshal_payload = (
            b"\x80\x04"
            b"\x8c\x07marshal"
            b"\x8c\x05loads"
            b"\x93"
            b"."
        )
        self.assertIn("marshal.loads", inspect_pickle_bytes(marshal_payload))

    def test_aibom_discovers_pytorch_bin_even_with_default_excludes_and_grok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            # Write a minimal PyTorch/Pickle .bin weight artifact
            (repo / "pytorch_model.bin").write_bytes(b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94.")
            (repo / "chat.py").write_text(
                'client.chat.completions.create(model="grok-3-mini", messages=[])\n',
                encoding="utf-8",
            )
            cfg = load_config(repo)
            rep = discover_ai_assets(repo, exclude_patterns=cfg.exclude_patterns)
            names = {a.name for a in rep.assets}
            self.assertIn("pytorch_model.bin", names)
            self.assertIn("grok-3-mini", names)

    def test_web_export_aibom_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = tmp_path / "ai_repo"
            repo.mkdir()
            (repo / "app.py").write_text('llm(model="gpt-4o")\n', encoding="utf-8")
            client = TestClient(create_app(db_path=tmp_path / "og.db"))
            scan_resp = client.post("/api/scan", json={"target": str(repo), "offline": True})
            self.assertEqual(scan_resp.status_code, 200)
            scan_id = scan_resp.json()["scan_id"]

            aibom_resp = client.get(f"/api/export/{scan_id}/aibom")
            self.assertEqual(aibom_resp.status_code, 200)
            data = aibom_resp.json()
            self.assertEqual(data["specVersion"], "1.6")
            self.assertEqual(len(data["components"]), 1)
            self.assertEqual(data["components"][0]["name"], "gpt-4o")


if __name__ == "__main__":
    unittest.main()
