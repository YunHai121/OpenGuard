"""Unit tests for Round #18: CycloneDX 1.6 AIBOM / ML-BOM static discovery & Web Compliance UI."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from openguard.aibom import discover_ai_assets, render_cyclonedx_aibom
from openguard.cli import app as cli_app
from openguard.web.app import create_app

runner = CliRunner()


class TestAibomAndWebComplianceUi(unittest.TestCase):
    def _build_demo_ai_repo(self, root: Path) -> None:
        (root / "weights").mkdir(parents=True, exist_ok=True)
        (root / "weights" / "model.safetensors").write_bytes(b"safetensors-demo-payload")
        (root / "weights" / "llama3-q4.gguf").write_bytes(b"GGUF-demo-payload")
        (root / "weights" / "legacy.pt").write_bytes(b"legacy-pt-bytes")

        (root / "train.py").write_text(
            "from transformers import AutoModelForCausalLM\n"
            "from datasets import load_dataset\n"
            "import openai\n\n"
            "m = AutoModelForCausalLM.from_pretrained('meta-llama/Llama-3.1-8B', revision='9f8e7d6')\n"
            "ds = load_dataset('tatsu-lab/alpaca')\n"
            "resp = openai.chat.completions.create(model='gpt-4o', messages=[])\n",
            encoding="utf-8",
        )
        (root / "agent.ts").write_text(
            "export const cfg = { model: 'claude-3-5-sonnet-20241022', fallback: { model: 'deepseek-chat' } };\n",
            encoding="utf-8",
        )

    def test_discover_ai_assets_and_cyclonedx_16_mlbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_demo_ai_repo(root)

            rep = discover_ai_assets(root)
            self.assertEqual(rep.dataset_count, 1)
            self.assertEqual(rep.model_count, 7)

            by_name = {a.name: a for a in rep.assets}
            self.assertTrue(by_name["model.safetensors"].safe_format)
            self.assertTrue(by_name["llama3-q4.gguf"].safe_format)
            self.assertFalse(by_name["legacy.pt"].safe_format)
            self.assertIsNotNone(by_name["model.safetensors"].sha256)
            self.assertTrue(by_name["meta-llama/Llama-3.1-8B"].pinned)
            self.assertEqual(by_name["claude-3-5-sonnet-20241022"].provider, "Anthropic")
            self.assertEqual(by_name["deepseek-chat"].provider, "DeepSeek")

            cdx = render_cyclonedx_aibom(rep)
            self.assertEqual(cdx["bomFormat"], "CycloneDX")
            self.assertEqual(cdx["specVersion"], "1.6")
            self.assertEqual(len(cdx["components"]), 8)
            types = {c["type"] for c in cdx["components"]}
            self.assertEqual(types, {"machine-learning-model", "data"})
            st_comp = next(c for c in cdx["components"] if c["name"] == "model.safetensors")
            self.assertEqual(st_comp["hashes"][0]["alg"], "SHA-256")
            self.assertIn("modelCard", st_comp)

    def test_cli_aibom_and_web_api_and_compliance_panel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ai_repo"
            root.mkdir()
            self._build_demo_ai_repo(root)
            out_json = Path(tmp) / "aibom.cdx.json"

            res = runner.invoke(cli_app, ["aibom", str(root), "--json", "-o", str(out_json)])
            self.assertEqual(res.exit_code, 0, msg=res.output)
            parsed = json.loads(res.stdout)
            self.assertEqual(parsed["specVersion"], "1.6")
            self.assertEqual(len(parsed["components"]), 8)
            self.assertTrue(out_json.is_file())

            web_app = create_app(db_path=Path(tmp) / "hist.db")
            client = TestClient(web_app)
            home = client.get("/")
            self.assertEqual(home.status_code, 200)
            self.assertIn("compliance-posture-container", home.text)

            api_res = client.get("/api/aibom", params={"target": str(root)})
            self.assertEqual(api_res.status_code, 200)
            body = api_res.json()
            self.assertEqual(body["model_count"], 7)
            self.assertEqual(body["dataset_count"], 1)
            self.assertEqual(body["cyclonedx_aibom"]["specVersion"], "1.6")

            self.assertEqual(client.get("/api/aibom", params={"target": str(Path(tmp) / "nope")}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
