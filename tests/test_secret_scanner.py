"""Tests for 3-stage hybrid secret scanner, validators, AST filtering, staged diff & git history."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.config import AuditConfig
from openguard.scanners.git_history_scanner import GitHistoryScanner
from openguard.scanners.secret_rules import validate_chinese_id, validate_jwt, validate_luhn
from openguard.scanners.secret_scanner import SecretScanner
from openguard.utils.entropy import is_likely_placeholder, mask_secret, shannon_entropy


class TestSecretValidatorsAndEntropy(unittest.TestCase):
    def test_shannon_entropy_distinction(self) -> None:
        low = shannon_entropy("aaaaaaaaaaaa1111")
        high = shannon_entropy("A9kP2mQ8xL4vW7nB5zY3cJ6tD")
        self.assertLess(low, 1.5)
        self.assertGreater(high, 4.0)

    def test_empty_and_short_entropy_edges(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertTrue(is_likely_placeholder("")[0])
        self.assertTrue(is_likely_placeholder("12345")[0])
        self.assertTrue(is_likely_placeholder("xxxxxxxxxxxx")[0])
        self.assertTrue(is_likely_placeholder("postgresql://user:P@ss...@host")[0])

    def test_placeholder_detection(self) -> None:
        self.assertTrue(is_likely_placeholder("sk-your_api_key_placeholder")[0])
        self.assertTrue(is_likely_placeholder("550e8400-e29b-41d4-a716-446655440000")[0])
        self.assertFalse(is_likely_placeholder("AKIA7F4K9P2M8Q3X6Z1W")[0])

    def test_mask_secret_never_exposes_full_value(self) -> None:
        raw = "sk-proj-A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2"
        masked = mask_secret(raw)
        self.assertIn("****", masked)
        self.assertNotIn("A8mK2pQ9xL4vW7nB", masked)
        self.assertEqual(mask_secret("abcd"), "ab****")

    def test_chinese_id_mod11_2_validator(self) -> None:
        self.assertTrue(validate_chinese_id("420102199905121235"))
        self.assertFalse(validate_chinese_id("420102199905121234"))
        self.assertFalse(validate_chinese_id("999999199905121235"))

    def test_luhn_validator(self) -> None:
        self.assertTrue(validate_luhn("6222020200112233446"))
        self.assertFalse(validate_luhn("6222020200112233445"))
        self.assertFalse(validate_luhn("1111111111111111"))

    def test_jwt_validator(self) -> None:
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.sigvalue1234"
        invalid_jwt = "eyJub3RfanNvbg==.eyJub3RfanNvbg==.sigvalue1234"
        self.assertTrue(validate_jwt(valid_jwt))
        self.assertFalse(validate_jwt(invalid_jwt))
        self.assertFalse(validate_jwt("only.two"))


class TestSecretScannerPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SecretScanner(AuditConfig(offline=True))

    def test_detects_cloud_ai_scm_and_webhook_secrets(self) -> None:
        code = (
            'AWS_KEY = "AKIA7F4K9P2M8Q3X6Z1W"\n'
            'ALI_KEY = "LTAI5t9xR2mP8qK4vW7nB"\n'
            'OAI_KEY = "sk-proj-A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"\n'
            'GH_PAT = "ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"\n'
            'FEISHU = "https://open.feishu.cn/open-apis/bot/v2/hook/9a8b7c6d-1234-4e5f-8a9b-0c1d2e3f4a5b"\n'
            'DB = "postgresql://admin:P@ssw0rdStrong9@10.0.0.5:5432/app"\n'
        )
        out = self.scanner.scan_content(code, "prod_config.py")
        rule_ids = {f.rule_id for f in out.findings}
        self.assertIn("OG-SEC-001", rule_ids)
        self.assertIn("OG-SEC-003", rule_ids)
        self.assertIn("OG-SEC-010", rule_ids)
        self.assertIn("OG-SEC-018", rule_ids)
        self.assertIn("OG-SEC-028", rule_ids)
        self.assertIn("OG-SEC-038", rule_ids)

    def test_suppresses_ast_docstring_regex_env_and_inline_ignore(self) -> None:
        code = (
            'import os, re\n'
            'def fn():\n'
            '    """Example:\n'
            '    AWS_KEY = "AKIA7F4K9P2M8Q3X6Z1W"\n'
            '    """\n'
            '    pat = re.compile(r"ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u")\n'
            '    k = os.getenv("API_KEY", "sk-proj-A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u")\n'
            '    ignored = "ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"  # openguard: ignore\n'
            '    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n'
        )
        out = self.scanner.scan_content(code, "clean_module.py")
        self.assertEqual(len(out.findings), 0)
        self.assertGreaterEqual(out.suppressed_count, 3)

    def test_custom_rule_loaded_from_config(self) -> None:
        cfg = AuditConfig(
            custom_rules=[
                {
                    "rule_id": "OG-CUSTOM-HUST",
                    "name": "Internal Campus Token",
                    "pattern": r"hust_sec_[A-Za-z0-9]{16}",
                    "severity": "HIGH",
                    "min_entropy": 2.5,
                }
            ]
        )
        scanner = SecretScanner(cfg)
        out = scanner.scan_content('CAMPUS_TOKEN = "hust_sec_9X4mK2pQ8vW7nB5z"', "app.py")
        self.assertTrue(any(f.rule_id == "OG-CUSTOM-HUST" for f in out.findings))

    def test_detects_domestic_webhooks_and_private_keys(self) -> None:
        code = (
            'WECHAT_BOT = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=9f4c7a12-8b3d-4e91-a6c5-7d2e4f8b1c3a"\n'
            'DING_BOT = "https://oapi.dingtalk.com/robot/send?access_token=a9f2c8d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8"\n'
            'PEM_HDR = "-----BEGIN OPENSSH PRIVATE KEY-----"\n'
        )
        out = self.scanner.scan_content(code, "alerts.py")
        ids = {f.rule_id for f in out.findings}
        self.assertIn("OG-SEC-030", ids)
        self.assertIn("OG-SEC-029", ids)
        self.assertIn("OG-SEC-031", ids)

    def test_detects_huggingface_groq_and_npm_tokens(self) -> None:
        code = (
            'HF_TOKEN = "hf_A9mK2pQ8xL4vW7nB5zY3cJ6tD1fH9sA2eG"\n'
            'GROQ_KEY = "gsk_A9mK2pQ8xL4vW7nB5zY3cJ6tD1fH9sA2eG4uR7y"\n'
            'NPM_TOK = "npm_A9mK2pQ8xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"\n'
        )
        out = self.scanner.scan_content(code, "ci_env.py")
        ids = {f.rule_id for f in out.findings}
        self.assertIn("OG-SEC-013", ids)
        self.assertIn("OG-SEC-014", ids)
        self.assertIn("OG-SEC-024", ids)

    def test_detects_pii_phone_and_bank_card_in_context(self) -> None:
        code = (
            'USER_PHONE = "13892746150"\n'
            'BANK_CARD_NO = "6222020200112233446"\n'
        )
        out = self.scanner.scan_content(code, "pii_handler.py")
        ids = {f.rule_id for f in out.findings}
        self.assertIn("OG-PII-003", ids)
        self.assertIn("OG-PII-002", ids)

    def test_binary_file_is_safely_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_file = Path(tmp) / "blob.dat"
            bin_file.write_bytes(b"\x00\x01\x02AKIA7F4K9P2M8Q3X6Z1W\x00")
            out = self.scanner.scan_file(bin_file, Path(tmp))
            self.assertEqual(out.files_scanned, 0)
            self.assertEqual(len(out.findings), 0)

    def test_baseline_scanners_work_for_benchmark(self) -> None:
        sample = 'API_KEY = "sk-your_api_key_placeholder"\nAWS = "AKIA7F4K9P2M8Q3X6Z1W"\n'
        regex_hits = self.scanner.scan_baseline_regex_only(sample, "b.py")
        ent_hits = self.scanner.scan_baseline_entropy_only(sample, "b.py")
        self.assertGreaterEqual(len(regex_hits), 2)
        self.assertGreaterEqual(len(ent_hits), 1)

    def test_git_history_and_staged_diff_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "tester@hust.edu.cn"], cwd=str(repo), capture_output=True, check=True)

            f = repo / "secret.py"
            f.write_text('ANTHROPIC_KEY = "sk-ant-api03-Z9kP2mQ7xL4vW8nB5zY3cJ6tD1fH9sA2eG4u"\n', encoding="utf-8")
            subprocess.run(["git", "add", "secret.py"], cwd=str(repo), capture_output=True, check=True)

            # Staged diff check
            staged_out = SecretScanner(AuditConfig(staged_only=True)).scan_directory(repo)
            self.assertEqual(len(staged_out.findings), 1)
            self.assertEqual(staged_out.findings[0].rule_id, "OG-SEC-012")

            subprocess.run(["git", "commit", "-m", "add secret"], cwd=str(repo), capture_output=True, check=True)

            # Remove secret from HEAD
            f.write_text('import os\nANTHROPIC_KEY = os.getenv("ANTHROPIC_KEY", "")\n', encoding="utf-8")
            subprocess.run(["git", "add", "secret.py"], cwd=str(repo), capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "remove secret"], cwd=str(repo), capture_output=True, check=True)

            # Working tree clean, but Git history scanner detects ghost secret
            head_out = self.scanner.scan_directory(repo)
            self.assertEqual(len(head_out.findings), 0)

            hist = GitHistoryScanner(AuditConfig(include_git_history=True), self.scanner).scan_history(repo)
            self.assertEqual(len(hist), 1)
            self.assertTrue(hist[0].is_historical_only)
            self.assertEqual(hist[0].rule_id, "OG-SEC-012")


if __name__ == "__main__":
    unittest.main()
