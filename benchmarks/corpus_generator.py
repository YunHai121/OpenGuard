"""Deterministic synthetic benchmark corpus generator for evaluating secret detection precision & recall."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import zlib
from dataclasses import dataclass
from typing import List

from openguard.scanners.secret_rules import _to_base62


def _make_crc32_ghp(rng: random.Random, alphabet: str) -> str:
    body = "".join(rng.choice(alphabet) for _ in range(30))
    crc = zlib.crc32(body.encode("ascii")) & 0xFFFFFFFF
    return f"ghp_{body}{_to_base62(crc, width=6)}"


def _make_supabase_jwt(rng: random.Random, role: str, alphabet: str) -> str:
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    ref = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
    pay = base64.urlsafe_b64encode(
        json.dumps({"iss": "supabase", "ref": ref, "role": role, "iat": 1730000000}).encode()
    ).decode().rstrip("=")
    sig = "".join(rng.choice(alphabet) for _ in range(32))
    return f"{hdr}.{pay}.{sig}"


@dataclass
class LabeledSample:
    """Single labeled code snippet for secret detection benchmarking."""

    sample_id: str
    category: str
    file_path: str
    content: str
    expected_positive: bool
    description: str


def _rand_token(rng: random.Random, length: int, alphabet: str) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _make_valid_chinese_id(rng: random.Random) -> str:
    area = rng.choice(["420102", "110105", "310104", "440305", "330106"])
    year = rng.randint(1985, 2004)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(100, 899)
    body = f"{area}{year:04d}{month:02d}{day:02d}{seq:03d}"
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = "10X98765432"
    chk = check_codes[sum(int(body[i]) * weights[i] for i in range(17)) % 11]
    return body + chk


def _make_invalid_chinese_id(rng: random.Random) -> str:
    valid = _make_valid_chinese_id(rng)
    wrong = "9" if valid[-1] != "9" else "8"
    return valid[:-1] + wrong


def generate_benchmark_corpus(seed: int = 20261120) -> List[LabeledSample]:
    """Generate 260 deterministic labeled samples (120 true positives + 140 realistic false-positive traps)."""
    rng = random.Random(seed)
    alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    upper_alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    hex_chars = "0123456789abcdef"
    samples: List[LabeledSample] = []

    # --- 100 True Positive Samples across 10 realistic classes ---
    for i in range(10):
        tok = "AKIA" + _rand_token(rng, 16, upper_alnum)
        samples.append(LabeledSample(f"TP-AWS-{i}", "cloud_aws", "src/cloud.py", f'AWS_ACCESS_KEY_ID = "{tok}"', True, "AWS Key assignment"))

    for i in range(10):
        tok = "LTAI" + _rand_token(rng, 18, alnum)
        samples.append(LabeledSample(f"TP-ALI-{i}", "cloud_aliyun", "config/oss.py", f'ALIYUN_ACCESS_KEY = "{tok}"', True, "Aliyun Key assignment"))

    for i in range(10):
        tok = "sk-proj-" + _rand_token(rng, 40, alnum)
        samples.append(LabeledSample(f"TP-OAI-{i}", "ai_openai", "llm/client.py", f'OPENAI_API_KEY = "{tok}"', True, "OpenAI key"))

    for i in range(10):
        tok = "sk-ant-api03-" + _rand_token(rng, 36, alnum)
        samples.append(LabeledSample(f"TP-ANT-{i}", "ai_anthropic", "llm/claude.py", f'ANTHROPIC_KEY = "{tok}"', True, "Anthropic key"))

    for i in range(10):
        tok = _make_crc32_ghp(rng, alnum)
        samples.append(LabeledSample(f"TP-GH-{i}", "scm_github", "ci/deploy.py", f'GITHUB_TOKEN = "{tok}"', True, "CRC32-valid GitHub PAT"))

    for i in range(10):
        tok = "glpat-" + _rand_token(rng, 22, alnum)
        samples.append(LabeledSample(f"TP-GL-{i}", "scm_gitlab", "ci/hust_sync.js", f'const GITLAB_TOKEN = "{tok}";', True, "GitLab PAT"))

    for i in range(10):
        pwd = _rand_token(rng, 14, alnum + "@#")
        samples.append(LabeledSample(f"TP-DB-{i}", "db_uri", "db/conn.py", f'DATABASE_URL = "postgresql://svc_app:{pwd}@10.0.1.8:5432/prod"', True, "PostgreSQL URI with password"))

    for i in range(10):
        uid = _rand_token(rng, 8, hex_chars) + "-" + _rand_token(rng, 4, hex_chars) + "-4abc-8def-" + _rand_token(rng, 12, hex_chars)
        samples.append(LabeledSample(f"TP-BOT-{i}", "webhook_feishu", "alerts/notify.py", f'FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/{uid}"', True, "Feishu webhook"))

    for i in range(10):
        cid = _make_valid_chinese_id(rng)
        samples.append(LabeledSample(f"TP-CID-{i}", "pii_id_card", "data/users.py", f'STUDENT_ID_NUMBER = "{cid}"', True, "Valid MOD 11-2 ID card"))

    for i in range(10):
        pwd = _rand_token(rng, 16, alnum + "!@#")
        samples.append(LabeledSample(f"TP-PWD-{i}", "hardcoded_pwd", "auth/admin.py", f'ADMIN_PASSWORD = "{pwd}"', True, "Hardcoded admin password"))

    for i in range(10):
        if i % 2 == 0:
            tok = "sk-or-v1-" + _rand_token(rng, 64, hex_chars)
            samples.append(LabeledSample(f"TP-AI26-{i}", "ai_openrouter", "llm/router.py", f'OPENROUTER_API_KEY = "{tok}"', True, "OpenRouter LLM gateway key"))
        else:
            tok = "xai-" + _rand_token(rng, 56, alnum)
            samples.append(LabeledSample(f"TP-AI26-{i}", "ai_xai", "llm/grok.py", f'XAI_API_KEY = "{tok}"', True, "xAI Grok API key"))

    for i in range(10):
        jwt_svc = _make_supabase_jwt(rng, "service_role", alnum)
        samples.append(LabeledSample(f"TP-SB-SVC-{i}", "cloud_supabase_service", "backend/db.ts", f'const SUPABASE_SERVICE_KEY = "{jwt_svc}";', True, "Supabase privileged service_role JWT"))

    # --- 140 True Negative (Realistic False-Positive Traps) ---
    for i in range(15):
        ph = rng.choice([
            "sk-your_example_api_key_placeholder",
            "AKIA_EXAMPLE_YOUR_ACCESS_KEY",
            "ghp_sample_dummy_token_replace_me",
            "glpat-placeholder_your_token_here",
            "changeme_secret_password_demo",
        ])
        samples.append(LabeledSample(f"TN-PH-{i}", "fp_placeholder", "src/settings.py", f'API_KEY = "{ph}"', False, "Placeholder literal"))

    for i in range(15):
        sha = hashlib.sha256(f"commit-{i}-{rng.random()}".encode()).hexdigest()
        samples.append(LabeledSample(f"TN-HEX-{i}", "fp_sha256", "build/manifest.py", f'PACKAGE_SHA256 = "{sha}"', False, "Pure SHA256 digest"))

    for i in range(15):
        uid = f"{_rand_token(rng,8,hex_chars)}-{_rand_token(rng,4,hex_chars)}-4{_rand_token(rng,3,hex_chars)}-a{_rand_token(rng,3,hex_chars)}-{_rand_token(rng,12,hex_chars)}"
        samples.append(LabeledSample(f"TN-UUID-{i}", "fp_uuid", "models/trace.py", f'REQUEST_TRACE_ID = "{uid}"', False, "Standard UUID trace ID"))

    for i in range(15):
        tok = "AKIA" + _rand_token(rng, 16, upper_alnum)
        samples.append(LabeledSample(f"TN-DOC-{i}", "fp_docstring", "src/helper.py", f'def connect():\n    """Example usage:\n    aws_key = "{tok}"\n    """\n    pass', False, "Python AST docstring example"))

    for i in range(15):
        tok = "ghp_" + _rand_token(rng, 36, alnum)
        samples.append(LabeledSample(f"TN-REG-{i}", "fp_regex_def", "src/rules.py", f'import re\nPATTERN = re.compile(r"{tok}")', False, "Python AST regex definition"))

    for i in range(15):
        samples.append(LabeledSample(f"TN-ENV-{i}", "fp_env_lookup", "src/app.py", 'import os\nSECRET_KEY = os.getenv("SECRET_KEY", "default_dev_key_123")', False, "Python AST os.getenv lookup"))

    for i in range(15):
        bad_id = _make_invalid_chinese_id(rng)
        samples.append(LabeledSample(f"TN-ID-{i}", "fp_invalid_id", "src/orders.py", f'SERIAL_BATCH_NO = "{bad_id}"', False, "18-digit string failing MOD 11-2"))

    for i in range(15):
        tok = "sk-proj-" + _rand_token(rng, 40, alnum)
        samples.append(LabeledSample(f"TN-IGN-{i}", "fp_inline_ignore", "src/mock.py", f'DEMO_KEY = "{tok}"  # openguard: ignore', False, "Inline suppression comment"))

    for i in range(10):
        jwt_anon = _make_supabase_jwt(rng, "anon", alnum)
        samples.append(LabeledSample(f"TN-SB-ANON-{i}", "fp_supabase_anon", "web/client.ts", f'const SUPABASE_ANON_KEY = "{jwt_anon}";', False, "Public client-side Supabase anon JWT"))

    for i in range(10):
        # CRC32-invalid mock token inside unit test file (caught by offline CRC32 + test context)
        bad_ghp = "ghp_" + _rand_token(rng, 30, alnum) + "000000"
        samples.append(LabeledSample(f"TN-CRC-MOCK-{i}", "fp_crc32_mock", "tests/test_github_mock.py", f'def test_auth():\n    token = "{bad_ghp}"\n    return token', False, "CRC32-invalid mock GitHub PAT in test"))

    return samples
