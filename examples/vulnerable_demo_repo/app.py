"""Demo backend service intentionally containing secrets, SAST risks, and false-positive decoys."""

import os
import re
import subprocess
import requests
import yaml

# --- 1. Real Hardcoded Secrets (Expected to be CAUGHT by OpenGuard) ---
AWS_ACCESS_KEY_ID = "AKIA7F4K9P2M8Q3X6Z1W"
ALIYUN_ACCESS_KEY = "LTAI5t9xR2mP8qK4vW7nB"
OPENAI_API_KEY = "sk-proj-A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4uR7yT5kN"
DATABASE_DSN = "postgresql://admin_user:S3cr3tDbP@ss99@10.12.34.56:5432/campus_db"
FEISHU_ALERT_BOT = "https://open.feishu.cn/open-apis/bot/v2/hook/9a8b7c6d-1234-4e5f-8a9b-0c1d2e3f4a5b"

# --- 2. Realistic False-Positive Decoys (Expected to be SUPPRESSED by AST + Entropy) ---
DOC_EXAMPLE_TOKEN = "sk-your_api_key_placeholder_example"
GIT_COMMIT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SAFE_ENV_TOKEN = os.getenv("PRODUCTION_TOKEN", "fallback_sample")
KEY_REGEX = re.compile(r"AKIA[0-9A-Z]{16}")


def load_user_config(raw_yaml: str):
    """Unsafe YAML deserialization (CWE-502)."""
    return yaml.load(raw_yaml)


def run_diagnostic(user_host: str):
    """OS command injection (CWE-78) and disabled TLS verification (CWE-295)."""
    subprocess.run(f"ping -c 1 {user_host}", shell=True, check=False)
    return requests.get("https://internal.example.edu/status", verify=False, timeout=3)


def compute_dynamic_formula(expr: str):
    """Unsafe dynamic eval (CWE-95)."""
    return eval(expr)
