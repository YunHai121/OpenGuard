"""Unit tests for Round #13: 2025-2026 AI/Serverless secret detectors & Supabase JWT role discrimination."""

from __future__ import annotations

import base64
import json
import unittest

from openguard import __version__
from openguard.config import AuditConfig
from openguard.models import Severity
from openguard.scanners.secret_rules import (
    build_builtin_secret_rules,
    is_supabase_anon_jwt,
    validate_jwt,
    validate_supabase_service_role_jwt,
)
from openguard.scanners.secret_scanner import SecretScanner


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = "K9mP2qR8xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"
    return f"{header}.{body}.{sig}"


class TestModernAiCloudSecretsAndSupabaseJwt(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SecretScanner(AuditConfig(offline=True))

    def test_builtin_rule_count_and_v140_version(self) -> None:
        from packaging.version import Version

        rules = build_builtin_secret_rules()
        self.assertGreaterEqual(len(rules), 54)
        self.assertGreaterEqual(Version(__version__), Version("1.4.0"))

    def test_supabase_jwt_distinguishes_public_anon_vs_critical_service_role(self) -> None:
        anon_jwt = _make_jwt({"iss": "supabase", "ref": "demo1234", "role": "anon", "iat": 1700000000})
        service_jwt = _make_jwt({"iss": "supabase", "ref": "demo1234", "role": "service_role", "iat": 1700000000})
        normal_jwt = _make_jwt({"sub": "user_42", "role": "member", "iat": 1700000000})

        self.assertTrue(is_supabase_anon_jwt(anon_jwt))
        self.assertFalse(validate_jwt(anon_jwt))

        self.assertTrue(validate_supabase_service_role_jwt(service_jwt))

        # Scanning frontend file with public anon key yields 0 findings
        anon_out = self.scanner.scan_content(f'const SUPABASE_KEY = "{anon_jwt}";\n', "src/client.ts")
        self.assertEqual(len(anon_out.findings), 0)

        # Scanning backend file with service_role JWT flags OG-SEC-043 as CRITICAL (and does not double-fire OG-SEC-032)
        svc_out = self.scanner.scan_content(f'SERVICE_KEY = "{service_jwt}"\n', "src/server.py")
        self.assertEqual([f.rule_id for f in svc_out.findings], ["OG-SEC-043"])
        self.assertEqual(svc_out.findings[0].severity, Severity.CRITICAL)

        # Generic non-Supabase JWT still flags OG-SEC-032 as HIGH
        norm_out = self.scanner.scan_content(f'AUTH_TOKEN = "{normal_jwt}"\n', "src/auth.py")
        self.assertEqual([f.rule_id for f in norm_out.findings], ["OG-SEC-032"])
        self.assertEqual(norm_out.findings[0].severity, Severity.HIGH)

    def test_detects_2025_2026_ai_and_serverless_provider_tokens(self) -> None:
        # Build synthetic test tokens at runtime so static source holds zero real-looking literals
        ant_admin = "-".join(["sk", "ant", "admin01", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4uK9mP2"])
        openrouter = "-".join(["sk", "or", "v1", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"])
        xai_tok = "-".join(["xai", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4uK9mP2qR8xL4vW7nB5zY3"])
        pplx_tok = "-".join(["pplx", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4uK9mP2qR8"])
        sb_sec = "_".join(["sb", "secret", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2"])
        vercel_blob = "_".join(["vercel", "blob", "rw", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH"])
        langsmith = "_".join(["lsv2", "pt", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"])
        linear = "_".join(["lin", "api", "A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4uK9mP"])

        code = (
            f'ANT = "{ant_admin}"\n'
            f'OR_KEY = "{openrouter}"\n'
            f'XAI_KEY = "{xai_tok}"\n'
            f'PPLX_KEY = "{pplx_tok}"\n'
            f'SB_KEY = "{sb_sec}"\n'
            f'BLOB_TOKEN = "{vercel_blob}"\n'
            f'LS_KEY = "{langsmith}"\n'
            f'LIN_KEY = "{linear}"\n'
            'DOUBAO_API_KEY = "ark_9f8e7d6c5b4a3210fedcba987654"\n'
        )
        out = self.scanner.scan_content(code, "deploy/runtime_secrets.py")
        found_ids = {f.rule_id for f in out.findings}
        for expected in (
            "OG-SEC-012",
            "OG-SEC-016",
            "OG-SEC-044",
            "OG-SEC-045",
            "OG-SEC-046",
            "OG-SEC-047",
            "OG-SEC-048",
            "OG-SEC-049",
            "OG-SEC-050",
        ):
            self.assertIn(expected, found_ids, msg=f"Missing {expected} in {found_ids}")


if __name__ == "__main__":
    unittest.main()
