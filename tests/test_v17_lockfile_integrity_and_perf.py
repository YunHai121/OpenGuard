"""Tests for Round #7 / v1.3.0 upgrades:
- package-lock.json Integrity Tamper/Downgrade Guard (OG-SUP-LOCK-001 / OG-SUP-LOCK-002)
- Adaptive multi-threaded directory scanning deterministic parity (max_workers=1 vs max_workers=4)
- OpenGuard v1.3.0 version & OpenSSF hygiene files verification
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openguard import __version__
from openguard.config import AuditConfig
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.install_script_scanner import InstallScriptScanner
from openguard.scanners.secret_scanner import SecretScanner


class TestLockfileIntegrityAndConcurrentScan(unittest.TestCase):
    def test_detects_http_downgrade_and_missing_or_sha1_integrity_in_package_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_data = {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/evil-http": {
                        "version": "1.0.0",
                        "resolved": "http://registry.evil.invalid/evil-http-1.0.0.tgz",
                        "integrity": "sha512-abc",
                    },
                    "node_modules/weak-sha1": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/weak-sha1/-/weak-sha1-2.0.0.tgz",
                        "integrity": "sha1-oldhash",
                    },
                    "node_modules/safe-pkg": {
                        "version": "3.0.0",
                        "resolved": "https://registry.npmjs.org/safe-pkg/-/safe-pkg-3.0.0.tgz",
                        "integrity": "sha512-validstronghash==",
                    },
                },
            }
            (root / "package-lock.json").write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
            hits = InstallScriptScanner().scan_repository(root)
            ids = {h.id for h in hits}
            self.assertIn("OG-SUP-LOCK-001", ids)
            self.assertIn("OG-SUP-LOCK-002", ids)

    def test_multithreaded_scan_matches_sequential_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Create 24 files (>= 16 triggers ThreadPoolExecutor path)
            for i in range(24):
                body = f"x_{i} = {i}\n"
                if i in (3, 19):
                    body += "import pickle\npickle.loads(b'data')\n"
                if i in (7, 21):
                    body += 'AWS_KEY = "AKIA' + f'7F4K9P2M8Q3X6Z{i:02d}"\n'
                (root / f"mod_{i:02d}.py").write_text(body, encoding="utf-8")

            seq_sec = SecretScanner(AuditConfig(max_workers=1)).scan_directory(root)
            par_sec = SecretScanner(AuditConfig(max_workers=4)).scan_directory(root)
            self.assertEqual(
                [(f.file_path, f.line_number, f.rule_id) for f in seq_sec.findings],
                [(f.file_path, f.line_number, f.rule_id) for f in par_sec.findings],
            )
            self.assertEqual(len(par_sec.findings), 2)

            seq_sast = CodeSecurityScanner(AuditConfig(max_workers=1)).scan_directory(root)
            par_sast = CodeSecurityScanner(AuditConfig(max_workers=4)).scan_directory(root)
            self.assertEqual(
                [(f.file_path, f.line_number, f.rule_id) for f in seq_sast],
                [(f.file_path, f.line_number, f.rule_id) for f in par_sast],
            )
            self.assertEqual(len(par_sast), 2)

    def test_v130_metadata_and_openssf_hygiene_files_present(self) -> None:
        from packaging.version import Version

        self.assertGreaterEqual(Version(__version__), Version("1.3.0"))
        repo_root = Path(__file__).resolve().parents[1]
        self.assertTrue((repo_root / ".github" / "dependabot.yml").is_file())
        self.assertTrue((repo_root / ".github" / "CODEOWNERS").is_file())


if __name__ == "__main__":
    unittest.main()
