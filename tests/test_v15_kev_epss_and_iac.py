"""Tests for Round #5 upgrades:
- CISA KEV & EPSS Risk-Based Vulnerability Prioritization Matrix (P0-P3)
- Cloud-Native IaC Misconfiguration Scanner (Docker Compose, Kubernetes YAML, Terraform HCL)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.reporters.markdown_reporter import render_pr_comment
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx
from openguard.scanners.iac_scanner import IaCScanner


class TestCisaKevEpssPrioritization(unittest.TestCase):
    def test_kev_epss_and_reachability_compute_p0_vs_p3_tiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "PyYAML==5.3.1\naiohttp==3.8.5\nfastapi==0.100.0\n",
                encoding="utf-8",
            )
            # Import & call yaml.load (EPSS 0.684, call_reachable -> P0)
            # Import aiohttp (CISA KEV CVE-2024-23334 -> P0)
            # Leave fastapi unimported (not KEV -> P3)
            (root / "app.py").write_text(
                "import yaml\nimport aiohttp\nyaml.load('a: 1')\n",
                encoding="utf-8",
            )
            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(root)
            by_id = {v.id: v for v in report.vulnerabilities}

            self.assertEqual(by_id["CVE-2020-14343"].priority_tier, "P0")
            self.assertGreater(by_id["CVE-2020-14343"].epss_score or 0.0, 0.5)

            self.assertTrue(by_id["CVE-2024-23334"].in_cisa_kev)
            self.assertEqual(by_id["CVE-2024-23334"].priority_tier, "P0")

            self.assertFalse(by_id["CVE-2024-24762"].in_cisa_kev)
            self.assertEqual(by_id["CVE-2024-24762"].priority_tier, "P3")

            # Verify CycloneDX exports KEV/EPSS/priority properties
            cdx = render_cyclonedx(report)
            aio_cdx = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2024-23334")
            props = {p["name"]: p["value"] for p in aio_cdx.get("properties", [])}
            self.assertEqual(props.get("openguard:cisa_kev"), "true")
            self.assertEqual(props.get("openguard:priority_tier"), "P0")

            # Verify PR comment highlights CISA KEV & P0
            pr_md = render_pr_comment(report)
            self.assertIn("CISA KEV", pr_md)
            self.assertIn("P0", pr_md)


class TestCloudNativeIaCScanner(unittest.TestCase):
    def test_scans_docker_compose_kubernetes_and_terraform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docker-compose.yml").write_text(
                "services:\n"
                "  db:\n"
                "    image: postgres:16\n"
                "    privileged: true\n"
                "    network_mode: host\n"
                "    volumes:\n"
                "      - /var/run/docker.sock:/var/run/docker.sock\n"
                "    ports:\n"
                "      - '0.0.0.0:5432:5432'\n",
                encoding="utf-8",
            )
            (root / "k8s-deploy.yaml").write_text(
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n"
                "  name: web\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      hostNetwork: true\n"
                "      containers:\n"
                "        - name: app\n"
                "          image: nginx:1.27\n"
                "          securityContext:\n"
                "            privileged: true\n"
                "            runAsUser: 0\n",
                encoding="utf-8",
            )
            (root / "main.tf").write_text(
                'resource "aws_security_group" "web" {\n'
                '  ingress {\n'
                '    from_port   = 22\n'
                '    to_port     = 22\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                '  }\n'
                '}\n'
                'resource "aws_s3_bucket" "data" {\n'
                '  acl = "public-read"\n'
                '}\n'
                'resource "aws_db_instance" "prod" {\n'
                '  storage_encrypted = false\n'
                '}\n',
                encoding="utf-8",
            )

            hits = IaCScanner().scan_repository(root)
            rule_ids = {h.rule_id for h in hits}
            expected = {
                "OG-IAC-001",
                "OG-IAC-002",
                "OG-IAC-003",
                "OG-IAC-004",
                "OG-IAC-005",
                "OG-IAC-006",
                "OG-IAC-007",
                "OG-IAC-008",
                "OG-IAC-009",
            }
            self.assertEqual(rule_ids, expected)


if __name__ == "__main__":
    unittest.main()
