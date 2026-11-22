"""Unit tests for Round #15: Multi-ecosystem dep remediation (Go/Cargo/Maven + --no-major) & 260-sample benchmark."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.corpus_generator import generate_benchmark_corpus
from benchmarks.run_benchmark import _evaluate_engine
from openguard.config import AuditConfig
from openguard.models import AuditReport, AuditSummary, DependencyComponent, FindingCategory, Severity, VulnerabilityFinding
from openguard.remediation.dep_remediator import DependencyRemediator
from openguard.scanners.secret_scanner import SecretScanner


class TestMultiEcoRemediationAndExpandedBenchmark(unittest.TestCase):
    def test_remediator_upgrades_go_cargo_and_maven_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.com/demo\n\n"
                "go 1.22\n\n"
                "require (\n"
                "\tgolang.org/x/net v0.15.0 // indirect\n"
                ")\n",
                encoding="utf-8",
            )
            (root / "Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\n\n'
                "[dependencies]\n"
                'openssl = "0.10.55"\n'
                'serde = { version = "^1.0.180", features = ["derive"] }\n',
                encoding="utf-8",
            )
            (root / "pom.xml").write_text(
                "<project>\n  <dependencies>\n"
                "    <dependency>\n"
                "      <groupId>org.apache.logging.log4j</groupId>\n"
                "      <artifactId>log4j-core</artifactId>\n"
                "      <version>2.14.1</version>\n"
                "    </dependency>\n"
                "  </dependencies>\n</project>\n",
                encoding="utf-8",
            )

            report = AuditReport(
                target_path=str(root),
                target_name="polyglot",
                summary=AuditSummary(total_score=50.0, grade="C"),
                components=[
                    DependencyComponent(name="golang.org/x/net", version="0.15.0", ecosystem="Go", source_file="go.mod"),
                    DependencyComponent(name="openssl", version="0.10.55", ecosystem="crates.io", source_file="Cargo.toml"),
                    DependencyComponent(
                        name="org.apache.logging.log4j:log4j-core",
                        version="2.14.1",
                        ecosystem="Maven",
                        source_file="pom.xml",
                    ),
                ],
                vulnerabilities=[
                    VulnerabilityFinding(
                        id="CVE-2023-44487",
                        component_name="golang.org/x/net",
                        component_version="0.15.0",
                        ecosystem="Go",
                        severity=Severity.HIGH,
                        summary="HTTP/2 Rapid Reset DoS",
                        fixed_version="v0.17.0",
                        category=FindingCategory.VULNERABILITY,
                    ),
                    VulnerabilityFinding(
                        id="RUSTSEC-2024-0001",
                        component_name="openssl",
                        component_version="0.10.55",
                        ecosystem="crates.io",
                        severity=Severity.HIGH,
                        summary="OpenSSL crate vulnerability",
                        fixed_version="0.10.66",
                        category=FindingCategory.VULNERABILITY,
                    ),
                    VulnerabilityFinding(
                        id="CVE-2021-44228",
                        component_name="org.apache.logging.log4j:log4j-core",
                        component_version="2.14.1",
                        ecosystem="Maven",
                        severity=Severity.CRITICAL,
                        summary="Log4Shell RCE",
                        fixed_version="2.17.1",
                        category=FindingCategory.VULNERABILITY,
                    ),
                ],
            )

            res = DependencyRemediator().remediate(root, report, apply=True)
            self.assertEqual(res.files_modified, 3)
            self.assertEqual(res.packages_upgraded, 3)
            self.assertIn("golang.org/x/net v0.17.0 // indirect", (root / "go.mod").read_text(encoding="utf-8"))
            self.assertIn('openssl = "0.10.66"', (root / "Cargo.toml").read_text(encoding="utf-8"))
            self.assertIn("<version>2.17.1</version>", (root / "pom.xml").read_text(encoding="utf-8"))

    def test_breaking_major_warning_and_no_major_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("pyyaml==5.3.1\nrequests==2.28.0\n", encoding="utf-8")
            report = AuditReport(
                target_path=str(root),
                target_name="py-app",
                summary=AuditSummary(total_score=50.0, grade="C"),
                components=[
                    DependencyComponent(name="pyyaml", version="5.3.1", ecosystem="PyPI", source_file="requirements.txt"),
                    DependencyComponent(name="requests", version="2.28.0", ecosystem="PyPI", source_file="requirements.txt"),
                ],
                vulnerabilities=[
                    VulnerabilityFinding(
                        id="CVE-2020-14343",
                        component_name="pyyaml",
                        component_version="5.3.1",
                        ecosystem="PyPI",
                        severity=Severity.CRITICAL,
                        summary="PyYAML arbitrary code execution",
                        fixed_version="6.0.1",  # Major bump 5 -> 6
                        category=FindingCategory.VULNERABILITY,
                    ),
                    VulnerabilityFinding(
                        id="CVE-2023-32681",
                        component_name="requests",
                        component_version="2.28.0",
                        ecosystem="PyPI",
                        severity=Severity.MEDIUM,
                        summary="Requests Proxy-Authorization header leak",
                        fixed_version="2.31.0",  # Minor bump 2.28 -> 2.31
                        category=FindingCategory.VULNERABILITY,
                    ),
                ],
            )

            # With allow_major=False, only requests is upgraded and pyyaml is skipped
            safe_res = DependencyRemediator().remediate(root, report, apply=False, allow_major=False)
            self.assertEqual(safe_res.packages_upgraded, 1)
            self.assertEqual(len(safe_res.skipped_breaking), 1)
            self.assertIn("pyyaml", safe_res.skipped_breaking[0])

            # With allow_major=True, both upgrade and breaking_warnings flags pyyaml
            full_res = DependencyRemediator().remediate(root, report, apply=False, allow_major=True)
            self.assertEqual(full_res.packages_upgraded, 2)
            self.assertEqual(len(full_res.breaking_warnings), 1)
            self.assertIn("BREAKING MAJOR", full_res.breaking_warnings[0])

    def test_expanded_260_sample_benchmark_maintains_zero_fpr_and_full_recall(self) -> None:
        corpus = generate_benchmark_corpus()
        self.assertEqual(len(corpus), 260)
        scanner = SecretScanner(AuditConfig(offline=True))
        metrics = _evaluate_engine(
            "OpenGuard Hybrid",
            corpus,
            lambda content, path: scanner.scan_content(content, path).findings,
        )
        self.assertEqual(metrics["tp"], 120)
        self.assertEqual(metrics["tn"], 140)
        self.assertEqual(metrics["fp"], 0)
        self.assertEqual(metrics["fn"], 0)
        self.assertEqual(metrics["f1_score"], 1.0)


if __name__ == "__main__":
    unittest.main()
