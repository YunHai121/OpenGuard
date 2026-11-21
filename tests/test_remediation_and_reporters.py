"""Tests for secret remediation, doc generator, Git hooks, and HTML/PDF/SARIF/SVG reporters."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.hook_installer import HookInstaller
from openguard.remediation.secret_remediator import SecretRemediator
from openguard.reporters.badge_generator import render_badge_svg
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.markdown_reporter import render_markdown_report
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.reporters.sarif_sbom_reporter import render_sarif


class TestRemediationAndReporters(unittest.TestCase):
    def test_secret_remediator_dry_run_and_apply_improves_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "demo"
            src_demo = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
            shutil.copytree(src_demo, repo)

            auditor = OpenGuardAuditor(AuditConfig(offline=True))
            before = auditor.audit(repo)
            self.assertGreater(len(before.secrets), 5)

            # Dry-run must not modify files
            dry = SecretRemediator().remediate(repo, before, apply=False)
            self.assertFalse(dry.applied)
            self.assertGreaterEqual(dry.findings_remediated, 5)
            self.assertFalse((repo / ".env.example").exists())

            # Apply changes & docs
            applied = SecretRemediator().remediate(repo, before, apply=True)
            self.assertTrue(applied.applied)
            self.assertTrue((repo / ".env.example").is_file())
            self.assertTrue((repo / ".env.openguard.local").is_file())
            self.assertTrue((repo / ".openguard_backup").is_dir())

            doc_actions = DocGenerator().generate(repo, license_id="MIT", apply=True)
            self.assertEqual(doc_actions["CONTRIBUTING.md"], "created")
            self.assertEqual(doc_actions["SECURITY.md"], "created")

            # Exclude local extracted secret file via .openguardignore as real users do
            (repo / ".openguardignore").write_text(".env.openguard.local\n", encoding="utf-8")
            after = auditor.audit(repo)
            self.assertLess(len(after.secrets), len(before.secrets))
            self.assertGreater(after.summary.total_score, before.summary.total_score)

    def test_doc_generator_supports_mulan_and_apache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r1 = Path(tmp) / "p1"
            r1.mkdir()
            DocGenerator().generate(r1, license_id="MulanPSL-2.0", apply=True)
            self.assertIn("木兰宽松许可证", (r1 / "LICENSE").read_text(encoding="utf-8"))

            r2 = Path(tmp) / "p2"
            r2.mkdir()
            DocGenerator().generate(r2, license_id="Apache-2.0", apply=True)
            self.assertIn("Apache License", (r2 / "LICENSE").read_text(encoding="utf-8"))

    def test_hook_installer_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "git_proj"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, check=True)

            res_ins = HookInstaller.install_pre_commit(repo)
            self.assertEqual(res_ins["status"], "installed")
            self.assertEqual(HookInstaller.status_pre_commit(repo)["installed"], "true")

            ci_res = HookInstaller.generate_ci_config(repo, platform="gitlab")
            self.assertTrue(Path(ci_res["path"]).is_file())

            res_un = HookInstaller.uninstall_pre_commit(repo)
            self.assertEqual(res_un["status"], "removed")

    def test_all_reporters_produce_valid_outputs(self) -> None:
        demo_dir = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(demo_dir)

        html_doc = render_html_report(report)
        self.assertIn("OpenGuard", html_doc)
        self.assertIn("<svg", html_doc)

        pdf_bytes = render_pdf_bytes(report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 2048)

        md_doc = render_markdown_report(report)
        self.assertIn("# OpenGuard", md_doc)

        sarif = render_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreater(len(sarif["runs"][0]["results"]), 5)

        svg_badge = render_badge_svg(report)
        self.assertIn("<svg", svg_badge)
        self.assertIn("OpenGuard", svg_badge)

    def test_export_report_all_formats_to_disk(self) -> None:
        demo_dir = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        auditor = OpenGuardAuditor(AuditConfig(offline=True))
        report = auditor.audit(demo_dir)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "all_exports"
            written = auditor.export_report(report, "all", out_dir)
            self.assertEqual(len(written), 9)
            self.assertIn("slsa_provenance.json", {p.name for p in written})
            for p in written:
                self.assertTrue(p.is_file())
                self.assertGreater(p.stat().st_size, 100)

    def test_remediator_handles_js_and_yaml_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            js_file = root / "cfg.js"
            js_file.write_text('export const GH_TOK = "ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u";\n', encoding="utf-8")
            yml_file = root / "app.yml"
            yml_file.write_text('openai_key: "sk-proj-A8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"\n', encoding="utf-8")

            auditor = OpenGuardAuditor(AuditConfig(offline=True))
            report = auditor.audit(root)
            res = SecretRemediator().remediate(root, report, apply=True)
            self.assertEqual(res.files_modified, 2)
            self.assertIn("process.env.", js_file.read_text(encoding="utf-8"))
            self.assertIn("${OPENAI_KEY}", yml_file.read_text(encoding="utf-8"))

    def test_badge_colors_reflect_score_tiers(self) -> None:
        demo_dir = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_demo_repo"
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(demo_dir)
        report.summary.total_score = 96.0
        report.summary.grade = "A+"
        self.assertIn("#10b981", render_badge_svg(report))
        report.summary.total_score = 84.0
        report.summary.grade = "B"
        self.assertIn("#3b82f6", render_badge_svg(report))
        report.summary.total_score = 72.0
        report.summary.grade = "C"
        self.assertIn("#f59e0b", render_badge_svg(report))


if __name__ == "__main__":
    unittest.main()
