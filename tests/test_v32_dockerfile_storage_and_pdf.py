"""Regression tests for Round #22: multi-stage Dockerfile, WAL SQLite storage & PDF compliance/empty-dim safety."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig, load_config
from openguard.models import AuditReport, AuditSummary
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.scanners.dockerfile_scanner import DockerfileScanner
from openguard.web.storage import AuditHistoryStore

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestDockerfileStorageAndPdf(unittest.TestCase):
    def test_multistage_dockerfile_resets_user_ignores_stage_alias_and_catches_registry_port(self) -> None:
        scanner = DockerfileScanner()
        df_multistage = (
            "FROM python:3.11-slim AS builder\n"
            "RUN useradd -r appuser\n"
            "USER appuser\n"
            "\n"
            "FROM python:3.11-slim\n"
            "COPY --from=builder /app /app\n"
        )
        hits = scanner.scan_content(df_multistage, "Dockerfile")
        self.assertIn("OG-DOCKER-002", [h.rule_id for h in hits])

        df_alias_and_port = (
            "FROM registry.internal:5000/org/app AS base\n"
            "USER appuser\n"
            "FROM base\n"
            "CMD [\"python\"]\n"
        )
        hits2 = scanner.scan_content(df_alias_and_port, "Dockerfile")
        ids2 = [h.rule_id for h in hits2]
        self.assertEqual(ids2.count("OG-DOCKER-001"), 1)
        self.assertNotIn("OG-DOCKER-002", ids2)

    def test_history_store_wal_and_repeated_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "og_wal.db"
            store = AuditHistoryStore(db_path=db_path)
            rep = AuditReport(
                target_path=str(REPO_ROOT),
                target_name="demo",
                summary=AuditSummary(total_score=95.0, grade="A", files_scanned=1, lines_scanned=10),
            )
            store.save_report(rep)
            loaded = store.get_report(rep.scan_id)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.scan_id, rep.scan_id)

    def test_pdf_handles_empty_dimensions_and_includes_compliance_on_real_audit(self) -> None:
        empty_rep = AuditReport(
            target_path=".",
            target_name="empty-dims",
            summary=AuditSummary(total_score=100.0, grade="A+", files_scanned=0, lines_scanned=0, dimensions=[]),
        )
        pdf_empty = render_pdf_bytes(empty_rep)
        self.assertTrue(pdf_empty.startswith(b"%PDF-"))

        cfg = load_config(REPO_ROOT)
        cfg.offline = True
        real_rep = OpenGuardAuditor(cfg).audit(REPO_ROOT)
        pdf_real = render_pdf_bytes(real_rep)
        self.assertTrue(pdf_real.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_real), 2000)


if __name__ == "__main__":
    unittest.main()
