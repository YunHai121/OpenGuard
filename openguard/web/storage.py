"""SQLite persistence and Before/After Diff comparator for OpenGuard Web Workbench."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from openguard.models import AuditReport


class AuditHistoryStore:
    """Persists audit runs in SQLite and computes diffs between historical scans."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        default_dir = Path.home() / ".openguard"
        self.db_path = Path(db_path) if db_path else (default_dir / "history.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_runs (
                    scan_id TEXT PRIMARY KEY,
                    scanned_at TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    project_license TEXT NOT NULL,
                    total_score REAL NOT NULL,
                    grade TEXT NOT NULL,
                    secrets_count INTEGER NOT NULL,
                    vulns_count INTEGER NOT NULL,
                    license_conflicts_count INTEGER NOT NULL,
                    sast_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )

    def save_report(self, report: AuditReport) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_runs (
                    scan_id, scanned_at, target_name, target_path, project_license,
                    total_score, grade, secrets_count, vulns_count,
                    license_conflicts_count, sast_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.scan_id,
                    report.scanned_at,
                    report.target_name,
                    report.target_path,
                    report.project_license,
                    report.summary.total_score,
                    report.summary.grade,
                    len(report.secrets) + len(report.git_history_secrets),
                    len(report.vulnerabilities),
                    len(report.license_conflicts),
                    len(report.code_security_findings),
                    report.model_dump_json(),
                ),
            )

    def list_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, scanned_at, target_name, target_path, project_license,
                       total_score, grade, secrets_count, vulns_count,
                       license_conflicts_count, sast_count
                FROM audit_runs
                ORDER BY rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_report(self, scan_id: str) -> Optional[AuditReport]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM audit_runs WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if not row:
            return None
        return AuditReport.model_validate_json(row["report_json"])

    @staticmethod
    def _finding_signatures(report: AuditReport) -> Dict[str, str]:
        sigs: Dict[str, str] = {}
        for f in report.secrets:
            key = f"SECRET|{f.rule_id}|{f.file_path}|{f.raw_hash}"
            sigs[key] = f"[密钥] {f.rule_name} @ {f.file_path}:{f.line_number}"
        for f in report.git_history_secrets:
            key = f"HIST|{f.rule_id}|{f.file_path}|{f.raw_hash}"
            sigs[key] = f"[历史密钥] {f.rule_name} @ {f.commit_hash}:{f.file_path}"
        for v in report.vulnerabilities:
            key = f"VULN|{v.id}|{v.component_name}"
            sigs[key] = f"[漏洞] {v.id} ({v.component_name}@{v.component_version})"
        for lc in report.license_conflicts:
            key = f"LIC|{lc.component_name}|{lc.component_license}"
            sigs[key] = f"[许可证] {lc.component_name} ({lc.component_license})"
        for cs in report.code_security_findings:
            key = f"SAST|{cs.rule_id}|{cs.file_path}|{cs.line_number}"
            sigs[key] = f"[SAST] {cs.rule_name} @ {cs.file_path}:{cs.line_number}"
        return sigs

    def diff_reports(self, before_id: str, after_id: str) -> Optional[Dict[str, Any]]:
        before = self.get_report(before_id)
        after = self.get_report(after_id)
        if not before or not after:
            return None

        sig_before = self._finding_signatures(before)
        sig_after = self._finding_signatures(after)

        resolved_keys = sorted(set(sig_before.keys()) - set(sig_after.keys()))
        new_keys = sorted(set(sig_after.keys()) - set(sig_before.keys()))
        persisting_keys = sorted(set(sig_before.keys()) & set(sig_after.keys()))

        dim_deltas = []
        after_dims = {d.key: d for d in after.summary.dimensions}
        for d in before.summary.dimensions:
            ad = after_dims.get(d.key)
            if ad:
                dim_deltas.append(
                    {
                        "name": d.name,
                        "before_score": d.score,
                        "after_score": ad.score,
                        "delta": round(ad.score - d.score, 1),
                    }
                )

        return {
            "before_scan_id": before.scan_id,
            "after_scan_id": after.scan_id,
            "before_target": before.target_name,
            "after_target": after.target_name,
            "before_score": before.summary.total_score,
            "after_score": after.summary.total_score,
            "score_delta": round(after.summary.total_score - before.summary.total_score, 1),
            "before_grade": before.summary.grade,
            "after_grade": after.summary.grade,
            "dimension_deltas": dim_deltas,
            "resolved_count": len(resolved_keys),
            "new_count": len(new_keys),
            "persisting_count": len(persisting_keys),
            "resolved_items": [sig_before[k] for k in resolved_keys],
            "new_items": [sig_after[k] for k in new_keys],
        }
