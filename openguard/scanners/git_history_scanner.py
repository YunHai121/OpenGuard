"""Git commit history scanner for detecting deleted 'ghost secrets' still exposed in VCS history."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from openguard.config import AuditConfig, is_path_excluded
from openguard.models import SecretFinding
from openguard.scanners.secret_scanner import SecretScanner


class GitHistoryScanner:
    """Scans historical Git commits to catch secrets deleted from HEAD but lingering in `.git`."""

    def __init__(self, config: AuditConfig, secret_scanner: SecretScanner) -> None:
        self.config = config
        self.secret_scanner = secret_scanner

    @staticmethod
    def get_git_metadata(repo_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """Return `(branch, short_commit_sha)` if `repo_path` is a Git repository."""
        if not (repo_path / ".git").exists():
            check = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if check.returncode != 0:
                return None, None

        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        sha_res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        branch = branch_res.stdout.strip() if branch_res.returncode == 0 else None
        commit = sha_res.stdout.strip() if sha_res.returncode == 0 else None
        return branch, commit

    def scan_history(
        self,
        repo_path: Path,
        head_secret_hashes: Optional[Set[str]] = None,
    ) -> List[SecretFinding]:
        """Scan up to `max_git_commits` recent commits for leaked historical secrets."""
        branch, _ = self.get_git_metadata(repo_path)
        if branch is None:
            return []

        cmd = [
            "git",
            "log",
            f"-n{self.config.max_git_commits}",
            "--no-merges",
            "--date=short",
            "--pretty=format:===OG_COMMIT===%H|%an|%ad",
            "-p",
            "-U0",
        ]
        res = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode != 0 or not res.stdout:
            return []

        existing_hashes = head_secret_hashes or set()
        seen_history: Set[Tuple[str, str]] = set()
        history_findings: List[SecretFinding] = []

        commit_hash = ""
        commit_author = ""
        commit_date = ""
        current_file = ""
        current_line = 0

        for raw_line in res.stdout.splitlines():
            if raw_line.startswith("===OG_COMMIT==="):
                meta = raw_line[len("===OG_COMMIT==="):].split("|", 2)
                if len(meta) == 3:
                    commit_hash, commit_author, commit_date = meta[0][:10], meta[1], meta[2]
                current_file = ""
                current_line = 0
                continue

            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip()
                continue

            if raw_line.startswith("@@ "):
                # Parse +start line number from unified diff header
                plus_part = raw_line.split("+", 1)[-1].split(" ", 1)[0]
                try:
                    current_line = int(plus_part.split(",")[0])
                except ValueError:
                    current_line = 1
                continue

            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                if not current_file or is_path_excluded(current_file, self.config.exclude_patterns):
                    current_line += 1
                    continue

                added_code = raw_line[1:]
                outcome = self.secret_scanner.scan_content(
                    added_code,
                    file_path=current_file,
                    line_offset=max(0, current_line - 1),
                    is_historical_only=True,
                    commit_hash=commit_hash,
                    commit_author=commit_author,
                    commit_date=commit_date,
                )
                for f in outcome.findings:
                    # Skip if exact secret is already active in HEAD (reported by working tree scanner)
                    if f.raw_hash in existing_hashes:
                        continue
                    dedup_key = (f.raw_hash, f.file_path)
                    if dedup_key in seen_history:
                        continue
                    seen_history.add(dedup_key)
                    f.remediation = (
                        f"该密钥虽已从当前代码移除，但仍残留在历史提交 `{commit_hash}` 中！"
                        f"请立即轮换凭据，并使用 `git filter-repo --path {current_file} --invert-paths` 清理历史。"
                    )
                    history_findings.append(f)
                current_line += 1

        return history_findings
