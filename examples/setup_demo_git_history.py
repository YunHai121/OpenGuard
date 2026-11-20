"""Create an isolated demo Git repository with deleted 'ghost secrets' in commit history."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path


def _force_remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _git(cwd: Path, *args: str) -> None:
    res = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return None


def create_demo_git_repo(target_dir: Path | None = None) -> Path:
    """Copy `vulnerable_demo_repo` and inject a historical secret commit that is later deleted."""
    repo_root = Path(__file__).resolve().parents[1]
    src = repo_root / "examples" / "vulnerable_demo_repo"
    dest = Path(target_dir) if target_dir else (repo_root / "demo_outputs" / "demo_git_repo")

    if dest.exists():
        shutil.rmtree(dest, onexc=_force_remove_readonly)
    shutil.copytree(src, dest)

    _git(dest, "init")
    _git(dest, "config", "user.name", "Demo Developer")
    _git(dest, "config", "user.email", "demo@hust.edu.cn")

    # Commit 1: Base project + an accidentally committed Anthropic & DingTalk key
    ghost_file = dest / "legacy_bot.py"
    ghost_file.write_text(
        '"""Temporary bot config committed by mistake."""\n'
        'CLAUDE_KEY = "sk-ant-api03-Z9kP2mQ7xL4vW8nB5zY3cJ6tD1fH9sA2eG4uR7"\n'
        'DINGTALK_BOT = "https://oapi.dingtalk.com/robot/send?access_token=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"\n',
        encoding="utf-8",
    )
    _git(dest, "add", ".")
    _git(dest, "commit", "-m", "feat: initial service setup with legacy bot config")

    # Commit 2: Developer deletes the hardcoded keys from HEAD, thinking it is safe
    ghost_file.write_text(
        '"""Cleaned bot config reading from environment."""\n'
        'import os\n'
        'CLAUDE_KEY = os.getenv("CLAUDE_KEY", "")\n'
        'DINGTALK_BOT = os.getenv("DINGTALK_BOT", "")\n',
        encoding="utf-8",
    )
    _git(dest, "add", "legacy_bot.py")
    _git(dest, "commit", "-m", "fix: remove hardcoded bot secrets from working tree")

    return dest


if __name__ == "__main__":
    created = create_demo_git_repo()
    print(f"Created isolated demo git repository with ghost secrets at: {created}")
