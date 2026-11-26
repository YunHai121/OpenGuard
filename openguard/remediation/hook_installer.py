"""Git pre-commit hook and CI/CD (GitLab CI for git.hust.edu.cn & GitHub Actions) installer."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Dict

PRE_COMMIT_SCRIPT = """#!/usr/bin/env sh
# OpenGuard Pre-commit Secret & Security Gatekeeper
echo "[OpenGuard] Checking staged changes for hardcoded secrets & high-risk code..."
if command -v openguard >/dev/null 2>&1; then
    openguard scan . --staged --offline --fail-on high
    STATUS=$?
elif command -v python3 >/dev/null 2>&1; then
    python3 -m openguard.cli scan . --staged --offline --fail-on high
    STATUS=$?
else
    python -m openguard.cli scan . --staged --offline --fail-on high
    STATUS=$?
fi

if [ $STATUS -ne 0 ]; then
    echo "[OpenGuard] BLOCKED: High/Critical secrets or security flaws found in staged files!"
    echo "Run 'openguard autofix . --secrets' to preview remediation or add '# openguard: ignore' if intentional."
    exit 1
fi
exit 0
"""

GITLAB_CI_TEMPLATE = """# OpenGuard Security & License Compliance Pipeline (Compatible with git.hust.edu.cn)
stages:
  - security_audit

openguard_audit:
  stage: security_audit
  image: python:3.11-slim
  variables:
    PIP_DISABLE_PIP_VERSION_CHECK: "1"
    PIP_DEFAULT_TIMEOUT: "60"
  before_script:
    - pip install --no-cache-dir -r requirements.txt
    - pip install --no-cache-dir -e . --no-build-isolation --no-deps
  script:
    - openguard scan . --offline --format all --output openguard_reports --fail-on critical
  artifacts:
    when: always
    paths:
      - openguard_reports/
    expire_in: 30 days
"""

GITHUB_ACTIONS_TEMPLATE = """name: OpenGuard Supply-Chain & Secret Audit

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read

jobs:
  openguard-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 50
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: "3.11"
      - name: Install OpenGuard
        run: |
          pip install --no-cache-dir -r requirements.txt
          pip install --no-cache-dir -e . --no-build-isolation --no-deps
      - name: Run OpenGuard Audit
        run: |
          openguard scan . --git-history --offline --format all --output openguard_reports --fail-on high
      - name: Upload Security Artifacts
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: openguard-security-reports
          path: openguard_reports/
"""


class HookInstaller:
    """Manages Git pre-commit hooks and CI/CD gatekeeper workflow files."""

    @staticmethod
    def install_pre_commit(repo_path: Path) -> Dict[str, str]:
        root = Path(repo_path).resolve()
        git_dir = root / ".git"
        if not git_dir.is_dir():
            return {"status": "error", "message": f"`{root}` 不是有效的 Git 仓库（缺少 `.git` 目录）。"}
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_file = hooks_dir / "pre-commit"
        hook_file.write_text(PRE_COMMIT_SCRIPT, encoding="utf-8", newline="\n")
        try:
            mode = hook_file.stat().st_mode
            hook_file.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass
        return {"status": "installed", "path": str(hook_file)}

    @staticmethod
    def uninstall_pre_commit(repo_path: Path) -> Dict[str, str]:
        hook_file = Path(repo_path).resolve() / ".git" / "hooks" / "pre-commit"
        if hook_file.is_file():
            content = hook_file.read_text(encoding="utf-8", errors="replace")
            if "OpenGuard" in content:
                hook_file.unlink()
                return {"status": "removed", "path": str(hook_file)}
            return {"status": "skipped", "message": "现有的 pre-commit 钩子非 OpenGuard 安装，未删除。"}
        return {"status": "not_found", "message": "未找到 pre-commit 钩子文件。"}

    @staticmethod
    def status_pre_commit(repo_path: Path) -> Dict[str, str]:
        hook_file = Path(repo_path).resolve() / ".git" / "hooks" / "pre-commit"
        if not hook_file.is_file():
            return {"installed": "false", "path": str(hook_file)}
        is_og = "OpenGuard" in hook_file.read_text(encoding="utf-8", errors="replace")
        return {"installed": "true" if is_og else "external", "path": str(hook_file)}

    @staticmethod
    def generate_ci_config(repo_path: Path, platform: str = "gitlab") -> Dict[str, str]:
        root = Path(repo_path).resolve()
        plat = platform.lower()
        if plat == "github":
            target = root / ".github" / "workflows" / "openguard.yml"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(GITHUB_ACTIONS_TEMPLATE, encoding="utf-8")
            return {"platform": "github", "path": str(target)}
        target = root / ".gitlab-ci.yml"
        target.write_text(GITLAB_CI_TEMPLATE, encoding="utf-8")
        return {"platform": "gitlab", "path": str(target)}
