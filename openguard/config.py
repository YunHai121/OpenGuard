"""Configuration loading and path exclusion handling for OpenGuard."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
    ".openguard_backup",
    "demo_outputs",
}

DEFAULT_EXCLUDE_PATTERNS = [
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dll",
    "*.exe",
    "*.bin",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.7z",
    "*.rar",
    "*.pdf",
    "*.docx",
    "*.xlsx",
    "*.pptx",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.mp4",
    "*.mp3",
    "*.sqlite",
    "*.db",
    "*.min.js",
    "*.min.css",
    "*.map",
]

DEFAULT_WEIGHTS: Dict[str, float] = {
    "secret_security": 0.30,
    "supply_chain_vuln": 0.20,
    "license_compliance": 0.20,
    "code_security": 0.15,
    "governance": 0.15,
}


class AuditConfig(BaseModel):
    """Runtime audit configuration model."""

    include_git_history: bool = False
    max_git_commits: int = 100
    offline: bool = False
    min_confidence: float = 0.45
    entropy_threshold: float = 3.3
    max_file_size_kb: int = 1024
    max_workers: int = 4
    staged_only: bool = False
    diff_ref: Optional[str] = None
    baseline_path: Optional[str] = None
    project_license_override: Optional[str] = None
    exclude_patterns: List[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS))
    custom_rules: List[Dict[str, Any]] = Field(default_factory=list)
    custom_sast_rules: List[Dict[str, Any]] = Field(default_factory=list)
    policy: Dict[str, Any] = Field(default_factory=dict)
    weights: Dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))


def load_ignore_patterns(root_path: Path) -> List[str]:
    """Load ignore patterns from `.openguardignore` if present."""
    patterns: List[str] = []
    ignore_file = root_path / ".openguardignore"
    if ignore_file.is_file():
        with ignore_file.open("r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line.replace("\\", "/"))
    return patterns


def load_config(root_path: Path, config_path: Optional[Path] = None) -> AuditConfig:
    """Load `.openguard.yml`/`.openguard.yaml` and `.openguardignore` from target repo."""
    cfg_data: Dict[str, Any] = {}
    candidates = [config_path] if config_path else [
        root_path / ".openguard.yml",
        root_path / ".openguard.yaml",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            with candidate.open("r", encoding="utf-8", errors="replace") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    cfg_data = loaded
            break

    config = AuditConfig(**{k: v for k, v in cfg_data.items() if k in AuditConfig.model_fields})
    repo_ignores = load_ignore_patterns(root_path)
    if repo_ignores:
        merged = list(config.exclude_patterns)
        for pat in repo_ignores:
            if pat not in merged:
                merged.append(pat)
        config.exclude_patterns = merged
    return config


def _strip_dot_slash(path_str: str) -> str:
    s = path_str.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/")


def is_path_excluded(rel_path: str, exclude_patterns: List[str]) -> bool:
    """Check whether a normalized POSIX relative path matches exclusion rules."""
    norm = _strip_dot_slash(rel_path)
    parts = [p for p in norm.split("/") if p]
    for part in parts:
        if part in DEFAULT_EXCLUDE_DIRS:
            return True

    filename = parts[-1] if parts else norm
    for raw_pat in exclude_patterns:
        pat = _strip_dot_slash(raw_pat)
        if not pat:
            continue
        if pat.endswith("/"):
            dir_prefix = pat.rstrip("/")
            if norm == dir_prefix or norm.startswith(dir_prefix + "/") or f"/{dir_prefix}/" in f"/{norm}":
                return True
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(filename, pat):
            return True
        if "/" in pat and norm.startswith(pat.rstrip("*")):
            return True
    return False
