"""Auditable effective Lines-of-Code (LOC) counter supporting multi-language projects."""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Set

from openguard.config import DEFAULT_EXCLUDE_DIRS

LANGUAGE_MAP: Dict[str, tuple[str, str, tuple[str, ...]]] = {
    ".py": ("Python", "#", ("'''", '"""')),
    ".js": ("JavaScript", "//", ("/*", "*/")),
    ".ts": ("TypeScript", "//", ("/*", "*/")),
    ".jsx": ("JavaScript", "//", ("/*", "*/")),
    ".tsx": ("TypeScript", "//", ("/*", "*/")),
    ".go": ("Go", "//", ("/*", "*/")),
    ".java": ("Java", "//", ("/*", "*/")),
    ".rs": ("Rust", "//", ("/*", "*/")),
    ".c": ("C", "//", ("/*", "*/")),
    ".cpp": ("C++", "//", ("/*", "*/")),
    ".h": ("C/C++ Header", "//", ("/*", "*/")),
    ".html": ("HTML", "<!--", ("<!--", "-->")),
    ".css": ("CSS", "/*", ("/*", "*/")),
    ".sh": ("Shell", "#", ()),
    ".ps1": ("PowerShell", "#", ("<#", "#>")),
    ".yml": ("YAML", "#", ()),
    ".yaml": ("YAML", "#", ()),
    ".json": ("JSON", "", ()),
    ".toml": ("TOML", "#", ()),
    ".md": ("Markdown", "", ()),
}


def count_file_loc(file_path: Path) -> Dict[str, Any]:
    """Count total, blank, comment, and effective code lines for a single source file."""
    ext = file_path.suffix.lower()
    lang_info = LANGUAGE_MAP.get(ext)
    if not lang_info:
        return {"language": "Other", "total": 0, "blank": 0, "comment": 0, "code": 0}

    lang_name, single_comment, block_markers = lang_info
    total = blank = comment = code = 0
    in_block = False
    block_end = ""

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            total += 1
            stripped = raw.strip()
            if not stripped:
                blank += 1
                continue

            if in_block:
                comment += 1
                if block_end and block_end in stripped:
                    in_block = False
                continue

            if single_comment and stripped.startswith(single_comment):
                comment += 1
                continue

            if len(block_markers) == 2:
                b_start, b_end = block_markers
                if (b_start, b_end) == ("'''", '"""'):
                    # Python triple-quote docstrings/comments (match exact opening delimiter)
                    matched_delim = ""
                    open_len = 0
                    for prefix in ('r"""', "r'''", '"""', "'''"):
                        if stripped.startswith(prefix):
                            matched_delim = prefix[-3:]
                            open_len = len(prefix)
                            break
                    if matched_delim:
                        comment += 1
                        if matched_delim not in stripped[open_len:]:
                            in_block = True
                            block_end = matched_delim
                        continue
                else:
                    if stripped.startswith(b_start):
                        comment += 1
                        if b_end not in stripped[len(b_start):]:
                            in_block = True
                            block_end = b_end
                        continue

            code += 1

    return {
        "language": lang_name,
        "total": total,
        "blank": blank,
        "comment": comment,
        "code": code,
    }


def count_repository_loc(
    root_path: Path,
    exclude_dirs: Iterable[str] | None = None,
    exclude_subpaths: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Count effective lines of code across a repository with transparent exclusions."""
    root = Path(root_path).resolve()
    excluded_dir_set: Set[str] = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        excluded_dir_set.update(exclude_dirs)
    subpath_prefixes = [p.replace("\\", "/").strip("/") for p in (exclude_subpaths or [])]

    by_lang: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"files": 0, "total": 0, "blank": 0, "comment": 0, "code": 0}
    )

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dir_set and d != ".git")
        rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
        if rel_dir != "." and any(rel_dir == pref or rel_dir.startswith(pref + "/") for pref in subpath_prefixes):
            dirnames[:] = []
            continue

        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in LANGUAGE_MAP:
                continue
            rel_file = fpath.relative_to(root).as_posix()
            if any(rel_file == pref or rel_file.startswith(pref + "/") for pref in subpath_prefixes):
                continue

            stats = count_file_loc(fpath)
            bucket = by_lang[stats["language"]]
            bucket["files"] += 1
            bucket["total"] += stats["total"]
            bucket["blank"] += stats["blank"]
            bucket["comment"] += stats["comment"]
            bucket["code"] += stats["code"]

    totals = {
        "files": sum(v["files"] for v in by_lang.values()),
        "total": sum(v["total"] for v in by_lang.values()),
        "blank": sum(v["blank"] for v in by_lang.values()),
        "comment": sum(v["comment"] for v in by_lang.values()),
        "code": sum(v["code"] for v in by_lang.values()),
    }

    return {
        "root_path": str(root),
        "excluded_dirs": sorted(excluded_dir_set),
        "excluded_subpaths": subpath_prefixes,
        "by_language": dict(sorted(by_lang.items(), key=lambda kv: kv[1]["code"], reverse=True)),
        "totals": totals,
    }
