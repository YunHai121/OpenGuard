"""Automated secret extraction & refactoring patch generator with backup rollback."""

from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from openguard.models import AuditReport, SecretFinding


@dataclass
class PatchPreview:
    """Unified diff preview and remediation plan for a single source file."""

    file_path: str
    unified_diff: str
    env_vars_added: List[str] = field(default_factory=list)
    findings_fixed: int = 0


@dataclass
class RemediationResult:
    """Summary of planned or applied secret remediation operations."""

    applied: bool
    files_modified: int
    findings_remediated: int
    previews: List[PatchPreview] = field(default_factory=list)
    env_example_path: Optional[str] = None
    env_local_path: Optional[str] = None
    backup_dir: Optional[str] = None
    notes: List[str] = field(default_factory=list)


from typing import Optional  # noqa: E402


def _make_env_var_name(line: str, rule_id: str, index: int) -> str:
    m = re.match(r"^\s*(?:export\s+|const\s+|let\s+|var\s+)?[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*[:=]", line)
    if m:
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", m.group(1)).upper()
        if len(candidate) >= 3:
            return candidate
    suffix = rule_id.replace("OG-", "").replace("-", "_")
    return f"OPENGUARD_{suffix}_{index}"


class SecretRemediator:
    """Replaces hardcoded secrets with environment variable lookups and generates `.env.example`."""

    SUPPORTED_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yml", ".yaml", ".env", ".json"}

    def remediate(
        self,
        root_path: Path,
        report: AuditReport,
        apply: bool = False,
    ) -> RemediationResult:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent

        by_file: Dict[str, List[SecretFinding]] = {}
        for f in report.secrets:
            ext = Path(f.file_path).suffix.lower()
            fname = Path(f.file_path).name.lower()
            if ext in self.SUPPORTED_EXTS or fname.startswith(".env"):
                by_file.setdefault(f.file_path, []).append(f)

        previews: List[PatchPreview] = []
        extracted_env: Dict[str, str] = {}
        used_vars: Set[str] = set()
        total_fixed = 0
        backup_dir = root / ".openguard_backup"

        for rel_path, file_findings in sorted(by_file.items()):
            fpath = root / rel_path
            if not fpath.is_file():
                continue

            original_text = fpath.read_text(encoding="utf-8", errors="replace")
            lines = original_text.splitlines(keepends=True)
            ext = fpath.suffix.lower()
            is_py = ext == ".py"
            is_js = ext in (".js", ".ts", ".jsx", ".tsx")

            file_vars: List[str] = []
            fixed_here = 0

            # Process lines referencing findings
            target_lines = {f.line_number: f for f in file_findings}
            new_lines = list(lines)

            for ln, finding in sorted(target_lines.items()):
                idx = ln - 1
                if not (0 <= idx < len(new_lines)):
                    continue
                raw_line = new_lines[idx]
                line_ending = "\n" if raw_line.endswith("\n") else ""
                stripped_line = raw_line.rstrip("\r\n")

                # Skip lines already reading env vars
                if "os.getenv" in stripped_line or "process.env" in stripped_line:
                    continue

                var_name = _make_env_var_name(stripped_line, finding.rule_id, len(used_vars) + 1)
                while var_name in used_vars:
                    var_name = f"{var_name}_{len(used_vars) + 1}"
                used_vars.add(var_name)

                # Replace quoted literal value on RHS of assignment
                quoted_m = re.search(r"([\"'])([^\"'\n]{6,})\1", stripped_line)
                if not quoted_m:
                    continue
                original_literal_val = quoted_m.group(2)

                if is_py:
                    replacement_expr = f'os.getenv("{var_name}", "")'
                    updated = (
                        stripped_line[: quoted_m.start()]
                        + replacement_expr
                        + stripped_line[quoted_m.end():]
                    )
                elif is_js:
                    replacement_expr = f'process.env.{var_name} || ""'
                    updated = (
                        stripped_line[: quoted_m.start()]
                        + replacement_expr
                        + stripped_line[quoted_m.end():]
                    )
                elif fpath.name.lower().startswith(".env") or ext in (".yml", ".yaml"):
                    updated = (
                        stripped_line[: quoted_m.start()]
                        + f'"${{{var_name}}}"'
                        + stripped_line[quoted_m.end():]
                    )
                else:
                    updated = (
                        stripped_line[: quoted_m.start()]
                        + f'"${{{var_name}}}"'
                        + stripped_line[quoted_m.end():]
                    )

                new_lines[idx] = updated + line_ending
                extracted_env[var_name] = original_literal_val
                file_vars.append(var_name)
                fixed_here += 1

            if fixed_here == 0:
                continue

            # Ensure `import os` exists for modified Python files
            if is_py and not re.search(r"^\s*import\s+os\b|^\s*from\s+os\s+import\b", original_text, re.M):
                insert_pos = 0
                for i, l in enumerate(new_lines):
                    if l.startswith("#!") or l.startswith("# -*-") or l.lstrip().startswith('"""') or l.lstrip().startswith("'''"):
                        insert_pos = i + 1
                    elif l.strip():
                        break
                new_lines.insert(insert_pos, "import os\n")

            modified_text = "".join(new_lines)
            diff_str = "".join(
                difflib.unified_diff(
                    original_text.splitlines(keepends=True),
                    modified_text.splitlines(keepends=True),
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                )
            )
            previews.append(
                PatchPreview(
                    file_path=rel_path,
                    unified_diff=diff_str,
                    env_vars_added=file_vars,
                    findings_fixed=fixed_here,
                )
            )
            total_fixed += fixed_here

            if apply:
                backup_target = backup_dir / rel_path
                backup_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fpath, backup_target)
                fpath.write_text(modified_text, encoding="utf-8")

        env_ex_rel = None
        env_local_rel = None
        notes: List[str] = []

        if extracted_env:
            env_ex_path = root / ".env.example"
            env_local_path = root / ".env.openguard.local"
            env_ex_rel = ".env.example"
            env_local_rel = ".env.openguard.local"

            if apply:
                ex_lines = [
                    "# Auto-generated by OpenGuard SecretRemediator",
                    "# Fill in real credentials locally; NEVER commit `.env` or `.env.openguard.local`.",
                    "",
                ]
                local_lines = [
                    "# Extracted local secrets moved out of source code by OpenGuard.",
                    "# Rotate these compromised values immediately!",
                    "",
                ]
                for var, val in extracted_env.items():
                    ex_lines.append(f"{var}=REPLACE_WITH_YOUR_{var}")
                    local_lines.append(f"{var}={val}")

                env_ex_path.write_text("\n".join(ex_lines) + "\n", encoding="utf-8")
                env_local_path.write_text("\n".join(local_lines) + "\n", encoding="utf-8")

                # Protect extracted file inside .gitignore immediately
                gi = root / ".gitignore"
                gi_content = gi.read_text(encoding="utf-8", errors="replace") if gi.is_file() else ""
                additions = []
                for entry in (".env", ".env.openguard.local", ".openguard_backup/"):
                    if entry not in gi_content:
                        additions.append(entry)
                if additions:
                    sep = "\n" if gi_content and not gi_content.endswith("\n") else ""
                    gi.write_text(
                        gi_content + sep + "\n# OpenGuard secret protection\n" + "\n".join(additions) + "\n",
                        encoding="utf-8",
                    )
                notes.append("已创建 `.env.example` 与 `.env.openguard.local`，并将敏感文件加入 `.gitignore`。")
            else:
                notes.append(f"预览模式：共识别 {total_fixed} 处可自动剥离的硬编码密钥，涉及 {len(previews)} 个文件。")

        return RemediationResult(
            applied=apply,
            files_modified=len(previews),
            findings_remediated=total_fixed,
            previews=previews,
            env_example_path=env_ex_rel,
            env_local_path=env_local_rel,
            backup_dir=str(backup_dir.relative_to(root)) if apply and previews else None,
            notes=notes,
        )
