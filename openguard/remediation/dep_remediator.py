"""Snyk/Dependabot-inspired safe dependency version auto-upgrader."""

from __future__ import annotations

import difflib
from enum import Enum
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from openguard.models import AuditReport, FindingCategory

SEMVER_LIKE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9._\-]*)?$")


@dataclass
class DepUpgradePreview:
    """Single manifest file upgrade preview."""

    file_path: str
    upgraded_packages: List[str] = field(default_factory=list)
    unified_diff: str = ""


@dataclass
class DepRemediationResult:
    """Aggregate result of dependency remediation."""

    applied: bool = False
    files_modified: int = 0
    packages_upgraded: int = 0
    previews: List[DepUpgradePreview] = field(default_factory=list)


class DependencyRemediator:
    """Upgrades vulnerable pinned dependencies in requirements.txt, pyproject.toml, and package.json."""

    def remediate(
        self,
        root_path: Path,
        report: AuditReport,
        apply: bool = False,
    ) -> DepRemediationResult:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent

        # Collect best fixed_version per (ecosystem, pkg_lower)
        upgrades: Dict[Tuple[str, str], str] = {}
        for v in report.vulnerabilities:
            cat_val = str(v.category.value) if isinstance(v.category, Enum) else str(v.category)
            if cat_val != FindingCategory.VULNERABILITY.value:
                continue
            fixed = (v.fixed_version or "").strip()
            if not fixed or not SEMVER_LIKE_RE.match(fixed):
                continue
            key = (v.ecosystem.lower(), v.component_name.lower())
            # Prefer highest version string if multiple CVEs hit same package
            prev = upgrades.get(key)
            if prev is None or self._ver_tuple(fixed) > self._ver_tuple(prev):
                upgrades[key] = fixed

        if not upgrades:
            return DepRemediationResult(applied=apply)

        # Group candidate manifest files from components
        manifest_files: Dict[str, str] = {}
        for c in report.components:
            if (c.ecosystem.lower(), c.name.lower()) in upgrades and c.source_file:
                manifest_files[c.source_file] = c.ecosystem

        result = DepRemediationResult(applied=apply)
        backup_root = root / ".openguard_backup"

        for rel_file in sorted(manifest_files.keys()):
            fpath = (root / rel_file).resolve()
            if not fpath.is_file():
                continue
            low_name = fpath.name.lower()
            original = fpath.read_text(encoding="utf-8", errors="replace")
            updated = original
            changed_pkgs: List[str] = []

            if low_name.startswith("requirements") and low_name.endswith(".txt"):
                updated, changed_pkgs = self._upgrade_requirements_txt(original, upgrades)
            elif low_name == "pyproject.toml":
                updated, changed_pkgs = self._upgrade_pyproject_toml(original, upgrades)
            elif low_name == "package.json":
                updated, changed_pkgs = self._upgrade_package_json(original, upgrades)
            else:
                continue

            if not changed_pkgs or updated == original:
                continue

            diff = "".join(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    updated.splitlines(keepends=True),
                    fromfile=f"a/{rel_file}",
                    tofile=f"b/{rel_file}",
                )
            )
            result.previews.append(
                DepUpgradePreview(
                    file_path=rel_file,
                    upgraded_packages=changed_pkgs,
                    unified_diff=diff,
                )
            )
            result.files_modified += 1
            result.packages_upgraded += len(changed_pkgs)

            if apply:
                backup_target = backup_root / rel_file
                backup_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fpath, backup_target)
                fpath.write_text(updated, encoding="utf-8")

        return result

    @staticmethod
    def _ver_tuple(ver: str) -> Tuple[int, ...]:
        parts = re.findall(r"\d+", ver)
        return tuple(int(p) for p in parts) if parts else (0,)

    @staticmethod
    def _upgrade_requirements_txt(
        text: str, upgrades: Dict[Tuple[str, str], str]
    ) -> Tuple[str, List[str]]:
        out_lines: List[str] = []
        changed: List[str] = []
        pat = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]+\])?\s*(===|==|~=|>=|<=|>|<)?\s*([^\s;,#]+)?(.*)$")
        for line in text.splitlines(keepends=True):
            raw_no_nl = line.rstrip("\r\n")
            nl = line[len(raw_no_nl):]
            stripped = raw_no_nl.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(line)
                continue
            m = pat.match(raw_no_nl)
            if m:
                indent, pkg, extras, op, old_ver, tail = m.groups()
                fixed = upgrades.get(("pypi", pkg.lower()))
                if fixed and old_ver != fixed:
                    new_op = op if op in ("==", ">=", "~=") else ">="
                    extras_str = extras or ""
                    out_lines.append(f"{indent}{pkg}{extras_str}{new_op}{fixed}{tail}{nl}")
                    changed.append(f"{pkg}: {old_ver or 'unspecified'} -> {new_op}{fixed}")
                    continue
            out_lines.append(line)
        return "".join(out_lines), changed

    @staticmethod
    def _upgrade_pyproject_toml(
        text: str, upgrades: Dict[Tuple[str, str], str]
    ) -> Tuple[str, List[str]]:
        changed: List[str] = []
        updated = text
        for (eco, pkg_low), fixed in upgrades.items():
            if eco != "pypi":
                continue
            # Match quoted PEP 508 specs like "pyyaml==5.3.1" or "requests>=2.28.0"
            pat = re.compile(
                rf'(["\'])({re.escape(pkg_low)}(?:\[[^\]]+\])?\s*(?:==|>=|~=)\s*)([^"\';,\s]+)(["\'])',
                re.I,
            )

            def _repl(m: re.Match[str]) -> str:
                old_v = m.group(3)
                if old_v == fixed:
                    return m.group(0)
                changed.append(f"{pkg_low}: {old_v} -> {fixed}")
                return f"{m.group(1)}{m.group(2)}{fixed}{m.group(4)}"

            updated = pat.sub(_repl, updated)
        return updated, changed

    @staticmethod
    def _upgrade_package_json(
        text: str, upgrades: Dict[Tuple[str, str], str]
    ) -> Tuple[str, List[str]]:
        try:
            data = json.loads(text)
        except Exception:
            return text, []

        changed: List[str] = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for pkg_name, ver_spec in list(block.items()):
                fixed = upgrades.get(("npm", pkg_name.lower()))
                if fixed and isinstance(ver_spec, str):
                    prefix = "^" if ver_spec.startswith("^") else ("~" if ver_spec.startswith("~") else "^")
                    new_spec = f"{prefix}{fixed}"
                    if ver_spec != new_spec:
                        block[pkg_name] = new_spec
                        changed.append(f"{pkg_name}: {ver_spec} -> {new_spec}")

        if not changed:
            return text, []
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n", changed
