"""OSV-Scanner / Renovate / Dependabot-inspired multi-ecosystem safe dependency auto-upgrader.

Supports 6 manifest formats:
- PyPI: `requirements*.txt`, `pyproject.toml`
- npm: `package.json`
- Go: `go.mod`
- Rust: `Cargo.toml`
- Java Maven: `pom.xml`

Includes breaking major-version boundary detection (`breaking_warnings`) and optional
`allow_major=False` (`--no-major`) guard inspired by Renovate & OSV-Scanner Guided Remediation.
"""

from __future__ import annotations

import difflib
from enum import Enum
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from openguard.models import AuditReport, FindingCategory

SEMVER_LIKE_RE = re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9._\-]*)?$")


@dataclass
class DepUpgradePreview:
    """Single manifest file upgrade preview."""

    file_path: str
    upgraded_packages: List[str] = field(default_factory=list)
    breaking_warnings: List[str] = field(default_factory=list)
    skipped_breaking: List[str] = field(default_factory=list)
    unified_diff: str = ""


@dataclass
class DepRemediationResult:
    """Aggregate result of dependency remediation."""

    applied: bool = False
    files_modified: int = 0
    packages_upgraded: int = 0
    breaking_warnings: List[str] = field(default_factory=list)
    skipped_breaking: List[str] = field(default_factory=list)
    previews: List[DepUpgradePreview] = field(default_factory=list)


class DependencyRemediator:
    """Upgrades vulnerable pinned dependencies across PyPI, npm, Go, Cargo, and Maven manifests."""

    def remediate(
        self,
        root_path: Path,
        report: AuditReport,
        apply: bool = False,
        allow_major: bool = True,
    ) -> DepRemediationResult:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent

        # Collect best fixed_version per (ecosystem_norm, pkg_lower)
        upgrades: Dict[Tuple[str, str], str] = {}
        for v in report.vulnerabilities:
            cat_val = str(v.category.value) if isinstance(v.category, Enum) else str(v.category)
            if cat_val != FindingCategory.VULNERABILITY.value:
                continue
            raw_fixed = (v.fixed_version or "").strip()
            if not raw_fixed or not SEMVER_LIKE_RE.match(raw_fixed):
                continue
            fixed = raw_fixed.lstrip("vV")
            eco_key = self._norm_eco(v.ecosystem)
            key = (eco_key, v.component_name.lower())
            prev = upgrades.get(key)
            if prev is None or self._ver_tuple(fixed) > self._ver_tuple(prev):
                upgrades[key] = fixed

        if not upgrades:
            return DepRemediationResult(applied=apply)

        manifest_files: Dict[str, str] = {}
        for c in report.components:
            if (self._norm_eco(c.ecosystem), c.name.lower()) in upgrades and c.source_file:
                manifest_files[c.source_file] = c.ecosystem

        result = DepRemediationResult(applied=apply)
        backup_root = root / ".openguard_backup"

        for rel_file in sorted(manifest_files.keys()):
            fpath = (root / rel_file).resolve()
            if not fpath.is_relative_to(root) or not fpath.is_file():
                continue
            low_name = fpath.name.lower()
            original = fpath.read_text(encoding="utf-8", errors="replace")
            updated = original
            changed_pkgs: List[str] = []
            breaking: List[str] = []
            skipped: List[str] = []

            if low_name.startswith("requirements") and low_name.endswith(".txt"):
                updated, changed_pkgs, breaking, skipped = self._upgrade_requirements_txt(
                    original, upgrades, allow_major=allow_major
                )
            elif low_name == "pyproject.toml":
                updated, changed_pkgs, breaking, skipped = self._upgrade_pyproject_toml(
                    original, upgrades, allow_major=allow_major
                )
            elif low_name == "package.json":
                updated, changed_pkgs, breaking, skipped = self._upgrade_package_json(
                    original, upgrades, allow_major=allow_major
                )
            elif low_name == "go.mod":
                updated, changed_pkgs, breaking, skipped = self._upgrade_go_mod(
                    original, upgrades, allow_major=allow_major
                )
            elif low_name == "cargo.toml":
                updated, changed_pkgs, breaking, skipped = self._upgrade_cargo_toml(
                    original, upgrades, allow_major=allow_major
                )
            elif low_name == "pom.xml":
                updated, changed_pkgs, breaking, skipped = self._upgrade_pom_xml(
                    original, upgrades, allow_major=allow_major
                )
            else:
                continue

            if skipped:
                result.skipped_breaking.extend(f"{rel_file}: {s}" for s in skipped)

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
                    breaking_warnings=breaking,
                    skipped_breaking=skipped,
                    unified_diff=diff,
                )
            )
            result.breaking_warnings.extend(f"{rel_file}: {w}" for w in breaking)
            result.files_modified += 1
            result.packages_upgraded += len(changed_pkgs)

            if apply:
                backup_target = backup_root / rel_file
                backup_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fpath, backup_target)
                fpath.write_text(updated, encoding="utf-8")

        return result

    @staticmethod
    def _norm_eco(eco: str) -> str:
        low = (eco or "").lower().strip()
        if low in ("cargo", "crates.io", "rust"):
            return "cargo"
        return low

    @staticmethod
    def _ver_tuple(ver: str) -> Tuple[int, ...]:
        parts = re.findall(r"\d+", ver)
        return tuple(int(p) for p in parts) if parts else (0,)

    @classmethod
    def _is_major_upgrade(cls, old_ver: Optional[str], new_ver: str, ecosystem: str) -> bool:
        if not old_ver:
            return False
        old_t = cls._ver_tuple(old_ver)
        new_t = cls._ver_tuple(new_ver)
        if not old_t or not new_t:
            return False
        if old_t[0] != new_t[0]:
            return new_t[0] > old_t[0]
        # Cargo 0.x -> 0.y treats minor bump as breaking
        if ecosystem == "cargo" and old_t[0] == 0 and len(old_t) >= 2 and len(new_t) >= 2:
            return new_t[1] > old_t[1]
        return False

    @classmethod
    def _upgrade_requirements_txt(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        out_lines: List[str] = []
        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        pat = re.compile(
            r"^(\s*)([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]+\])?\s*(===|==|~=|>=|<=|>|<)?\s*([^\s;,#]+)?(.*)$"
        )
        for line in text.splitlines(keepends=True):
            raw_no_nl = line.rstrip("\r\n")
            nl = line[len(raw_no_nl) :]
            stripped = raw_no_nl.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(line)
                continue
            m = pat.match(raw_no_nl)
            if m:
                indent, pkg, extras, op, old_ver, tail = m.groups()
                fixed = upgrades.get(("pypi", pkg.lower()))
                if fixed and old_ver != fixed:
                    is_maj = cls._is_major_upgrade(old_ver, fixed, "pypi")
                    if is_maj and not allow_major:
                        skipped.append(f"{pkg}: {old_ver} -> {fixed} [BREAKING MAJOR skipped]")
                        out_lines.append(line)
                        continue
                    new_op = op if op in ("==", ">=", "~=") else ">="
                    extras_str = extras or ""
                    out_lines.append(f"{indent}{pkg}{extras_str}{new_op}{fixed}{tail}{nl}")
                    changed.append(f"{pkg}: {old_ver or 'unspecified'} -> {new_op}{fixed}")
                    if is_maj:
                        breaking.append(f"[BREAKING MAJOR] {pkg}: {old_ver} -> {fixed}")
                    continue
            out_lines.append(line)
        return "".join(out_lines), changed, breaking, skipped

    @classmethod
    def _upgrade_pyproject_toml(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        updated = text
        for (eco, pkg_low), fixed in upgrades.items():
            if eco != "pypi":
                continue
            pat = re.compile(
                rf'(["\'])({re.escape(pkg_low)}(?:\[[^\]]+\])?\s*(?:==|>=|~=)\s*)([^"\';,\s]+)(["\'])',
                re.I,
            )

            def _repl(m: re.Match[str]) -> str:
                old_v = m.group(3)
                if old_v == fixed:
                    return m.group(0)
                is_maj = cls._is_major_upgrade(old_v, fixed, "pypi")
                if is_maj and not allow_major:
                    skipped.append(f"{pkg_low}: {old_v} -> {fixed} [BREAKING MAJOR skipped]")
                    return m.group(0)
                changed.append(f"{pkg_low}: {old_v} -> {fixed}")
                if is_maj:
                    breaking.append(f"[BREAKING MAJOR] {pkg_low}: {old_v} -> {fixed}")
                return f"{m.group(1)}{m.group(2)}{fixed}{m.group(4)}"

            updated = pat.sub(_repl, updated)
        return updated, changed, breaking, skipped

    @classmethod
    def _upgrade_package_json(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        try:
            data = json.loads(text)
        except Exception:
            return text, [], [], []

        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for pkg_name, ver_spec in list(block.items()):
                fixed = upgrades.get(("npm", pkg_name.lower()))
                if fixed and isinstance(ver_spec, str):
                    old_clean = ver_spec.lstrip("^~>=<vV ")
                    prefix = "^" if ver_spec.startswith("^") else ("~" if ver_spec.startswith("~") else "^")
                    new_spec = f"{prefix}{fixed}"
                    if ver_spec == new_spec:
                        continue
                    is_maj = cls._is_major_upgrade(old_clean, fixed, "npm")
                    if is_maj and not allow_major:
                        skipped.append(f"{pkg_name}: {ver_spec} -> {new_spec} [BREAKING MAJOR skipped]")
                        continue
                    block[pkg_name] = new_spec
                    changed.append(f"{pkg_name}: {ver_spec} -> {new_spec}")
                    if is_maj:
                        breaking.append(f"[BREAKING MAJOR] {pkg_name}: {ver_spec} -> {new_spec}")

        if not changed:
            return text, [], breaking, skipped
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n", changed, breaking, skipped

    @classmethod
    def _upgrade_go_mod(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        out_lines: List[str] = []
        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        pat = re.compile(r"^(\s*(?:require\s+)?)([A-Za-z0-9._\-/]+)(\s+)(v\d+\.\d+\.\d+[^\s]*)(.*)$")
        for line in text.splitlines(keepends=True):
            raw_no_nl = line.rstrip("\r\n")
            nl = line[len(raw_no_nl) :]
            m = pat.match(raw_no_nl)
            if m:
                prefix, mod_path, sep, old_ver, tail = m.groups()
                fixed = upgrades.get(("go", mod_path.lower()))
                if fixed:
                    new_ver = f"v{fixed}"
                    if old_ver != new_ver:
                        is_maj = cls._is_major_upgrade(old_ver.lstrip("v"), fixed, "go")
                        if is_maj and not allow_major:
                            skipped.append(f"{mod_path}: {old_ver} -> {new_ver} [BREAKING MAJOR Go import-path change]")
                            out_lines.append(line)
                            continue
                        out_lines.append(f"{prefix}{mod_path}{sep}{new_ver}{tail}{nl}")
                        changed.append(f"{mod_path}: {old_ver} -> {new_ver}")
                        if is_maj:
                            breaking.append(
                                f"[BREAKING MAJOR] {mod_path}: {old_ver} -> {new_ver} (Go v2+ 需同步更新源码 import 路径)"
                            )
                        continue
            out_lines.append(line)
        return "".join(out_lines), changed, breaking, skipped

    @classmethod
    def _upgrade_cargo_toml(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        out_lines: List[str] = []
        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        simple_pat = re.compile(r'^(\s*)([A-Za-z0-9_\-]+)(\s*=\s*")([~^=<>]*)(\d+\.\d+(?:\.\d+)?[^"]*)(".*)$')
        table_pat = re.compile(
            r'^(\s*)([A-Za-z0-9_\-]+)(\s*=\s*\{[^}]*version\s*=\s*")([~^=<>]*)(\d+\.\d+(?:\.\d+)?[^"]*)(".*)$'
        )
        for line in text.splitlines(keepends=True):
            raw_no_nl = line.rstrip("\r\n")
            nl = line[len(raw_no_nl) :]
            m = simple_pat.match(raw_no_nl) or table_pat.match(raw_no_nl)
            if m:
                indent, crate, mid, op, old_ver, tail = m.groups()
                fixed = upgrades.get(("cargo", crate.lower()))
                if fixed and old_ver != fixed:
                    is_maj = cls._is_major_upgrade(old_ver, fixed, "cargo")
                    if is_maj and not allow_major:
                        skipped.append(f"{crate}: {op}{old_ver} -> {op}{fixed} [BREAKING MAJOR skipped]")
                        out_lines.append(line)
                        continue
                    out_lines.append(f"{indent}{crate}{mid}{op}{fixed}{tail}{nl}")
                    changed.append(f"{crate}: {op}{old_ver} -> {op}{fixed}")
                    if is_maj:
                        breaking.append(f"[BREAKING MAJOR] {crate}: {op}{old_ver} -> {op}{fixed}")
                    continue
            out_lines.append(line)
        return "".join(out_lines), changed, breaking, skipped

    @classmethod
    def _upgrade_pom_xml(
        cls, text: str, upgrades: Dict[Tuple[str, str], str], allow_major: bool = True
    ) -> Tuple[str, List[str], List[str], List[str]]:
        changed: List[str] = []
        breaking: List[str] = []
        skipped: List[str] = []
        dep_block_pat = re.compile(r"(<dependency\b[^>]*>.*?</dependency>)", re.S)

        def _repl_dep(m: re.Match[str]) -> str:
            block = m.group(1)
            g_m = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block)
            a_m = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block)
            v_m = re.search(r"(<version>\s*)([^<\s]+)(\s*</version>)", block)
            if not a_m or not v_m:
                return block
            gid = g_m.group(1).strip() if g_m else ""
            aid = a_m.group(1).strip()
            old_ver = v_m.group(2).strip()
            if old_ver.startswith("${"):
                return block
            coord = f"{gid}:{aid}".lower() if gid else aid.lower()
            fixed = upgrades.get(("maven", coord)) or upgrades.get(("maven", aid.lower()))
            if not fixed or old_ver == fixed:
                return block
            is_maj = cls._is_major_upgrade(old_ver, fixed, "maven")
            label = f"{gid}:{aid}" if gid else aid
            if is_maj and not allow_major:
                skipped.append(f"{label}: {old_ver} -> {fixed} [BREAKING MAJOR skipped]")
                return block
            changed.append(f"{label}: {old_ver} -> {fixed}")
            if is_maj:
                breaking.append(f"[BREAKING MAJOR] {label}: {old_ver} -> {fixed}")
            return block[: v_m.start()] + f"{v_m.group(1)}{fixed}{v_m.group(3)}" + block[v_m.end() :]

        updated = dep_block_pat.sub(_repl_dep, text)
        return updated, changed, breaking, skipped
