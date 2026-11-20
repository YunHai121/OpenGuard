"""Static import-level CVE Reachability Analyzer across Python, JS/TS, and Go."""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import DependencyComponent, FindingCategory, VulnerabilityFinding

# Map PyPI distribution names (lowercased) to top-level Python module names
PYPI_IMPORT_ALIASES: Dict[str, Set[str]] = {
    "pyyaml": {"yaml"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "beautifulsoup4": {"bs4"},
    "python-docx": {"docx"},
    "pymupdf": {"fitz"},
    "mysqlclient": {"mysqldb"},
    "pyqt5": {"pyqt5"},
    "pyqt6": {"pyqt6"},
    "pyside6": {"pyside6"},
    "pyjwt": {"jwt"},
    "opencv-python": {"cv2"},
    "opencv-python-headless": {"cv2"},
    "python-dotenv": {"dotenv"},
    "python-multipart": {"multipart", "python_multipart"},
    "python-jose": {"jose"},
    "pycryptodome": {"crypto"},
    "pypdf2": {"pypdf2"},
    "ruamel.yaml": {"ruamel"},
    "google-genai": {"google"},
    "llama-index": {"llama_index"},
}

JS_IMPORT_RE = re.compile(
    r"""(?:import\s+[^;]*?\s+from\s+|import\s+|require\s*\(\s*)["']([^"'\s]+)["']"""
)
GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')
GO_BLOCK_IMPORT_RE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')


class ReachabilityAnalyzer:
    """Determines whether declared/vulnerable dependencies are actually imported in source code."""

    SUPPORTED_ECOSYSTEMS = {"PyPI", "npm", "Go"}

    def collect_imports(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, List[str]]]:
        """Return `{ecosystem: {normalized_module: ["file:line", ...]}}` for Python, JS/TS, Go."""
        root = Path(root_path).resolve()
        if root.is_file():
            files = [root]
            base = root.parent
        else:
            files = []
            base = root
            excludes = exclude_patterns or []
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
                dirnames[:] = [
                    d for d in sorted(dirnames)
                    if d not in DEFAULT_EXCLUDE_DIRS
                    and not is_path_excluded(
                        f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", excludes
                    )
                ]
                for fname in sorted(filenames):
                    fpath = Path(dirpath) / fname
                    rel = fpath.relative_to(root).as_posix()
                    if is_path_excluded(rel, excludes):
                        continue
                    if fpath.suffix.lower() in (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go"):
                        files.append(fpath)

        imports: Dict[str, Dict[str, List[str]]] = {
            "PyPI": defaultdict(list),
            "npm": defaultdict(list),
            "Go": defaultdict(list),
        }

        for fpath in files:
            rel = fpath.resolve().relative_to(base).as_posix()
            ext = fpath.suffix.lower()
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if ext == ".py":
                self._extract_python_imports(content, rel, imports["PyPI"])
            elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                self._extract_js_imports(content, rel, imports["npm"])
            elif ext == ".go":
                self._extract_go_imports(content, rel, imports["Go"])

        return imports

    @staticmethod
    def _extract_python_imports(content: str, rel: str, bucket: Dict[str, List[str]]) -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0].lower()
                    loc = f"{rel}:{node.lineno}"
                    if loc not in bucket[top]:
                        bucket[top].append(loc)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".", 1)[0].lower()
                loc = f"{rel}:{node.lineno}"
                if loc not in bucket[top]:
                    bucket[top].append(loc)

    @staticmethod
    def _extract_js_imports(content: str, rel: str, bucket: Dict[str, List[str]]) -> None:
        for idx, line in enumerate(content.splitlines(), start=1):
            for m in JS_IMPORT_RE.finditer(line):
                spec = m.group(1)
                if spec.startswith((".", "/", "node:")):
                    continue
                if spec.startswith("@") and "/" in spec:
                    pkg = "/".join(spec.split("/")[:2]).lower()
                else:
                    pkg = spec.split("/", 1)[0].lower()
                loc = f"{rel}:{idx}"
                if loc not in bucket[pkg]:
                    bucket[pkg].append(loc)

    @staticmethod
    def _extract_go_imports(content: str, rel: str, bucket: Dict[str, List[str]]) -> None:
        in_block = False
        for idx, line in enumerate(content.splitlines(), start=1):
            s = line.strip()
            if s.startswith("import ("):
                in_block = True
                continue
            if in_block:
                if s == ")":
                    in_block = False
                    continue
                m = GO_BLOCK_IMPORT_RE.match(line)
                if m:
                    mod = m.group(1).lower()
                    loc = f"{rel}:{idx}"
                    if loc not in bucket[mod]:
                        bucket[mod].append(loc)
            else:
                m = GO_SINGLE_IMPORT_RE.match(line)
                if m:
                    mod = m.group(1).lower()
                    loc = f"{rel}:{idx}"
                    if loc not in bucket[mod]:
                        bucket[mod].append(loc)

    def _match_locations(
        self,
        ecosystem: str,
        pkg_name: str,
        imports_map: Dict[str, Dict[str, List[str]]],
    ) -> Optional[List[str]]:
        if ecosystem not in self.SUPPORTED_ECOSYSTEMS:
            return None
        eco_bucket = imports_map.get(ecosystem, {})
        low = pkg_name.lower()

        candidates: Set[str] = {low, low.replace("-", "_")}
        if ecosystem == "PyPI" and low in PYPI_IMPORT_ALIASES:
            candidates.update(PYPI_IMPORT_ALIASES[low])

        locs: List[str] = []
        if ecosystem == "Go":
            for mod_path, mod_locs in eco_bucket.items():
                if mod_path == low or mod_path.startswith(low + "/"):
                    for loc in mod_locs:
                        if loc not in locs:
                            locs.append(loc)
            return locs

        for cand in candidates:
            for loc in eco_bucket.get(cand, []):
                if loc not in locs:
                    locs.append(loc)
        return locs

    def enrich(
        self,
        root_path: Path,
        components: List[DependencyComponent],
        vulnerabilities: List[VulnerabilityFinding],
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Annotate SBOM components and CVEs with import-level reachability evidence."""
        imports_map = self.collect_imports(root_path, exclude_patterns=exclude_patterns)

        comp_usage: Dict[tuple[str, str], List[str]] = {}
        for comp in components:
            locs = self._match_locations(comp.ecosystem, comp.name, imports_map)
            if locs:
                comp.used_in_code = True
                comp.import_locations = locs[:15]
                comp_usage[(comp.ecosystem.lower(), comp.name.lower())] = locs[:15]

        for vuln in vulnerabilities:
            if vuln.source == "install_script":
                vuln.reachable = True
                continue
            if vuln.ecosystem not in self.SUPPORTED_ECOSYSTEMS:
                vuln.reachable = None
                continue
            locs = comp_usage.get((vuln.ecosystem.lower(), vuln.component_name.lower()))
            if locs is None:
                locs = self._match_locations(vuln.ecosystem, vuln.component_name, imports_map) or []
            vuln.reachable = len(locs) > 0
            vuln.import_locations = locs[:15]
