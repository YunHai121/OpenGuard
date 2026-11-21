"""Static Import- & Call-Graph Symbol-Level CVE Reachability Analyzer across Python, JS/TS, and Go."""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import DependencyComponent, VulnerabilityFinding

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

# Vulnerable symbol map: CVE_ID -> set of lowercased vulnerable method/function call patterns
VULNERABLE_CVE_SYMBOLS: Dict[str, Set[str]] = {
    "CVE-2020-14343": {"yaml.load", "yaml.unsafe_load", "yaml.fullloader", "load"},
    "CVE-2023-50447": {"imagemath.eval", "pil.imagemath.eval", "eval"},
    "CVE-2021-23337": {"lodash.template", "_.template", "template"},
    "CVE-2024-22195": {"xmlattr"},
    "CVE-2024-23334": {"add_static", "follow_symlinks"},
    "CVE-2019-7164": {"order_by", "group_by"},
    "CVE-2022-29217": {"jwt.decode", "decode"},
    "CVE-2024-34069": {"debuggedapplication", "run_simple"},
    "CVE-2023-32681": {"requests.get", "requests.post", "requests.request", "requests.put", "requests.session", "get", "post", "request"},
    "CVE-2021-33503": {"poolmanager", "httpconnectionpool", "request", "parse_url"},
    "CVE-2023-45803": {"poolmanager", "httpconnectionpool", "request"},
    "CVE-2023-30861": {"flask", "session"},
    "CVE-2024-27351": {"truncator", "truncatechars_html", "truncatewords_html"},
    "CVE-2023-45857": {"axios.get", "axios.post", "axios.request", "axios.create"},
    "CVE-2024-29041": {"res.location", "res.redirect"},
}

JS_IMPORT_RE = re.compile(
    r"""(?:import\s+[^;]*?\s+from\s+|import\s+|require\s*\(\s*)["']([^"'\s]+)["']"""
)
JS_CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(")
GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')
GO_BLOCK_IMPORT_RE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')


class ReachabilityAnalyzer:
    """Determines both import-level and call-graph symbol-level reachability of CVEs."""

    SUPPORTED_ECOSYSTEMS = {"PyPI", "npm", "Go"}

    def collect_imports(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, List[str]]]:
        """Return `{ecosystem: {normalized_module: ["file:line", ...]}}` for Python, JS/TS, Go."""
        imports, _ = self.collect_imports_and_calls(root_path, exclude_patterns=exclude_patterns)
        return imports

    def collect_imports_and_calls(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, Dict[str, List[str]]], Dict[str, Dict[str, List[str]]]]:
        """Collect imports and resolved call-site symbols per ecosystem."""
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
                    d
                    for d in sorted(dirnames)
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
        calls: Dict[str, Dict[str, List[str]]] = {
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
                self._extract_python_imports_and_calls(content, rel, imports["PyPI"], calls["PyPI"])
            elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                self._extract_js_imports_and_calls(content, rel, imports["npm"], calls["npm"])
            elif ext == ".go":
                self._extract_go_imports(content, rel, imports["Go"])

        return imports, calls

    @staticmethod
    def _extract_python_imports_and_calls(
        content: str,
        rel: str,
        import_bucket: Dict[str, List[str]],
        call_bucket: Dict[str, List[str]],
    ) -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        # Track local alias -> canonical module/symbol path (e.g., `import yaml as y` -> y: yaml)
        alias_map: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0].lower()
                    loc = f"{rel}:{node.lineno}"
                    if loc not in import_bucket[top]:
                        import_bucket[top].append(loc)
                    local_name = (alias.asname or alias.name.split(".", 1)[0]).lower()
                    alias_map[local_name] = alias.name.lower()
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".", 1)[0].lower()
                loc = f"{rel}:{node.lineno}"
                if loc not in import_bucket[top]:
                    import_bucket[top].append(loc)
                for alias in node.names:
                    local_name = (alias.asname or alias.name).lower()
                    alias_map[local_name] = f"{node.module.lower()}.{alias.name.lower()}"

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            raw_call = ReachabilityAnalyzer._resolve_ast_call_name(node.func)
            if not raw_call:
                continue
            low_call = raw_call.lower()
            parts = low_call.split(".")
            if parts[0] in alias_map:
                canonical = alias_map[parts[0]] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
            else:
                canonical = low_call

            # Special-case PyYAML `yaml.load(..., Loader=yaml.SafeLoader)` -> NOT vulnerable to CVE-2020-14343
            if canonical.endswith("yaml.load") or canonical == "yaml.load":
                has_safe_loader = any(
                    kw.arg == "Loader"
                    and ("safeloader" in ast.dump(kw.value).lower() or "csafeloader" in ast.dump(kw.value).lower())
                    for kw in node.keywords
                )
                if has_safe_loader:
                    continue

            loc = f"{rel}:{node.lineno}"
            for sym in (canonical, parts[-1]):
                if loc not in call_bucket[sym]:
                    call_bucket[sym].append(loc)

            # Track keyword flags like `follow_symlinks=True`
            for kw in node.keywords:
                if kw.arg and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    kw_sym = kw.arg.lower()
                    if loc not in call_bucket[kw_sym]:
                        call_bucket[kw_sym].append(loc)

    @staticmethod
    def _resolve_ast_call_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts = [func_node.attr]
            cur = func_node.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _extract_js_imports_and_calls(
        content: str,
        rel: str,
        import_bucket: Dict[str, List[str]],
        call_bucket: Dict[str, List[str]],
    ) -> None:
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
                if loc not in import_bucket[pkg]:
                    import_bucket[pkg].append(loc)
            for cm in JS_CALL_RE.finditer(line):
                sym = cm.group(1).lower()
                loc = f"{rel}:{idx}"
                if loc not in call_bucket[sym]:
                    call_bucket[sym].append(loc)
                tail = sym.rsplit(".", 1)[-1]
                if loc not in call_bucket[tail]:
                    call_bucket[tail].append(loc)

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

    @staticmethod
    def _match_call_locations(
        cve_id: str,
        ecosystem: str,
        calls_map: Dict[str, Dict[str, List[str]]],
    ) -> Optional[List[str]]:
        target_syms = VULNERABLE_CVE_SYMBOLS.get(cve_id)
        if not target_syms:
            return None
        eco_calls = calls_map.get(ecosystem, {})
        hits: List[str] = []
        for sym in target_syms:
            for loc in eco_calls.get(sym, []):
                if loc not in hits:
                    hits.append(loc)
        return hits

    def enrich(
        self,
        root_path: Path,
        components: List[DependencyComponent],
        vulnerabilities: List[VulnerabilityFinding],
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Annotate SBOM components and CVEs with import-level & call-graph reachability evidence."""
        imports_map, calls_map = self.collect_imports_and_calls(root_path, exclude_patterns=exclude_patterns)

        comp_usage: Dict[tuple[str, str], List[str]] = {}
        comp_source: Dict[tuple[str, str], str] = {}
        for comp in components:
            key = (comp.ecosystem.lower(), comp.name.lower())
            if comp.source_file:
                comp_source[key] = comp.source_file
            locs = self._match_locations(comp.ecosystem, comp.name, imports_map)
            if locs:
                comp.used_in_code = True
                comp.import_locations = locs[:15]
                comp_usage[key] = locs[:15]

        for vuln in vulnerabilities:
            key = (vuln.ecosystem.lower(), vuln.component_name.lower())
            if not vuln.source_file and key in comp_source:
                vuln.source_file = comp_source[key]

            if vuln.source == "install_script":
                vuln.reachable = True
                vuln.reachability_level = "call_reachable"
                continue
            if vuln.ecosystem not in self.SUPPORTED_ECOSYSTEMS:
                vuln.reachable = None
                vuln.reachability_level = "unknown"
                continue
            locs = comp_usage.get(key)
            if locs is None:
                locs = self._match_locations(vuln.ecosystem, vuln.component_name, imports_map) or []

            vuln.import_locations = locs[:15]
            if not locs:
                vuln.reachable = False
                vuln.reachability_level = "unreachable"
                vuln.call_locations = []
                continue

            vuln.reachable = True
            call_hits = self._match_call_locations(vuln.id, vuln.ecosystem, calls_map)
            if call_hits is None:
                # CVE has no fine-grained symbol signature -> conservatively mark import_only
                vuln.reachability_level = "import_only"
                vuln.call_locations = []
            elif call_hits:
                vuln.reachability_level = "call_reachable"
                vuln.call_locations = call_hits[:15]
            else:
                vuln.reachability_level = "import_only"
                vuln.call_locations = []
