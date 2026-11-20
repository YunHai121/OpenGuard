"""Multi-ecosystem dependency manifest parser and NetworkX DAG builder (7 ecosystems)."""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import DependencyComponent

REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]+\])?\s*(?:(===|==|~=|>=|<=|>|<|!=)\s*([^\s;,#]+))?"
)
GO_REQ_RE = re.compile(r"^\s*([^\s/]+(?:/[^\s]+)+)\s+v?([^\s]+)")
GRADLE_DEP_RE = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\(\s][\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']"
)
CMAKE_PKG_RE = re.compile(r"(?i)find_package\s*\(\s*([A-Za-z0-9_+\-]+)")


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    clean_ver = version if version and version != "unspecified" else ""
    eco_map = {
        "PyPI": "pypi",
        "npm": "npm",
        "Go": "golang",
        "Maven": "maven",
        "crates.io": "cargo",
        "C/C++": "generic",
        "Packagist": "composer",
    }
    ns = eco_map.get(ecosystem, ecosystem.lower())
    return f"pkg:{ns}/{name}@{clean_ver}" if clean_ver else f"pkg:{ns}/{name}"


class DependencyParser:
    """Zero-build static dependency extractor across 7 language ecosystems."""

    def parse_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> Tuple[List[DependencyComponent], List[Tuple[str, str]], nx.DiGraph]:
        """Parse all supported dependency manifests and build a NetworkX directed dependency graph."""
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent
        excludes = exclude_patterns or []

        components_map: Dict[Tuple[str, str], DependencyComponent] = {}
        edges: List[Tuple[str, str]] = []
        graph = nx.DiGraph()
        project_node = root.name
        graph.add_node(project_node, ecosystem="project", direct=True)

        def upsert_component(comp: DependencyComponent) -> DependencyComponent:
            key = (comp.ecosystem.lower(), comp.name.lower())
            if key in components_map:
                existing = components_map[key]
                if existing.version == "unspecified" and comp.version != "unspecified":
                    existing.version = comp.version
                    existing.purl = _make_purl(existing.ecosystem, existing.name, existing.version)
                if comp.direct:
                    existing.direct = True
                if existing.license_id == "UNKNOWN" and comp.license_id != "UNKNOWN":
                    existing.license_id = comp.license_id
                    existing.license_source = comp.license_source
                for dep in comp.dependencies:
                    if dep not in existing.dependencies:
                        existing.dependencies.append(dep)
                return existing
            if not comp.purl:
                comp.purl = _make_purl(comp.ecosystem, comp.name, comp.version)
            components_map[key] = comp
            graph.add_node(comp.name, ecosystem=comp.ecosystem, version=comp.version, direct=comp.direct)
            return comp

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in sorted(dirnames) if d not in DEFAULT_EXCLUDE_DIRS]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root).as_posix()
                if is_path_excluded(rel, excludes):
                    continue

                lower_name = fname.lower()
                if lower_name.startswith("requirements") and lower_name.endswith(".txt"):
                    self._parse_requirements_txt(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "pyproject.toml":
                    self._parse_pyproject_toml(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "package.json":
                    self._parse_package_json(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "package-lock.json":
                    self._parse_package_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "go.mod":
                    self._parse_go_mod(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "pom.xml":
                    self._parse_pom_xml(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name in ("build.gradle", "build.gradle.kts"):
                    self._parse_gradle(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "cargo.toml":
                    self._parse_cargo_toml(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "cargo.lock":
                    self._parse_cargo_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "vcpkg.json":
                    self._parse_vcpkg_json(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "cmakelists.txt":
                    self._parse_cmake(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "composer.json":
                    self._parse_composer_json(fpath, rel, upsert_component, project_node, edges, graph)

        # Deduplicate edges cleanly
        unique_edges: List[Tuple[str, str]] = []
        seen_edges = set()
        for src, dst in edges:
            if (src, dst) not in seen_edges:
                seen_edges.add((src, dst))
                unique_edges.append((src, dst))
                graph.add_edge(src, dst)

        components = sorted(components_map.values(), key=lambda c: (not c.direct, c.ecosystem, c.name.lower()))
        return components, unique_edges, graph

    def _parse_requirements_txt(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        with fpath.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(("-r", "--", "-e", "git+", "http")):
                    continue
                m = REQ_LINE_RE.match(line)
                if not m:
                    continue
                pkg = m.group(1)
                ver = (m.group(3) or "unspecified").strip()
                comp = upsert(
                    DependencyComponent(
                        name=pkg,
                        version=ver,
                        ecosystem="PyPI",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_pyproject_toml(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            with fpath.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return

        deps: List[str] = []
        project_sec = data.get("project", {})
        if isinstance(project_sec, dict):
            deps.extend(project_sec.get("dependencies", []) or [])
            opt = project_sec.get("optional-dependencies", {}) or {}
            if isinstance(opt, dict):
                for group_deps in opt.values():
                    if isinstance(group_deps, list):
                        deps.extend(group_deps)

        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                ver = spec if isinstance(spec, str) else (spec.get("version", "") if isinstance(spec, dict) else "")
                ver_clean = ver.lstrip("^~>=<! ") or "unspecified"
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver_clean,
                        ecosystem="PyPI",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

        for dep_str in deps:
            if not isinstance(dep_str, str):
                continue
            m = REQ_LINE_RE.match(dep_str)
            if not m:
                continue
            pkg = m.group(1)
            ver = (m.group(3) or "unspecified").strip()
            comp = upsert(
                DependencyComponent(
                    name=pkg,
                    version=ver,
                    ecosystem="PyPI",
                    source_file=rel,
                    direct=True,
                )
            )
            edges.append((proj, comp.name))

    def _parse_package_json(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, ver_spec in block.items():
                ver = str(ver_spec).lstrip("^~>=<v ") or "unspecified"
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="npm",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_package_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if not pkg_path or not isinstance(info, dict):
                    continue
                name = pkg_path.split("node_modules/")[-1]
                ver = str(info.get("version", "unspecified"))
                lic = str(info.get("license", "UNKNOWN"))
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="npm",
                        source_file=rel,
                        direct="node_modules/" not in pkg_path.replace("node_modules/", "", 1),
                        license_id=lic if lic and lic != "UNKNOWN" else "UNKNOWN",
                        license_source="package-lock.json" if lic and lic != "UNKNOWN" else "unknown",
                    )
                )
                sub_deps = info.get("dependencies", {})
                if isinstance(sub_deps, dict):
                    for child in sub_deps.keys():
                        edges.append((comp.name, child))
                        if child not in comp.dependencies:
                            comp.dependencies.append(child)
            return

        deps = data.get("dependencies")
        if isinstance(deps, dict):
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                ver = str(info.get("version", "unspecified"))
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="npm",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))
                reqs = info.get("requires", {})
                if isinstance(reqs, dict):
                    for child in reqs.keys():
                        edges.append((comp.name, child))

    def _parse_go_mod(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        in_require = False
        for raw in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if line.startswith("require "):
                line = line[len("require "):].strip()
            elif not in_require:
                continue
            if "// indirect" in raw:
                direct = False
                line = line.split("//")[0].strip()
            else:
                direct = True
            m = GO_REQ_RE.match(line)
            if m:
                mod_name, ver = m.group(1), m.group(2)
                comp = upsert(
                    DependencyComponent(
                        name=mod_name,
                        version=ver,
                        ecosystem="Go",
                        source_file=rel,
                        direct=direct,
                    )
                )
                if direct:
                    edges.append((proj, comp.name))

    def _parse_pom_xml(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            tree = ET.parse(fpath)
            root_el = tree.getroot()
        except Exception:
            return
        ns_prefix = ""
        if root_el.tag.startswith("{"):
            ns_prefix = root_el.tag.split("}", 1)[0] + "}"
        for dep in root_el.findall(f".//{ns_prefix}dependency"):
            gid = dep.findtext(f"{ns_prefix}groupId") or ""
            aid = dep.findtext(f"{ns_prefix}artifactId") or ""
            ver = dep.findtext(f"{ns_prefix}version") or "unspecified"
            if gid and aid:
                full_name = f"{gid}:{aid}"
                comp = upsert(
                    DependencyComponent(
                        name=full_name,
                        version=ver.strip(),
                        ecosystem="Maven",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_gradle(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        text = fpath.read_text(encoding="utf-8", errors="replace")
        for m in GRADLE_DEP_RE.finditer(text):
            full_name = f"{m.group(1)}:{m.group(2)}"
            comp = upsert(
                DependencyComponent(
                    name=full_name,
                    version=m.group(3),
                    ecosystem="Maven",
                    source_file=rel,
                    direct=True,
                )
            )
            edges.append((proj, comp.name))

    def _parse_cargo_toml(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            with fpath.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return
        for sec in ("dependencies", "dev-dependencies"):
            block = data.get(sec)
            if not isinstance(block, dict):
                continue
            for name, spec in block.items():
                ver = spec if isinstance(spec, str) else (spec.get("version", "unspecified") if isinstance(spec, dict) else "unspecified")
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=str(ver).lstrip("^~>=< "),
                        ecosystem="crates.io",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_cargo_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            with fpath.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return
        for pkg in data.get("package", []) or []:
            if not isinstance(pkg, dict) or "name" not in pkg:
                continue
            name = str(pkg["name"])
            ver = str(pkg.get("version", "unspecified"))
            comp = upsert(
                DependencyComponent(
                    name=name,
                    version=ver,
                    ecosystem="crates.io",
                    source_file=rel,
                    direct=False,
                )
            )
            for child in pkg.get("dependencies", []) or []:
                child_name = str(child).split(" ", 1)[0]
                edges.append((comp.name, child_name))

    def _parse_vcpkg_json(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        for item in data.get("dependencies", []) or []:
            name = item if isinstance(item, str) else (item.get("name", "") if isinstance(item, dict) else "")
            if name:
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version="unspecified",
                        ecosystem="C/C++",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_cmake(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        text = fpath.read_text(encoding="utf-8", errors="replace")
        for m in CMAKE_PKG_RE.finditer(text):
            pkg = m.group(1)
            comp = upsert(
                DependencyComponent(
                    name=pkg,
                    version="unspecified",
                    ecosystem="C/C++",
                    source_file=rel,
                    direct=True,
                )
            )
            edges.append((proj, comp.name))

    def _parse_composer_json(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        for sec in ("require", "require-dev"):
            block = data.get(sec)
            if not isinstance(block, dict):
                continue
            for name, ver in block.items():
                if name == "php" or name.startswith("ext-"):
                    continue
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=str(ver).lstrip("^~>=< "),
                        ecosystem="Packagist",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))
