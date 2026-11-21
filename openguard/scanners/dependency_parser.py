"""Multi-ecosystem dependency manifest & lockfile parser and NetworkX DAG builder (10 ecosystems)."""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx
import yaml

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
        "RubyGems": "gem",
        "NuGet": "nuget",
        "GitHub Actions": "githubactions",
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
                elif lower_name in ("uv.lock", "poetry.lock"):
                    self._parse_python_toml_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "package.json":
                    self._parse_package_json(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "package-lock.json":
                    self._parse_package_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "yarn.lock":
                    self._parse_yarn_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "pnpm-lock.yaml":
                    self._parse_pnpm_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "go.mod":
                    self._parse_go_mod(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "go.sum":
                    self._parse_go_sum(fpath, rel, upsert_component, project_node, edges, graph)
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
                elif lower_name == "composer.lock":
                    self._parse_composer_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name == "gemfile.lock":
                    self._parse_gemfile_lock(fpath, rel, upsert_component, project_node, edges, graph)
                elif lower_name.endswith(".csproj"):
                    self._parse_csproj(fpath, rel, upsert_component, project_node, edges, graph)
                elif (
                    ".github/workflows/" in f"/{rel.lower()}"
                    and lower_name.endswith((".yml", ".yaml"))
                ):
                    self._parse_github_workflow_actions(fpath, rel, upsert_component, project_node, edges, graph)

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

    def _parse_python_toml_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse `uv.lock` and `poetry.lock` TOML lockfiles with exact transitive dependencies."""
        try:
            with fpath.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return
        for pkg in data.get("package", []) or []:
            if not isinstance(pkg, dict) or "name" not in pkg:
                continue
            name = str(pkg["name"]).strip()
            ver = str(pkg.get("version", "unspecified")).strip()
            if not name:
                continue
            comp = upsert(
                DependencyComponent(
                    name=name,
                    version=ver,
                    ecosystem="PyPI",
                    source_file=rel,
                    direct=False,
                )
            )
            # uv.lock: dependencies = [{name = "..."}] ; poetry.lock: dependencies = {pkg = "^1.0"}
            deps = pkg.get("dependencies")
            if isinstance(deps, list):
                for item in deps:
                    child = item.get("name") if isinstance(item, dict) else (str(item) if isinstance(item, str) else "")
                    if child:
                        edges.append((comp.name, str(child)))
            elif isinstance(deps, dict):
                for child in deps.keys():
                    if str(child).lower() != "python":
                        edges.append((comp.name, str(child)))

    def _parse_yarn_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse yarn.lock (v1 Classic & v2+ Berry) resolved npm package versions."""
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        current_names: List[str] = []
        header_pkg_re = re.compile(r'["\']?(@?[^@\s,"\']+)@')
        ver_re = re.compile(r'^\s+version(?:\s+|:\s*)["\']?([^"\'\s]+)["\']?')
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
                current_names = []
                for part in line.rstrip(":").split(","):
                    m = header_pkg_re.search(part.strip())
                    if m and m.group(1) not in current_names:
                        current_names.append(m.group(1))
            elif current_names:
                mv = ver_re.match(line)
                if mv:
                    ver = mv.group(1)
                    for name in current_names:
                        upsert(
                            DependencyComponent(
                                name=name,
                                version=ver,
                                ecosystem="npm",
                                source_file=rel,
                                direct=False,
                            )
                        )
                    current_names = []

    def _parse_pnpm_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse pnpm-lock.yaml (v6 & v9 formats) resolved npm package graph."""
        try:
            data = yaml.safe_load(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return
        for raw_key, info in packages.items():
            key_str = str(raw_key).lstrip("/")
            # Strip peer-dep suffixes like "(react@18.0.0)" or "_react@18.0.0"
            clean_key = key_str.split("(", 1)[0].split("_", 1)[0]
            if "@" not in clean_key:
                continue
            # Scoped package `@scope/pkg@1.2.3` vs unscoped `pkg@1.2.3`
            idx = clean_key.rfind("@")
            if idx <= 0:
                continue
            name = clean_key[:idx]
            ver = clean_key[idx + 1 :]
            if not name or not ver:
                continue
            comp = upsert(
                DependencyComponent(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    source_file=rel,
                    direct=False,
                )
            )
            if isinstance(info, dict):
                sub_deps = info.get("dependencies")
                if isinstance(sub_deps, dict):
                    for child in sub_deps.keys():
                        edges.append((comp.name, str(child)))

    def _parse_go_sum(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse Go `go.sum` lockfile for exact transitive module versions."""
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for raw in lines:
            parts = raw.strip().split()
            if len(parts) < 2:
                continue
            mod_name, raw_ver = parts[0], parts[1]
            ver = raw_ver.removesuffix("/go.mod").lstrip("v")
            if not mod_name or not ver:
                continue
            upsert(
                DependencyComponent(
                    name=mod_name,
                    version=ver,
                    ecosystem="Go",
                    source_file=rel,
                    direct=False,
                )
            )

    def _parse_gemfile_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse Ruby Bundler `Gemfile.lock` GEM specs & transitive dependency edges."""
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        in_specs = False
        current_gem: Optional[str] = None
        spec_re = re.compile(r"^    ([A-Za-z0-9._\-]+)\s+\(([^)]+)\)\s*$")
        dep_re = re.compile(r"^      ([A-Za-z0-9._\-]+)")
        for line in lines:
            if line.strip() == "specs:":
                in_specs = True
                current_gem = None
                continue
            if in_specs and line and not line.startswith(" "):
                in_specs = False
                current_gem = None
                continue
            if not in_specs:
                continue
            ms = spec_re.match(line)
            if ms:
                name, ver = ms.group(1), ms.group(2)
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="RubyGems",
                        source_file=rel,
                        direct=False,
                    )
                )
                current_gem = comp.name
                continue
            if current_gem:
                md = dep_re.match(line)
                if md:
                    edges.append((current_gem, md.group(1)))

    def _parse_composer_lock(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse PHP Composer `composer.lock` with exact versions, SPDX licenses, and edges."""
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        for sec in ("packages", "packages-dev"):
            for pkg in data.get(sec, []) or []:
                if not isinstance(pkg, dict) or "name" not in pkg:
                    continue
                name = str(pkg["name"])
                ver = str(pkg.get("version", "unspecified")).lstrip("v")
                lics = pkg.get("license") or []
                lic_id = str(lics[0]) if (isinstance(lics, list) and lics) else "UNKNOWN"
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="Packagist",
                        source_file=rel,
                        direct=False,
                        license_id=lic_id,
                        license_source="composer.lock" if lic_id != "UNKNOWN" else "unknown",
                    )
                )
                req = pkg.get("require")
                if isinstance(req, dict):
                    for child in req.keys():
                        if child != "php" and not str(child).startswith("ext-"):
                            edges.append((comp.name, str(child)))

    def _parse_csproj(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Parse .NET `*.csproj` NuGet `<PackageReference>` XML entries."""
        try:
            tree = ET.parse(fpath)
            root_el = tree.getroot()
        except Exception:
            return
        for elem in root_el.iter():
            tag_name = elem.tag.split("}", 1)[-1]
            if tag_name != "PackageReference":
                continue
            name = (elem.attrib.get("Include") or elem.attrib.get("Update") or "").strip()
            ver = (elem.attrib.get("Version") or elem.findtext("Version") or "unspecified").strip()
            if name:
                comp = upsert(
                    DependencyComponent(
                        name=name,
                        version=ver,
                        ecosystem="NuGet",
                        source_file=rel,
                        direct=True,
                    )
                )
                edges.append((proj, comp.name))

    def _parse_github_workflow_actions(self, fpath: Path, rel: str, upsert, proj: str, edges, graph) -> None:
        """Index third-party GitHub Actions (`uses: owner/repo@ref`) as `pkg:githubactions` SBOM components."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        uses_re = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"#\s]+)['\"]?")
        for raw in content.splitlines():
            m = uses_re.match(raw)
            if not m:
                continue
            ref_str = m.group(1)
            if ref_str.startswith("./") or ref_str.startswith("docker://") or "@" not in ref_str:
                continue
            action_name, ref_ver = ref_str.rsplit("@", 1)
            if not action_name or not ref_ver:
                continue
            comp = upsert(
                DependencyComponent(
                    name=action_name,
                    version=ref_ver,
                    ecosystem="GitHub Actions",
                    source_file=rel,
                    direct=True,
                )
            )
            edges.append((proj, comp.name))
