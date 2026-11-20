"""SPDX License detection, curated package license registry, and viral copyleft conflict analyzer."""

from __future__ import annotations

import importlib.metadata
import json
import re
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx

from openguard.models import (
    DependencyComponent,
    LicenseCompatibility,
    LicenseConflict,
    Severity,
)

# Permissive licenses that cannot absorb strong copyleft obligations
PERMISSIVE_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD",
    "ISC",
    "MulanPSL-2.0",
    "MulanPSL-1.0",
    "Unlicense",
    "CC0-1.0",
    "Python-2.0",
    "PSF-2.0",
    "Zlib",
    "0BSD",
}

WEAK_COPYLEFT_LICENSES = {
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-2.0",
    "EPL-1.0",
    "CDDL-1.0",
}

STRONG_COPYLEFT_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "SSPL-1.0",
}

# Curated knowledge base of 150+ widely used packages across PyPI, npm, Go, Maven, Crates
BUILTIN_PACKAGE_LICENSES: Dict[str, str] = {
    # PyPI
    "fastapi": "MIT",
    "uvicorn": "BSD-3-Clause",
    "pydantic": "MIT",
    "pydantic-core": "MIT",
    "starlette": "BSD-3-Clause",
    "typer": "MIT",
    "rich": "MIT",
    "click": "BSD-3-Clause",
    "networkx": "BSD-3-Clause",
    "httpx": "BSD-3-Clause",
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "packaging": "Apache-2.0",
    "pyyaml": "MIT",
    "jinja2": "BSD-3-Clause",
    "reportlab": "BSD-3-Clause",
    "python-docx": "MIT",
    "django": "BSD-3-Clause",
    "flask": "BSD-3-Clause",
    "werkzeug": "BSD-3-Clause",
    "sqlalchemy": "MIT",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "scikit-learn": "BSD-3-Clause",
    "torch": "BSD-3-Clause",
    "transformers": "Apache-2.0",
    "openai": "Apache-2.0",
    "anthropic": "MIT",
    "aiohttp": "Apache-2.0",
    "cryptography": "Apache-2.0",
    "pillow": "HPND",
    "celery": "BSD-3-Clause",
    "redis": "MIT",
    "pymongo": "Apache-2.0",
    "pytest": "MIT",
    "loguru": "MIT",
    "streamlit": "Apache-2.0",
    "lxml": "BSD-3-Clause",
    "beautifulsoup4": "MIT",
    "selenium": "Apache-2.0",
    "playwright": "Apache-2.0",
    "opencv-python": "Apache-2.0",
    "ultralytics": "AGPL-3.0",
    "pyqt5": "GPL-3.0",
    "pyqt6": "GPL-3.0",
    "pyside6": "LGPL-3.0",
    "mysqlclient": "GPL-2.0",
    "gpl-example-lib": "GPL-3.0",
    "pypdf": "BSD-3-Clause",
    "pymupdf": "AGPL-3.0",
    "chardet": "LGPL-2.1",
    "psycopg2": "LGPL-3.0",
    "psycopg2-binary": "LGPL-3.0",
    "pynput": "LGPL-3.0",
    "unrar": "GPL-3.0",
    "ffmpeg-python": "Apache-2.0",
    "tqdm": "MPL-2.0",
    "certifi": "MPL-2.0",
    "pytz": "MIT",
    "six": "MIT",
    "tenacity": "Apache-2.0",
    "python-dotenv": "BSD-3-Clause",
    "python-jose": "MIT",
    "passlib": "BSD-3-Clause",
    "bcrypt": "Apache-2.0",
    "paramiko": "LGPL-2.1",
    "scapy": "GPL-2.0",
    "frida": "wxWindows",
    "grpcio": "Apache-2.0",
    "protobuf": "BSD-3-Clause",
    "pycryptodome": "BSD-2-Clause",
    # npm
    "express": "MIT",
    "react": "MIT",
    "react-dom": "MIT",
    "vue": "MIT",
    "next": "MIT",
    "vite": "MIT",
    "axios": "MIT",
    "lodash": "MIT",
    "moment": "MIT",
    "dayjs": "MIT",
    "typescript": "Apache-2.0",
    "eslint": "MIT",
    "prettier": "MIT",
    "tailwindcss": "MIT",
    "jsonwebtoken": "MIT",
    "minimist": "MIT",
    "chalk": "MIT",
    "commander": "MIT",
    "debug": "MIT",
    "ws": "MIT",
    "cors": "MIT",
    "dotenv": "BSD-2-Clause",
    "mongoose": "MIT",
    "sequelize": "MIT",
    "prisma": "Apache-2.0",
    "echarts": "Apache-2.0",
    "d3": "ISC",
    "mermaid": "MIT",
    "three": "MIT",
    "node-forge": "BSD-3-Clause",
    "cheerio": "MIT",
    "puppeteer": "Apache-2.0",
    "sharp": "Apache-2.0",
    "ffmpeg.wasm": "MIT",
    "gpl-js-codec": "GPL-3.0",
    "extjs": "GPL-3.0",
    "fullcalendar-scheduler": "GPL-3.0",
    "mysql": "MIT",
    "sqlite3": "BSD-3-Clause",
    "koa": "MIT",
    "fastify": "MIT",
    "zod": "MIT",
    "lucide-react": "ISC",
    # Go
    "github.com/gin-gonic/gin": "MIT",
    "github.com/spf13/cobra": "Apache-2.0",
    "github.com/stretchr/testify": "MIT",
    "github.com/sirupsen/logrus": "MIT",
    "go.uber.org/zap": "MIT",
    "golang.org/x/net": "BSD-3-Clause",
    "golang.org/x/crypto": "BSD-3-Clause",
    "gorm.io/gorm": "MIT",
    "github.com/gorilla/websocket": "BSD-2-Clause",
    "github.com/prometheus/client_golang": "Apache-2.0",
    # Maven
    "org.apache.logging.log4j:log4j-core": "Apache-2.0",
    "org.springframework:spring-core": "Apache-2.0",
    "org.springframework.boot:spring-boot-starter-web": "Apache-2.0",
    "com.fasterxml.jackson.core:jackson-databind": "Apache-2.0",
    "com.google.guava:guava": "Apache-2.0",
    "com.mysql:mysql-connector-j": "GPL-2.0",
    "mysql:mysql-connector-java": "GPL-2.0",
    "com.itextpdf:itextpdf": "AGPL-3.0",
    "junit:junit": "EPL-1.0",
    "org.slf4j:slf4j-api": "MIT",
    # Rust Crates
    "serde": "MIT",
    "serde_json": "MIT",
    "tokio": "MIT",
    "reqwest": "MIT",
    "axum": "MIT",
    "clap": "MIT",
    "rand": "MIT",
    "regex": "MIT",
    "openssl": "Apache-2.0",
    # C/C++
    "openssl_cpp": "Apache-2.0",
    "zlib": "Zlib",
    "boost": "BSL-1.0",
    "eigen": "MPL-2.0",
    "qt": "LGPL-3.0",
    "ffmpeg": "LGPL-2.1",
    "gsl": "GPL-3.0",
}

LICENSE_TEXT_SIGNATURES: List[Tuple[str, List[List[str]]]] = [
    ("MulanPSL-2.0", [["mulan permissive software license, version 2"], ["木兰宽松许可证", "第2版"], ["mulanpsl v2"]]),
    ("MulanPSL-1.0", [["mulan permissive software license, version 1"], ["mulanpsl v1"]]),
    ("AGPL-3.0", [["gnu affero general public license", "version 3"]]),
    ("GPL-3.0", [["gnu general public license", "version 3"]]),
    ("GPL-2.0", [["gnu general public license", "version 2"]]),
    ("LGPL-3.0", [["gnu lesser general public license", "version 3"]]),
    ("LGPL-2.1", [["gnu lesser general public license", "version 2.1"]]),
    ("Apache-2.0", [["apache license", "version 2.0"]]),
    ("MPL-2.0", [["mozilla public license version 2.0"]]),
    ("BSD-3-Clause", [["redistribution and use in source and binary forms", "neither the name of"]]),
    ("BSD-2-Clause", [["redistribution and use in source and binary forms", "redistributions of source code"]]),
    ("ISC", [["isc license", "permission to use, copy, modify, and/or distribute this software"]]),
    ("MIT", [["mit license", "permission is hereby granted, free of charge"]]),
    ("Unlicense", [["this is free and unencumbered software released into the public domain"]]),
    ("CC0-1.0", [["cc0 1.0 universal"]]),
]


def normalize_spdx_id(raw: str) -> str:
    """Normalize verbose license strings from metadata into clean SPDX identifiers."""
    if not raw:
        return "UNKNOWN"
    s = raw.strip()
    upper = s.upper()
    if upper in ("UNKNOWN", "NONE", "UNSPECIFIED", ""):
        return "UNKNOWN"
    if " OR " in upper:
        parts = [normalize_spdx_id(p) for p in re.split(r"\s+OR\s+", s, flags=re.I)]
        return " OR ".join(parts)
    if " AND " in upper:
        parts = [normalize_spdx_id(p) for p in re.split(r"\s+AND\s+", s, flags=re.I)]
        return " AND ".join(parts)
    if "MULAN" in upper and "2" in upper:
        return "MulanPSL-2.0"
    if "AGPL" in upper or "AFFERO GENERAL PUBLIC LICENSE" in upper:
        return "AGPL-3.0"
    if ("LGPL" in upper or "LESSER GENERAL PUBLIC LICENSE" in upper) and "3" in upper:
        return "LGPL-3.0"
    if ("LGPL" in upper or "LESSER GENERAL PUBLIC LICENSE" in upper) and "2" in upper:
        return "LGPL-2.1"
    if ("GPL" in upper or "GENERAL PUBLIC LICENSE" in upper) and "3" in upper:
        return "GPL-3.0"
    if ("GPL" in upper or "GENERAL PUBLIC LICENSE" in upper) and "2" in upper:
        return "GPL-2.0"
    if "APACHE" in upper:
        return "Apache-2.0"
    if "BSD-3" in upper or "3-CLAUSE" in upper:
        return "BSD-3-Clause"
    if "BSD-2" in upper or "2-CLAUSE" in upper:
        return "BSD-2-Clause"
    if "BSD" in upper:
        return "BSD-3-Clause"
    if "MIT" in upper:
        return "MIT"
    if "MPL" in upper and "2" in upper:
        return "MPL-2.0"
    if "ISC" in upper:
        return "ISC"
    if "SSPL" in upper:
        return "SSPL-1.0"
    if "EPL" in upper:
        return "EPL-2.0"
    if "ZLIB" in upper:
        return "Zlib"
    if "PSF" in upper or "PYTHON" in upper:
        return "PSF-2.0"
    return s.split(";")[0].split("\n")[0].strip()[:40]


class LicenseAnalyzer:
    """Detects project license, resolves dependency licenses, and derives copyleft conflicts."""

    def __init__(self, override_project_license: Optional[str] = None) -> None:
        self.override_project_license = override_project_license
        self._local_pypi_cache: Optional[Dict[str, str]] = None

    def detect_project_license(self, root_path: Path) -> str:
        """Identify the target repository's primary SPDX license."""
        if self.override_project_license:
            return normalize_spdx_id(self.override_project_license)

        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent

        # 1. Inspect LICENSE / COPYING files
        for fname in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYING.txt"):
            fpath = root / fname
            if fpath.is_file():
                text = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for spdx_id, needle_groups in LICENSE_TEXT_SIGNATURES:
                    if any(all(n in text for n in grp) for grp in needle_groups):
                        return spdx_id

        # 2. Fallback to package.json / pyproject.toml / Cargo.toml metadata
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                if data.get("license"):
                    return normalize_spdx_id(str(data["license"]))
            except Exception:
                pass

        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                with pyproject.open("rb") as f:
                    data = tomllib.load(f)
                lic = data.get("project", {}).get("license")
                if isinstance(lic, dict) and lic.get("text"):
                    return normalize_spdx_id(str(lic["text"]))
                if isinstance(lic, str):
                    return normalize_spdx_id(lic)
            except Exception:
                pass

        cargo = root / "Cargo.toml"
        if cargo.is_file():
            try:
                with cargo.open("rb") as f:
                    data = tomllib.load(f)
                lic = data.get("package", {}).get("license")
                if isinstance(lic, str):
                    return normalize_spdx_id(lic)
            except Exception:
                pass

        return "UNKNOWN"

    def _get_local_pypi_licenses(self) -> Dict[str, str]:
        if self._local_pypi_cache is not None:
            return self._local_pypi_cache
        cache: Dict[str, str] = {}
        try:
            for dist in importlib.metadata.distributions():
                name = (dist.metadata.get("Name") or "").lower().replace("_", "-")
                lic = dist.metadata.get("License-Expression") or dist.metadata.get("License") or ""
                if not lic:
                    classifiers = dist.metadata.get_all("Classifier") or []
                    for cl in classifiers:
                        if cl.startswith("License :: OSI Approved :: "):
                            lic = cl.rsplit("::", 1)[-1].strip()
                            break
                norm = normalize_spdx_id(lic)
                if name and norm != "UNKNOWN":
                    cache[name] = norm
        except Exception:
            pass
        self._local_pypi_cache = cache
        return cache

    def enrich_component_licenses(self, components: List[DependencyComponent]) -> None:
        """Populate missing component licenses from curated registry and local environment metadata."""
        local_meta = self._get_local_pypi_licenses()
        for comp in components:
            if comp.license_id and comp.license_id != "UNKNOWN":
                comp.license_id = normalize_spdx_id(comp.license_id)
                continue
            key = comp.name.lower()
            norm_py = key.replace("_", "-")
            if key in BUILTIN_PACKAGE_LICENSES:
                comp.license_id = BUILTIN_PACKAGE_LICENSES[key]
                comp.license_source = "openguard_registry"
            elif norm_py in BUILTIN_PACKAGE_LICENSES:
                comp.license_id = BUILTIN_PACKAGE_LICENSES[norm_py]
                comp.license_source = "openguard_registry"
            elif comp.ecosystem == "PyPI" and norm_py in local_meta:
                comp.license_id = local_meta[norm_py]
                comp.license_source = "local_python_metadata"

    def analyze_conflicts(
        self,
        project_name: str,
        project_license: str,
        components: List[DependencyComponent],
        graph: nx.DiGraph,
    ) -> List[LicenseConflict]:
        """Evaluate every dependency against the project's outbound license using SPDX matrix."""
        self.enrich_component_licenses(components)
        proj_lic = normalize_spdx_id(project_license)
        conflicts: List[LicenseConflict] = []

        for comp in components:
            comp_lic = normalize_spdx_id(comp.license_id)
            if comp_lic == "UNKNOWN":
                continue

            compat, sev, explanation, remediation = self._check_pair(proj_lic, comp_lic)
            if compat == LicenseCompatibility.COMPATIBLE:
                continue

            try:
                path = nx.shortest_path(graph, source=project_name, target=comp.name)
            except Exception:
                path = [project_name, comp.name]

            conflicts.append(
                LicenseConflict(
                    component_name=comp.name,
                    component_version=comp.version,
                    component_license=comp_lic,
                    project_license=proj_lic,
                    compatibility=compat,
                    severity=sev,
                    dependency_path=path,
                    explanation=explanation,
                    remediation=remediation,
                )
            )

        return conflicts

    @staticmethod
    def _check_pair(
        project_lic: str,
        dep_lic: str,
    ) -> Tuple[LicenseCompatibility, Severity, str, str]:
        # Handle dual licenses like "MIT OR GPL-3.0" permissively
        if " OR " in dep_lic.upper():
            options = [normalize_spdx_id(part) for part in re.split(r"\s+OR\s+", dep_lic, flags=re.I)]
            if any(opt in PERMISSIVE_LICENSES for opt in options):
                return LicenseCompatibility.COMPATIBLE, Severity.INFO, "", ""

        dep_is_strong = dep_lic in STRONG_COPYLEFT_LICENSES or any(
            dep_lic.startswith(x) for x in ("GPL-", "AGPL-", "SSPL-")
        )
        dep_is_weak = dep_lic in WEAK_COPYLEFT_LICENSES or any(
            dep_lic.startswith(x) for x in ("LGPL-", "MPL-", "EPL-")
        )
        proj_is_permissive = project_lic in PERMISSIVE_LICENSES
        proj_is_unknown = project_lic == "UNKNOWN"

        if dep_is_strong:
            if dep_lic.startswith("AGPL"):
                if project_lic != "AGPL-3.0":
                    return (
                        LicenseCompatibility.INCOMPATIBLE,
                        Severity.CRITICAL,
                        f"依赖采用强网络传染性许可证 `{dep_lic}`，即使作为网络服务端调用也要求整体按 AGPL-3.0 开源。",
                        "替换为 MIT/Apache-2.0/BSD 同类库（例如用 pypdf/pdfplumber 替代 PyMuPDF），或将项目整体切换为 AGPL-3.0。",
                    )
            elif proj_is_permissive or proj_is_unknown:
                return (
                    LicenseCompatibility.INCOMPATIBLE,
                    Severity.HIGH,
                    f"项目采用 `{project_lic}`，但引入了强传染性许可证 `{dep_lic}` 依赖，存在 GPL 病毒式传染与合规侵权风险。",
                    f"移除 `{dep_lic}` 依赖并更换为宽松许可替代库（如用 PySide6 替代 PyQt5，用 PyMySQL 替代 mysqlclient），或重新评估项目许可证。",
                )
            elif project_lic == "GPL-2.0" and dep_lic.startswith("GPL-3"):
                return (
                    LicenseCompatibility.INCOMPATIBLE,
                    Severity.HIGH,
                    "GPL-2.0-only 与 GPL-3.0 条款存在兼容性冲突，无法直接合并分发。",
                    "确认项目是否允许升级为 GPL-3.0 或寻找替代依赖。",
                )

        if dep_is_weak and (proj_is_permissive or proj_is_unknown):
            return (
                LicenseCompatibility.REVIEW_REQUIRED,
                Severity.MEDIUM,
                f"依赖采用弱传染性许可证 `{dep_lic}`：若静态链接或修改该库源码并打包分发，须同步公开对应修改及动态链接说明。",
                "保持动态依赖引用（不修改并打包其源码），在发行版中保留其版权声明与许可证文本。",
            )

        return LicenseCompatibility.COMPATIBLE, Severity.INFO, "", ""
