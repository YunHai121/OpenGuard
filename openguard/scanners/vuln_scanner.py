"""Supply-chain vulnerability & typosquatting detector (Offline CVE KB + Live OSV.dev API)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from packaging.version import InvalidVersion, Version

from openguard.models import DependencyComponent, FindingCategory, Severity, VulnerabilityFinding

# Curated Offline CVE Database covering high-frequency Python, npm, Go, Maven, and Rust CVEs
OFFLINE_CVE_DB: List[Dict[str, Any]] = [
    # PyPI
    {
        "ecosystem": "PyPI",
        "package": "pyyaml",
        "id": "CVE-2020-14343",
        "affected_lt": "5.4",
        "fixed": "5.4.1",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "summary": "PyYAML < 5.4 中 `yaml.load` / FullLoader 存在任意代码执行漏洞。",
    },
    {
        "ecosystem": "PyPI",
        "package": "urllib3",
        "id": "CVE-2021-33503",
        "affected_lt": "1.26.5",
        "fixed": "1.26.19",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "urllib3 URL 解析中多个 `@` 字符导致 ReDoS 拒绝服务风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "urllib3",
        "id": "CVE-2023-45803",
        "affected_lt": "2.0.7",
        "fixed": "2.2.2",
        "severity": Severity.MEDIUM,
        "cvss": 4.2,
        "summary": "urllib3 跨源重定向时未剥离 Request Body 造成敏感请求体泄露。",
    },
    {
        "ecosystem": "PyPI",
        "package": "requests",
        "id": "CVE-2023-32681",
        "affected_lt": "2.31.0",
        "fixed": "2.32.3",
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
        "summary": "requests 向重定向目标意外泄露 Proxy-Authorization 凭据头。",
    },
    {
        "ecosystem": "PyPI",
        "package": "jinja2",
        "id": "CVE-2024-22195",
        "affected_lt": "3.1.3",
        "fixed": "3.1.4",
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
        "summary": "Jinja2 `xmlattr` 过滤器存在跨站脚本 (XSS) 属性注入漏洞。",
    },
    {
        "ecosystem": "PyPI",
        "package": "flask",
        "id": "CVE-2023-30861",
        "affected_lt": "2.3.2",
        "fixed": "3.0.3",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "Flask 未设置 Vary: Cookie 头导致代理缓存中发生 Session Cookie 跨用户泄露。",
    },
    {
        "ecosystem": "PyPI",
        "package": "werkzeug",
        "id": "CVE-2024-34069",
        "affected_lt": "3.0.3",
        "fixed": "3.0.6",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "Werkzeug Debugger 在特定域名/主机配置下存在远程代码执行风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "django",
        "id": "CVE-2024-27351",
        "affected_lt": "4.2.11",
        "fixed": "5.0.8",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "Django `Truncator` 对复杂 HTML 存在正则回溯拒绝服务 (ReDoS)。",
    },
    {
        "ecosystem": "PyPI",
        "package": "pillow",
        "id": "CVE-2023-50447",
        "affected_lt": "10.2.0",
        "fixed": "10.4.0",
        "severity": Severity.CRITICAL,
        "cvss": 8.1,
        "summary": "Pillow `ImageMath.eval` 存在任意代码执行漏洞。",
    },
    {
        "ecosystem": "PyPI",
        "package": "cryptography",
        "id": "CVE-2024-26130",
        "affected_lt": "42.0.4",
        "fixed": "43.0.1",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "cryptography PKCS#12 解析时发生 NULL 指针解引用崩溃 (DoS)。",
    },
    {
        "ecosystem": "PyPI",
        "package": "fastapi",
        "id": "CVE-2024-24762",
        "affected_lt": "0.109.1",
        "fixed": "0.115.0",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "python-multipart / FastAPI Content-Type 头解析存在 ReDoS 拒绝服务风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "starlette",
        "id": "CVE-2024-47874",
        "affected_lt": "0.40.0",
        "fixed": "0.41.0",
        "severity": Severity.HIGH,
        "cvss": 8.7,
        "summary": "Starlette multipart 表单解析允许构造超大未限制字段耗尽内存。",
    },
    {
        "ecosystem": "PyPI",
        "package": "aiohttp",
        "id": "CVE-2024-23334",
        "affected_lt": "3.9.2",
        "fixed": "3.10.11",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "aiohttp 启用 `follow_symlinks` 的静态资源服务存在目录遍历漏洞。",
    },
    {
        "ecosystem": "PyPI",
        "package": "sqlalchemy",
        "id": "CVE-2019-7164",
        "affected_lt": "1.3.0",
        "fixed": "2.0.35",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "summary": "SQLAlchemy 旧版本 `order_by` / `group_by` 参数处理不当导致 SQL 注入风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "pyjwt",
        "id": "CVE-2022-29217",
        "affected_lt": "2.4.0",
        "fixed": "2.9.0",
        "severity": Severity.HIGH,
        "cvss": 7.4,
        "summary": "PyJWT 存在算法混淆攻击风险（HMAC 与非对称公钥混用）。",
    },
    {
        "ecosystem": "PyPI",
        "package": "paramiko",
        "id": "CVE-2023-48795",
        "affected_lt": "3.4.0",
        "fixed": "3.5.0",
        "severity": Severity.MEDIUM,
        "cvss": 5.9,
        "summary": "Terrapin SSH 握手前缀截断漏洞可能降低通道完整性。",
    },
    {
        "ecosystem": "PyPI",
        "package": "setuptools",
        "id": "CVE-2024-6345",
        "affected_lt": "70.0.0",
        "fixed": "75.1.0",
        "severity": Severity.HIGH,
        "cvss": 8.8,
        "summary": "setuptools `package_index` 下载 URL 处理存在远程代码执行漏洞。",
    },
    {
        "ecosystem": "PyPI",
        "package": "tornado",
        "id": "CVE-2023-28370",
        "affected_lt": "6.3.2",
        "fixed": "6.4.1",
        "severity": Severity.MEDIUM,
        "cvss": 5.4,
        "summary": "Tornado StaticFileHandler 存在开放重定向风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "numpy",
        "id": "CVE-2021-41496",
        "affected_lt": "1.22.0",
        "fixed": "1.26.4",
        "severity": Severity.MEDIUM,
        "cvss": 5.5,
        "summary": "NumPy f2py 模块存在缓冲区溢出风险。",
    },
    {
        "ecosystem": "PyPI",
        "package": "lxml",
        "id": "CVE-2022-2309",
        "affected_lt": "4.9.1",
        "fixed": "5.3.0",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "lxml iterwalk NULL 指针解引用触发崩溃。",
    },
    # npm
    {
        "ecosystem": "npm",
        "package": "lodash",
        "id": "CVE-2021-23337",
        "affected_lt": "4.17.21",
        "fixed": "4.17.21",
        "severity": Severity.HIGH,
        "cvss": 7.2,
        "summary": "lodash `template` 函数存在原型链污染及命令注入风险。",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "id": "CVE-2023-45857",
        "affected_lt": "1.6.0",
        "fixed": "1.7.7",
        "severity": Severity.MEDIUM,
        "cvss": 6.5,
        "summary": "axios 跨站请求意外暴露 XSRF-TOKEN 请求头。",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "id": "CVE-2024-29041",
        "affected_lt": "4.19.2",
        "fixed": "4.21.1",
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
        "summary": "Express `res.location` / `res.redirect` 存在开放重定向绕过。",
    },
    {
        "ecosystem": "npm",
        "package": "minimist",
        "id": "CVE-2021-44906",
        "affected_lt": "1.2.6",
        "fixed": "1.2.8",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "summary": "minimist 命令行参数解析存在严重原型链污染 (Prototype Pollution) 漏洞。",
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "id": "CVE-2022-23529",
        "affected_lt": "9.0.0",
        "fixed": "9.0.2",
        "severity": Severity.HIGH,
        "cvss": 7.6,
        "summary": "jsonwebtoken `verify()` 恶意构造密钥对象可导致任意代码执行。",
    },
    {
        "ecosystem": "npm",
        "package": "tar",
        "id": "CVE-2024-28863",
        "affected_lt": "6.2.1",
        "fixed": "6.2.1",
        "severity": Severity.MEDIUM,
        "cvss": 6.5,
        "summary": "node-tar 未限制深层嵌套目录解压消耗大量 CPU/内存资源。",
    },
    {
        "ecosystem": "npm",
        "package": "ws",
        "id": "CVE-2024-37890",
        "affected_lt": "8.17.1",
        "fixed": "8.18.0",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "ws 处理过多 HTTP Headers 时存在未捕获异常导致服务崩溃 (DoS)。",
    },
    {
        "ecosystem": "npm",
        "package": "semver",
        "id": "CVE-2022-25883",
        "affected_lt": "7.5.2",
        "fixed": "7.6.3",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "node-semver 版本解析存在正则拒绝服务 (ReDoS)。",
    },
    # Go / Maven / Rust
    {
        "ecosystem": "Go",
        "package": "golang.org/x/net",
        "id": "CVE-2023-44487",
        "affected_lt": "0.17.0",
        "fixed": "0.28.0",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "HTTP/2 Rapid Reset 攻击导致服务端资源耗尽 (DoS)。",
    },
    {
        "ecosystem": "Go",
        "package": "github.com/gin-gonic/gin",
        "id": "CVE-2023-29401",
        "affected_lt": "1.9.1",
        "fixed": "1.10.0",
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
        "summary": "Gin Context.FileAttachment 文件名未转义存在 HTTP 头注入风险。",
    },
    {
        "ecosystem": "Maven",
        "package": "org.apache.logging.log4j:log4j-core",
        "id": "CVE-2021-44228",
        "affected_lt": "2.17.1",
        "fixed": "2.23.1",
        "severity": Severity.CRITICAL,
        "cvss": 10.0,
        "summary": "Log4Shell JNDI 注入导致极端严重的远程代码执行漏洞。",
    },
    {
        "ecosystem": "Maven",
        "package": "org.springframework:spring-core",
        "id": "CVE-2022-22965",
        "affected_lt": "5.3.18",
        "fixed": "6.1.13",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "summary": "Spring4Shell JDK9+ 数据绑定导致远程代码执行漏洞。",
    },
    {
        "ecosystem": "Maven",
        "package": "com.fasterxml.jackson.core:jackson-databind",
        "id": "CVE-2022-42003",
        "affected_lt": "2.14.0",
        "fixed": "2.17.2",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "summary": "Jackson-databind 深度嵌套 JSON 反序列化资源耗尽漏洞。",
    },
    {
        "ecosystem": "crates.io",
        "package": "openssl",
        "id": "CVE-2024-2511",
        "affected_lt": "0.10.64",
        "fixed": "0.10.66",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "summary": "OpenSSL 会话缓存无界增长导致内存拒绝服务风险。",
    },
]

POPULAR_PACKAGES_FOR_TYPOSQUAT: Dict[str, List[str]] = {
    "PyPI": [
        "requests", "urllib3", "numpy", "pandas", "fastapi", "flask", "django",
        "pydantic", "pyyaml", "cryptography", "pillow", "scipy", "torch",
        "scikit-learn", "aiohttp", "sqlalchemy", "beautifulsoup4", "httpx",
        "typer", "rich", "click", "pytest", "setuptools", "jinja2", "networkx",
        "uvicorn", "starlette", "celery", "redis", "pymongo", "openai",
    ],
    "npm": [
        "react", "react-dom", "express", "lodash", "axios", "vue", "typescript",
        "next", "vite", "eslint", "prettier", "chalk", "commander", "moment",
        "dayjs", "jsonwebtoken", "minimist", "dotenv", "mongoose", "tailwindcss",
        "webpack", "babel", "jquery", "underscore", "cheerio", "puppeteer",
    ],
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _safe_parse_version(ver_str: str) -> Optional[Version]:
    cleaned = re.sub(r"^[vV~^=<>!\s]+", "", ver_str.strip())
    cleaned = cleaned.split(",")[0].split(" ")[0].strip()
    if not cleaned or cleaned in ("unspecified", "*", "latest"):
        return None
    try:
        return Version(cleaned)
    except InvalidVersion:
        m = re.match(r"(\d+(?:\.\d+){0,2})", cleaned)
        if m:
            try:
                return Version(m.group(1))
            except InvalidVersion:
                return None
    return None


class VulnScanner:
    """Combines offline CVE intelligence, live OSV.dev API, and typosquatting heuristics."""

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, offline: bool = False, cache_dir: Optional[Path] = None) -> None:
        self.offline = offline
        self.cache_path = (cache_dir or Path.home() / ".openguard") / "osv_cache.json"

    def scan_components(self, components: List[DependencyComponent]) -> List[VulnerabilityFinding]:
        """Identify known CVEs (offline + online OSV) and potential typosquatting packages."""
        findings: List[VulnerabilityFinding] = []
        seen: set[Tuple[str, str]] = set()

        # 1. Offline CVE knowledge base
        for comp in components:
            parsed_ver = _safe_parse_version(comp.version)
            pkg_lower = comp.name.lower()
            for entry in OFFLINE_CVE_DB:
                if entry["ecosystem"].lower() != comp.ecosystem.lower():
                    continue
                if entry["package"].lower() != pkg_lower:
                    continue
                if parsed_ver is None:
                    continue
                threshold = _safe_parse_version(entry["affected_lt"])
                if threshold and parsed_ver < threshold:
                    key = (entry["id"], pkg_lower)
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            VulnerabilityFinding(
                                id=entry["id"],
                                component_name=comp.name,
                                component_version=comp.version,
                                ecosystem=comp.ecosystem,
                                severity=entry["severity"],
                                cvss_score=entry["cvss"],
                                summary=entry["summary"],
                                fixed_version=entry["fixed"],
                                references=[f"https://nvd.nist.gov/vuln/detail/{entry['id']}"],
                                source="offline_db",
                                source_file=comp.source_file,
                                remediation=f"升级 `{comp.name}` 至安全版本 `>={entry['fixed']}`。",
                            )
                        )

        # 2. Supply-chain Typosquatting detection
        for comp in components:
            popular_list = POPULAR_PACKAGES_FOR_TYPOSQUAT.get(comp.ecosystem, [])
            low_name = comp.name.lower()
            if low_name in popular_list:
                continue
            for pop in popular_list:
                if abs(len(low_name) - len(pop)) > 2:
                    continue
                dist = _levenshtein(low_name, pop)
                # Flag 1-edit distance on >=5 char packages or 2-edit transposition on >=7 chars
                if (dist == 1 and len(pop) >= 5) or (dist == 2 and len(pop) >= 7 and sorted(low_name) == sorted(pop)):
                    key = (f"TYPO-{low_name}", low_name)
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            VulnerabilityFinding(
                                id=f"OG-TYPO-{comp.name.upper()}",
                                component_name=comp.name,
                                component_version=comp.version,
                                ecosystem=comp.ecosystem,
                                severity=Severity.HIGH,
                                cvss_score=7.8,
                                summary=f"疑似投毒/拼写仿冒包 (Typosquatting)：`{comp.name}` 与热门组件 `{pop}` 仅相差 {dist} 个字符。",
                                fixed_version=f"核验并替换为 `{pop}`",
                                source="typosquatting",
                                source_file=comp.source_file,
                                category=FindingCategory.TYPOSQUATTING,
                                remediation=f"立即核查 `{comp.source_file}` 中是否误拼写 `{pop}` 为 `{comp.name}`，防范供应链恶意投毒。",
                            )
                        )
                    break

        # 3. Online OSV.dev enrichment (graceful short-timeout fallback)
        if not self.offline and components:
            osv_hits = self._query_osv_batch(components)
            for hit in osv_hits:
                key = (hit.id, hit.component_name.lower())
                if key not in seen:
                    seen.add(key)
                    findings.append(hit)

        return findings

    def _query_osv_batch(self, components: List[DependencyComponent]) -> List[VulnerabilityFinding]:
        queries = []
        indexed_comps: List[DependencyComponent] = []
        for comp in components:
            if comp.version in ("unspecified", "*", "latest", ""):
                continue
            if comp.ecosystem not in ("PyPI", "npm", "Go", "Maven", "crates.io", "Packagist"):
                continue
            clean_v = re.sub(r"^[vV~^=<>!\s]+", "", comp.version.strip())
            queries.append(
                {
                    "version": clean_v,
                    "package": {"name": comp.name, "ecosystem": comp.ecosystem},
                }
            )
            indexed_comps.append(comp)

        if not queries:
            return []

        try:
            try:
                client_cm = httpx.Client(timeout=4.0)
            except httpx.InvalidURL:
                client_cm = httpx.Client(timeout=4.0, trust_env=False)
            with client_cm as client:
                resp = client.post(self.OSV_BATCH_URL, json={"queries": queries[:60]})
                if resp.status_code != 200:
                    return []
                payload = resp.json()
        except Exception:
            return []

        results = payload.get("results", [])
        findings: List[VulnerabilityFinding] = []
        for comp, res in zip(indexed_comps, results):
            for vuln in (res.get("vulns") or [])[:3]:
                vid = str(vuln.get("id", "OSV-UNKNOWN"))
                findings.append(
                    VulnerabilityFinding(
                        id=vid,
                        component_name=comp.name,
                        component_version=comp.version,
                        ecosystem=comp.ecosystem,
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        summary=str(vuln.get("summary") or f"OSV 漏洞库报告 {comp.name}@{comp.version} 受 {vid} 影响。"),
                        fixed_version="参阅 OSV 公告",
                        references=[f"https://osv.dev/vulnerability/{vid}"],
                        source="osv_api",
                        source_file=comp.source_file,
                        remediation=f"升级 `{comp.name}` 至最新已修复版本，详见 https://osv.dev/vulnerability/{vid}。",
                    )
                )
        return findings
