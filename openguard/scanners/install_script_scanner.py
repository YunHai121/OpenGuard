"""Socket.dev-inspired behavioral scanner for suspicious package install/lifecycle scripts."""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import FindingCategory, Severity, VulnerabilityFinding

SUSPICIOUS_SCRIPT_HOOKS = ("preinstall", "install", "postinstall", "prepare", "preuninstall")

NPM_SCRIPT_PATTERNS: List[Tuple[str, Severity, float, re.Pattern[str], str]] = [
    (
        "OG-SUP-NPM-001",
        Severity.CRITICAL,
        9.4,
        re.compile(r"(?:curl|wget|fetch)\s+[^|]*\|\s*(?:sh|bash|zsh|pwsh|powershell|node|python)", re.I),
        "npm 生命周期脚本下载远程载荷并直接管道输入 Shell 执行，属于典型投毒木马特征。",
    ),
    (
        "OG-SUP-NPM-002",
        Severity.HIGH,
        8.2,
        re.compile(r"(?:base64\s+-d|Buffer\.from\([^)]+,\s*['\"]base64['\"]\)|\beval\s*\()", re.I),
        "npm 安装脚本包含 Base64 解码或动态 eval 执行逻辑，存在混淆恶意代码风险。",
    ),
    (
        "OG-SUP-NPM-003",
        Severity.HIGH,
        7.8,
        re.compile(r"(?:curl|wget|powershell\s+-e|/dev/tcp/|nc\s+-e|chmod\s+\+x\s+.*&&)", re.I),
        "npm 生命周期脚本触发非标准网络下载或提权执行行为。",
    ),
]


class InstallScriptScanner:
    """Detects malicious lifecycle hooks in package.json and dangerous setup.py calls."""

    def scan_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[VulnerabilityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent
        excludes = exclude_patterns or []
        findings: List[VulnerabilityFinding] = []

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
                low = fname.lower()
                if low == "package.json":
                    findings.extend(self._scan_package_json(fpath, rel))
                elif low == "package-lock.json":
                    findings.extend(self._scan_package_lock_integrity(fpath, rel))
                elif low == "setup.py":
                    findings.extend(self._scan_setup_py(fpath, rel))
        return findings

    def _scan_package_json(self, fpath: Path, rel: str) -> List[VulnerabilityFinding]:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []

        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return []

        pkg_name = str(data.get("name") or rel)
        pkg_ver = str(data.get("version") or "0.0.0")
        findings: List[VulnerabilityFinding] = []

        for hook_name, cmd in scripts.items():
            if hook_name not in SUSPICIOUS_SCRIPT_HOOKS or not isinstance(cmd, str):
                continue
            for rule_id, sev, cvss, pat, summary in NPM_SCRIPT_PATTERNS:
                if pat.search(cmd):
                    findings.append(
                        VulnerabilityFinding(
                            id=rule_id,
                            component_name=f"{pkg_name} (scripts.{hook_name})",
                            component_version=pkg_ver,
                            ecosystem="npm",
                            severity=sev,
                            cvss_score=cvss,
                            summary=f"{summary} 脚本内容: `{cmd[:120]}`",
                            fixed_version="移除高危 install 钩子或加 `--ignore-scripts` 审查",
                            source="install_script",
                            category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                            remediation=f"立即审查 `{rel}` 中 `scripts.{hook_name}` 的来源与行为，安装未知依赖建议启用 `npm ci --ignore-scripts`。",
                            reachable=True,
                            import_locations=[rel],
                        )
                    )
                    break
        return findings

    def _scan_package_lock_integrity(self, fpath: Path, rel: str) -> List[VulnerabilityFinding]:
        """Audit `package-lock.json` for lockfile injection (http:// downgrade or missing/weak sha1 integrity)."""
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return []

        findings: List[VulnerabilityFinding] = []
        http_pkgs: List[str] = []
        weak_int_pkgs: List[str] = []

        for pkg_path, info in packages.items():
            if not pkg_path or not isinstance(info, dict) or info.get("link"):
                continue
            resolved = str(info.get("resolved") or "").strip()
            integrity = str(info.get("integrity") or "").strip()
            name = pkg_path.split("node_modules/")[-1]

            if resolved.lower().startswith("http://"):
                http_pkgs.append(f"{name} ({resolved[:60]})")
            elif resolved.lower().startswith("https://"):
                if not integrity or integrity.lower().startswith("sha1-"):
                    weak_int_pkgs.append(name)

        if http_pkgs:
            findings.append(
                VulnerabilityFinding(
                    id="OG-SUP-LOCK-001",
                    component_name=rel,
                    component_version="package-lock.json",
                    ecosystem="npm",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    summary=f"锁文件 `{rel}` 包含明文 HTTP (`http://`) 包下载地址，存在中间人篡改与锁文件投毒风险：{', '.join(http_pkgs[:4])}。",
                    fixed_version="切换为 HTTPS 官方源并重新生成 package-lock.json",
                    source="install_script",
                    source_file=rel,
                    category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                    remediation="核查并清除 `http://` 非加密依赖源，使用受信任 HTTPS 镜像源重新执行 `npm install --package-lock-only`。",
                    reachable=True,
                    reachability_level="call_reachable",
                    priority_tier="P0",
                    import_locations=[rel],
                )
            )

        if weak_int_pkgs:
            findings.append(
                VulnerabilityFinding(
                    id="OG-SUP-LOCK-002",
                    component_name=rel,
                    component_version="package-lock.json",
                    ecosystem="npm",
                    severity=Severity.HIGH,
                    cvss_score=7.8,
                    summary=f"锁文件 `{rel}` 中存在缺少 `sha512` 完整性校验或降级为弱 `sha1` 的远端依赖：{', '.join(weak_int_pkgs[:5])}。",
                    fixed_version="使用 npm >= 8 重新生成带 sha512 integrity 的锁文件",
                    source="install_script",
                    source_file=rel,
                    category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                    remediation="重新生成包含 `sha512-...` 完整性哈希的 `package-lock.json`，并在 CI 中使用 `npm ci` 强制校验。",
                    reachable=True,
                    reachability_level="call_reachable",
                    priority_tier="P1",
                    import_locations=[rel],
                )
            )

        return findings

    def _scan_setup_py(self, fpath: Path, rel: str) -> List[VulnerabilityFinding]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except Exception:
            return []

        risky_calls: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._call_name(node.func)
                if name in (
                    "os.system",
                    "os.popen",
                    "subprocess.run",
                    "subprocess.Popen",
                    "subprocess.call",
                    "urllib.request.urlopen",
                    "urllib.request.urlretrieve",
                    "socket.socket",
                    "exec",
                    "eval",
                ):
                    risky_calls.append(f"{name}@L{node.lineno}")

        if not risky_calls:
            return []

        return [
            VulnerabilityFinding(
                id="OG-SUP-PY-001",
                component_name=rel,
                component_version="setup.py",
                ecosystem="PyPI",
                severity=Severity.HIGH,
                cvss_score=8.0,
                summary=f"`setup.py` 在包安装阶段调用高危系统命令或网络接口: {', '.join(risky_calls[:5])}。",
                fixed_version="迁移至声明式 pyproject.toml 构建",
                source="install_script",
                category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                remediation="审核 `setup.py` 安装期命令与网络访问必要性，推荐迁移至纯声明式 `pyproject.toml` (PEP 621)。",
                reachable=True,
                import_locations=[f"{rel}"],
            )
        ]

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = [node.attr]
            cur = node.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""
