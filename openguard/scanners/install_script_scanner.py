"""Socket.dev & Datadog GuardDog-inspired behavioral scanner for supply-chain malware hooks.

Detects:
- Malicious npm lifecycle hooks (`preinstall`/`install`/`postinstall`/`prepare`/`preuninstall`)
  AND linked local JS scripts (`node telemetry.js`) for s1ngularity/Nx-style AI CLI hijacking
  (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) & credential exfiltration
- `package-lock.json` integrity tamper/downgrade (`http://` resolved or weak/missing `sha1`)
- Python `.pth` startup persistence backdoors (Shai-Hulud / GuardDog `import ...` hooks)
- Python `setup.py` dangerous calls, `cmdclass` install overrides, and env/credential exfiltration
"""

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
        re.compile(
            r"(?:base64\s+-d|Buffer\.from\([^)]+,\s*['\"]base64['\"]\)|\beval\s*\(|"
            r"\bnode\s+-e\s+['\"][^\n]*(?:child_process|execSync|exec\(|fetch\()|"
            r"\bpython3?\s+-c\s+['\"][^\n]*(?:os\.system|subprocess|urllib|exec\())",
            re.I,
        ),
        "npm 安装脚本包含 Base64 解码、动态 eval 或内联 `node -e` / `python -c` 高危执行逻辑，存在混淆恶意代码风险。",
    ),
    (
        "OG-SUP-NPM-003",
        Severity.HIGH,
        7.8,
        re.compile(r"(?:curl|wget|powershell\s+-e|/dev/tcp/|nc\s+-e|chmod\s+\+x\s+.*&&)", re.I),
        "npm 生命周期脚本触发非标准网络下载或提权执行行为。",
    ),
]

# s1ngularity / Nx-style AI CLI weaponization & destructive shell sabotage indicators
AI_CLI_HIJACK_RE = re.compile(
    r"(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|"
    r"--trust-all-tools|(?:claude|gemini|codex)\b[^\n]{0,80}--yolo|"
    r"sudo\s+shutdown\s+-h\s+0)",
    re.I,
)
CRED_HARVEST_RE = re.compile(
    r"(?:process\.env\b|\.aws/credentials|\.npmrc|\.pypirc|id_rsa|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY)",
    re.I,
)
EXFIL_SINK_RE = re.compile(
    r"(?:webhook\.site|pipedream\.net|requestbin|oastify\.com|interact\.sh|"
    r"\bfetch\s*\(|https?\.request\s*\(|axios\.post\s*\(|https?://\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)
NODE_LOCAL_SCRIPT_RE = re.compile(
    r"\b(?:node|sh|bash|python3?)\s+['\"]?(\.?/?[A-Za-z0-9_.\-/]+\.(?:(?:c|m)?js|sh|py))['\"]?"
)
PTH_EXEC_IMPORT_RE = re.compile(r"^\s*import\s+\S+")
PTH_HIGH_RISK_RE = re.compile(r"(?:\bexec\s*\(|\beval\s*\(|__import__|base64|subprocess|urllib|socket|os\.system)", re.I)
PY_CRED_INDICATOR_RE = re.compile(
    r"(?:os\.environ|os\.getenv|\.aws/credentials|\.npmrc|\.pypirc|id_rsa|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)",
    re.I,
)
PY_OBFUSCATION_CALLS = {"base64.b64decode", "b64decode", "zlib.decompress", "codecs.decode", "marshal.loads"}
PY_NETWORK_CALLS = {
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "requests.post",
    "requests.get",
    "httpx.post",
    "httpx.get",
    "http.client.HTTPSConnection",
    "http.client.HTTPConnection",
    "socket.socket",
}
PY_CMDCLASS_HOOKS = {"install", "develop", "egg_info", "build_py"}


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
                    findings.extend(self._scan_package_json(fpath, rel, root))
                elif low == "package-lock.json":
                    findings.extend(self._scan_package_lock_integrity(fpath, rel))
                elif low == "setup.py":
                    findings.extend(self._scan_setup_py(fpath, rel))
                elif low.endswith(".pth"):
                    findings.extend(self._scan_pth_file(fpath, rel))
        return findings

    def _scan_package_json(self, fpath: Path, rel: str, repo_root: Path) -> List[VulnerabilityFinding]:
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

            # 1. Direct command-line patterns (pipe-to-shell, base64/eval, download/exec)
            matched_inline = False
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
                            source_file=rel,
                            category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                            remediation=f"立即审查 `{rel}` 中 `scripts.{hook_name}` 的来源与行为，安装未知依赖建议启用 `npm ci --ignore-scripts`。",
                            reachable=True,
                            reachability_level="call_reachable",
                            priority_tier="P0",
                            import_locations=[rel],
                        )
                    )
                    matched_inline = True
                    break

            # 2. Inline AI CLI hijacking (s1ngularity/Nx pattern)
            if not matched_inline and AI_CLI_HIJACK_RE.search(cmd):
                findings.append(
                    VulnerabilityFinding(
                        id="OG-SUP-NPM-004",
                        component_name=f"{pkg_name} (scripts.{hook_name})",
                        component_version=pkg_ver,
                        ecosystem="npm",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        summary=f"npm 生命周期脚本试图劫持本地 AI 编程助手权限或破坏 Shell 环境（s1ngularity 攻击特征）: `{cmd[:120]}`",
                        fixed_version="立即移除恶意生命周期钩子并轮换本机所有凭据",
                        source="install_script",
                        source_file=rel,
                        category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                        remediation=f"立即隔离并审查 `{rel}`，使用 `npm ci --ignore-scripts` 禁止安装期执行不可信脚本。",
                        reachable=True,
                        reachability_level="call_reachable",
                        priority_tier="P0",
                        import_locations=[rel],
                    )
                )

            # 3. Follow referenced local JS scripts (e.g. `node telemetry.js`) safely inside repo_root
            for m_js in NODE_LOCAL_SCRIPT_RE.finditer(cmd):
                script_arg = m_js.group(1)
                candidate = (fpath.parent / script_arg).resolve()
                try:
                    if not candidate.is_relative_to(repo_root) or not candidate.is_file():
                        continue
                    if candidate.stat().st_size > 512 * 1024:
                        continue
                    js_body = candidate.read_text(encoding="utf-8", errors="replace")
                    js_rel = candidate.relative_to(repo_root).as_posix()
                except OSError:
                    continue

                if AI_CLI_HIJACK_RE.search(js_body):
                    findings.append(
                        VulnerabilityFinding(
                            id="OG-SUP-NPM-004",
                            component_name=f"{pkg_name} ({js_rel})",
                            component_version=pkg_ver,
                            ecosystem="npm",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            summary=f"生命周期钩子 `scripts.{hook_name}` 调用的脚本 `{js_rel}` 包含 AI CLI 越权劫持或破坏性指令（s1ngularity/Nx 特征）。",
                            fixed_version="删除恶意安装脚本并立即轮换本地 GitHub/npm/AWS 凭据",
                            source="install_script",
                            source_file=js_rel,
                            category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                            remediation=f"审查 `{js_rel}` 并将其从 `{rel}` 的 `scripts.{hook_name}` 中彻底移除。",
                            reachable=True,
                            reachability_level="call_reachable",
                            priority_tier="P0",
                            import_locations=[rel, js_rel],
                        )
                    )
                elif (CRED_HARVEST_RE.search(js_body) or PY_CRED_INDICATOR_RE.search(js_body)) and (
                    EXFIL_SINK_RE.search(js_body) or "curl " in js_body.lower() or "urllib" in js_body.lower()
                ):
                    findings.append(
                        VulnerabilityFinding(
                            id="OG-SUP-NPM-005",
                            component_name=f"{pkg_name} ({js_rel})",
                            component_version=pkg_ver,
                            ecosystem="npm",
                            severity=Severity.CRITICAL,
                            cvss_score=9.4,
                            summary=f"生命周期钩子 `scripts.{hook_name}` 调用的脚本 `{js_rel}` 同时读取敏感环境变量/凭据并存在外传网络调用。",
                            fixed_version="移除窃密脚本并使用 `npm ci --ignore-scripts` 审计依赖",
                            source="install_script",
                            source_file=js_rel,
                            category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                            remediation=f"审查 `{js_rel}` 中的 `process.env`/凭据读取及外发 HTTP 目标，阻断供应链窃密。",
                            reachable=True,
                            reachability_level="call_reachable",
                            priority_tier="P0",
                            import_locations=[rel, js_rel],
                        )
                    )
        return findings

    def _scan_pth_file(self, fpath: Path, rel: str) -> List[VulnerabilityFinding]:
        """Detect Python `.pth` startup persistence backdoors (Shai-Hulud / GuardDog)."""
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        exec_lines: List[Tuple[int, str]] = []
        high_risk = False
        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if PTH_EXEC_IMPORT_RE.match(stripped):
                exec_lines.append((idx, stripped[:120]))
                if PTH_HIGH_RISK_RE.search(stripped):
                    high_risk = True

        if not exec_lines:
            return []

        sev = Severity.CRITICAL if high_risk else Severity.HIGH
        cvss = 9.6 if high_risk else 8.4
        tier = "P0" if high_risk else "P1"
        sample_ln, sample_txt = exec_lines[0]
        return [
            VulnerabilityFinding(
                id="OG-SUP-PY-002",
                component_name=rel,
                component_version="site-startup (.pth)",
                ecosystem="PyPI",
                severity=sev,
                cvss_score=cvss,
                summary=f"Python `.pth` 文件 `{rel}` 第 {sample_ln} 行包含启动期自动执行 `import` 代码（Shai-Hulud / GuardDog 持久化后门特征）: `{sample_txt}`",
                fixed_version="移除 `.pth` 中的可执行 import 语句，仅保留纯路径条目",
                source="install_script",
                source_file=rel,
                category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                remediation="Python 解释器每次启动都会自动执行 `.pth` 中以 `import ` 开头的语句，请立即核查其合法性并清除恶意持久化载荷。",
                reachable=True,
                reachability_level="call_reachable",
                priority_tier=tier,
                import_locations=[f"{rel}:{sample_ln}"],
            )
        ]

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
        obf_calls: List[str] = []
        net_calls: List[str] = []
        cmdclass_hooks: List[str] = []

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
                if name in PY_OBFUSCATION_CALLS:
                    obf_calls.append(f"{name}@L{node.lineno}")
                if name in PY_NETWORK_CALLS:
                    net_calls.append(f"{name}@L{node.lineno}")
                # GuardDog heuristic: setup(..., cmdclass={"install": CustomInstall})
                if name in ("setup", "setuptools.setup"):
                    for kw in node.keywords:
                        if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                            for k in kw.value.keys:
                                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value in PY_CMDCLASS_HOOKS:
                                    cmdclass_hooks.append(f"{k.value}@L{node.lineno}")

        findings: List[VulnerabilityFinding] = []
        has_cred_read = bool(PY_CRED_INDICATOR_RE.search(content))

        if (has_cred_read and net_calls) or (obf_calls and (risky_calls or net_calls)):
            signals = [*cmdclass_hooks[:2], *obf_calls[:2], *net_calls[:2]]
            findings.append(
                VulnerabilityFinding(
                    id="OG-SUP-PY-003",
                    component_name=rel,
                    component_version="setup.py",
                    ecosystem="PyPI",
                    severity=Severity.CRITICAL,
                    cvss_score=9.5,
                    summary=f"`setup.py` 检出 GuardDog 高危供应链攻击链（安装期凭据窃取外传或混淆载荷执行）: {', '.join(signals[:5])}。",
                    fixed_version="立即移除恶意 setup.py 并改用纯声明式 pyproject.toml",
                    source="install_script",
                    source_file=rel,
                    category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                    remediation="严禁在 `setup.py` 中读取环境变量/凭据并外发网络或执行 Base64/zlib 解压载荷，请彻底审查包来源并轮换凭据。",
                    reachable=True,
                    reachability_level="call_reachable",
                    priority_tier="P0",
                    import_locations=[rel],
                )
            )
        elif cmdclass_hooks and not risky_calls:
            findings.append(
                VulnerabilityFinding(
                    id="OG-SUP-PY-003",
                    component_name=rel,
                    component_version="setup.py",
                    ecosystem="PyPI",
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    summary=f"`setup.py` 通过 `cmdclass` 覆写安装期命令（{', '.join(cmdclass_hooks[:4])}），存在 `pip install` 自动执行任意代码风险（GuardDog 启发式）。",
                    fixed_version="迁移至纯声明式 pyproject.toml (PEP 621)",
                    source="install_script",
                    source_file=rel,
                    category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                    remediation="人工审计 `cmdclass` 覆写类的 `run()` 实现，确认无静默下载或凭据收集行为。",
                    reachable=True,
                    reachability_level="call_reachable",
                    priority_tier="P1",
                    import_locations=[rel],
                )
            )

        if risky_calls:
            findings.append(
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
                    source_file=rel,
                    category=FindingCategory.SUPPLY_CHAIN_SCRIPT,
                    remediation="审核 `setup.py` 安装期命令与网络访问必要性，推荐迁移至纯声明式 `pyproject.toml` (PEP 621)。",
                    reachable=True,
                    import_locations=[f"{rel}"],
                )
            )

        return findings

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
