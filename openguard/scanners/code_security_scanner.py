"""AST-based Python SAST and multi-language code security anti-pattern scanner."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import os
import re
from pathlib import Path
from typing import List, Tuple

from openguard.config import AuditConfig, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity

JS_SAST_PATTERNS: List[Tuple[str, str, str, Severity, re.Pattern[str], str, str]] = [
    (
        "OG-SAST-JS-001",
        "Dynamic eval() / Function() Code Execution",
        "CWE-95",
        Severity.HIGH,
        re.compile(r"\b(?:eval|new\s+Function)\s*\("),
        "在 JavaScript/TypeScript 中调用动态 `eval()` 或 `new Function()` 易导致远程代码/XSS 注入。",
        "改用 `JSON.parse()` 或显式映射函数替代动态求值。",
    ),
    (
        "OG-SAST-JS-002",
        "Unsafe DOM XSS Sink (innerHTML / dangerouslySetInnerHTML)",
        "CWE-79",
        Severity.MEDIUM,
        re.compile(r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*:)"),
        "直接写入未净化的 HTML 字符串存在跨站脚本 (XSS) 风险。",
        "优先使用 `textContent` 或经 `DOMPurify.sanitize()` 净化后再渲染。",
    ),
    (
        "OG-SAST-JS-003",
        "Disabled TLS Certificate Verification in Node.js",
        "CWE-295",
        Severity.HIGH,
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?|rejectUnauthorized\s*:\s*false"),
        "全局或局部禁用 TLS 证书校验使 HTTPS 连接易受中间人攻击 (MITM)。",
        "移除禁用校验配置并配置正确的 CA 证书链。",
    ),
]


class CodeSecurityScanner:
    """Static Application Security Testing (SAST) scanner using Python AST + JS/Shell rules."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    def scan_directory(self, root_path: Path) -> List[CodeSecurityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            return self.scan_file(root, root.parent)

        target_files: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
            dirnames[:] = [
                d for d in sorted(dirnames)
                if not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", self.config.exclude_patterns)
            ]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root).as_posix()
                if is_path_excluded(rel, self.config.exclude_patterns):
                    continue
                if fpath.suffix.lower() in (
                    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".go",
                    ".java", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs",
                ):
                    target_files.append(fpath)

        cache = None
        if getattr(self.config, "use_cache", False):
            from openguard.utils.scan_cache import IncrementalScanCache

            cache = IncrementalScanCache(root, self.config)

        def _scan_one(fpath: Path) -> List[CodeSecurityFinding]:
            if cache is None:
                return self.scan_file(fpath, root)
            from openguard.utils.scan_cache import compute_file_cache_key

            try:
                raw_bytes = fpath.read_bytes()
            except OSError:
                return []
            rel = fpath.resolve().relative_to(root.resolve()).as_posix()
            ckey = compute_file_cache_key(raw_bytes, cache.config_fp, f"sast:{rel}")
            cached = cache.get(ckey)
            if cached is not None:
                return [CodeSecurityFinding(**item) for item in cached]
            res = self.scan_content(raw_bytes.decode("utf-8", errors="replace"), rel)
            cache.put(ckey, [item.model_dump() for item in res])
            return res

        workers = max(1, min(int(getattr(self.config, "max_workers", 4) or 1), 8))
        findings: List[CodeSecurityFinding] = []
        if workers > 1 and len(target_files) >= 16:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for batch in pool.map(_scan_one, target_files):
                    findings.extend(batch)
        else:
            for fpath in target_files:
                findings.extend(_scan_one(fpath))
        if cache is not None:
            cache.flush()
        return findings

    def scan_file(self, file_path: Path, root_path: Path | None = None) -> List[CodeSecurityFinding]:
        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        rel = file_path.resolve().relative_to(root_path.resolve()).as_posix() if root_path else file_path.name
        return self.scan_content(raw, rel)

    def scan_content(self, content: str, file_path: str = "snippet.py") -> List[CodeSecurityFinding]:
        ext = Path(file_path).suffix.lower()
        if ext == ".py":
            return self._scan_python_ast(content, file_path)
        if ext in (".js", ".ts", ".jsx", ".tsx"):
            return self._scan_js_patterns(content, file_path)
        if ext == ".sh":
            return self._scan_shell_patterns(content, file_path)
        if ext == ".go":
            return self._scan_go_patterns(content, file_path)
        if ext == ".java":
            return self._scan_java_patterns(content, file_path)
        if ext in (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"):
            return self._scan_cpp_patterns(content, file_path)
        if ext == ".rs":
            return self._scan_rust_patterns(content, file_path)
        return []

    def _scan_python_ast(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []

        def snippet_at(ln: int) -> str:
            return lines[ln - 1].strip()[:180] if 1 <= ln <= len(lines) else ""

        def has_ignore(ln: int) -> bool:
            s = snippet_at(ln).lower()
            return "openguard: ignore" in s or "nosec" in s

        class _SastVisitor(ast.NodeVisitor):
            def visit_Call(self, node: ast.Call) -> None:
                ln = node.lineno
                if has_ignore(ln):
                    self.generic_visit(node)
                    return

                func_name = self._resolve_call_name(node.func)

                # 1. CWE-95: eval() / exec()
                if func_name in ("eval", "exec"):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-PY-001",
                            rule_name="Dynamic eval()/exec() Execution",
                            cwe_id="CWE-95",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=ln,
                            snippet=snippet_at(ln),
                            description=f"调用 `{func_name}()` 执行动态代码，若输入可控可导致任意代码执行 (RCE)。",
                            remediation="使用 `ast.literal_eval()` 解析字面量，或通过显式字典分发替换动态执行。",
                        )
                    )

                # 2. CWE-502: Unsafe deserialization (pickle.loads / yaml.load without SafeLoader)
                elif func_name in ("pickle.loads", "pickle.load", "marshal.loads", "shelve.open"):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-PY-002",
                            rule_name="Unsafe Pickle/Marshal Deserialization",
                            cwe_id="CWE-502",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=ln,
                            snippet=snippet_at(ln),
                            description=f"`{func_name}()` 反序列化不可信数据时可直接触发任意代码执行。",
                            remediation="改用 `json.loads()` 等无代码执行能力的安全序列化格式。",
                        )
                    )
                elif func_name == "yaml.load":
                    loader_kw = [kw for kw in node.keywords if kw.arg == "Loader"]
                    loader_is_safe = any(
                        "SafeLoader" in ast.dump(kw.value) or "CSafeLoader" in ast.dump(kw.value)
                        for kw in loader_kw
                    )
                    if not loader_is_safe:
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-SAST-PY-003",
                                rule_name="Unsafe PyYAML yaml.load() Without SafeLoader",
                                cwe_id="CWE-502",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snippet_at(ln),
                                description="`yaml.load()` 未指定 `Loader=yaml.SafeLoader`，构造恶意 YAML 可执行任意 Python 对象。",
                                remediation="替换为 `yaml.safe_load(...)` 或显式传入 `Loader=yaml.SafeLoader`。",
                            )
                        )

                # 3. CWE-78: Command Injection (subprocess shell=True / os.system)
                elif func_name in ("os.system", "os.popen") or (
                    func_name.startswith("subprocess.")
                    and any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                ):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-PY-004",
                            rule_name="OS Command Injection Risk (shell=True / os.system)",
                            cwe_id="CWE-78",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=ln,
                            snippet=snippet_at(ln),
                            description=f"通过 `{func_name}` 启用 Shell 解析执行系统命令，若拼接外部参数易触发命令注入。",
                            remediation="改用 `subprocess.run(['cmd', arg1], shell=False)` 列表传参方式隔离 Shell 解释器。",
                        )
                    )

                # 4. CWE-295: Disabled TLS verification (verify=False)
                elif any(
                    kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                    for kw in node.keywords
                ):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-PY-005",
                            rule_name="Disabled SSL/TLS Certificate Verification",
                            cwe_id="CWE-295",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=ln,
                            snippet=snippet_at(ln),
                            description="网络请求显式关闭 TLS 证书校验 (`verify=False`)，存在中间人劫持与凭据窃取风险。",
                            remediation="移除 `verify=False` 或通过 `verify='/path/to/ca.pem'` 指定受信任根证书。",
                        )
                    )

                # 5. CWE-89: Potential SQL Injection in `.execute(...)`
                elif func_name.endswith(".execute") and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-SAST-PY-006",
                                rule_name="Potential SQL Injection via String Formatting",
                                cwe_id="CWE-89",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snippet_at(ln),
                                description="`execute()` 中使用 f-string 或字符串拼接构造 SQL，存在 SQL 注入风险。",
                                remediation="改用参数化查询 `cursor.execute('SELECT ... WHERE id = ?', (val,))`。",
                            )
                        )

                # 6. CWE-489: Flask/Web Debug Mode enabled in code
                elif func_name.endswith(".run") and any(
                    kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                ):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-PY-007",
                            rule_name="Web Framework Debug Mode Enabled",
                            cwe_id="CWE-489",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=ln,
                            snippet=snippet_at(ln),
                            description="硬编码开启 `debug=True` 可能暴露交互式调试控制台并引发信息泄露或 RCE。",
                            remediation="生产环境通过环境变量控制开关：`debug=os.getenv('DEBUG') == 'true'`。",
                        )
                    )

                # 7. CWE-327: Weak cryptographic hash (md5 / sha1 without usedforsecurity=False)
                elif func_name in ("hashlib.md5", "hashlib.sha1"):
                    non_sec = any(
                        kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords
                    )
                    if not non_sec:
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-SAST-PY-008",
                                rule_name="Weak Cryptographic Hash Algorithm (MD5/SHA1)",
                                cwe_id="CWE-327",
                                severity=Severity.LOW,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snippet_at(ln),
                                description=f"使用弱散列算法 `{func_name}`，不可用于密码存储或签名校验。",
                                remediation="安全场景改用 `hashlib.sha256` 或 `bcrypt`/`argon2`；纯校验场景可传入 `usedforsecurity=False`。",
                            )
                        )

                self.generic_visit(node)

            @staticmethod
            def _resolve_call_name(func_node: ast.AST) -> str:
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

        _SastVisitor().visit(tree)

        # Intra-procedural Python AST Taint Tracking (SQLi, Command Injection, SSRF, Path Traversal)
        from openguard.scanners.taint_analyzer import PythonTaintAnalyzer

        existing_keys = {(f.line_number, f.cwe_id) for f in findings}
        for tf in PythonTaintAnalyzer().analyze(content, file_path):
            if (tf.line_number, tf.cwe_id) not in existing_keys:
                existing_keys.add((tf.line_number, tf.cwe_id))
                findings.append(tf)

        return findings

    def _scan_js_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or "openguard: ignore" in stripped.lower():
                continue
            for rule_id, name, cwe, sev, pat, desc, rem in JS_SAST_PATTERNS:
                if pat.search(line):
                    if rule_id == "OG-SAST-JS-002":
                        lower_line = line.lower()
                        if "dompurify.sanitize" in lower_line or "sanitizehtml" in lower_line:
                            continue
                        # Static literal with no interpolation
                        if re.search(r"\.innerHTML\s*=\s*['\"][^$'\"`]*['\"]\s*;?\s*$", stripped):
                            continue
                    findings.append(
                        CodeSecurityFinding(
                            rule_id=rule_id,
                            rule_name=name,
                            cwe_id=cwe,
                            severity=sev,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=desc,
                            remediation=rem,
                        )
                    )

        # Cross-statement JavaScript / TypeScript Taint Tracking (XSS, SSRF, RCE, Path Traversal, Prototype Pollution)
        from openguard.scanners.js_taint_analyzer import JSTaintAnalyzer

        existing_keys = {(f.line_number, f.cwe_id) for f in findings}
        for tf in JSTaintAnalyzer().analyze(content, file_path):
            if (tf.line_number, tf.cwe_id) not in existing_keys:
                existing_keys.add((tf.line_number, tf.cwe_id))
                findings.append(tf)

        return findings

    def _scan_shell_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "openguard: ignore" in stripped.lower():
                continue
            if re.search(r"\bchmod\s+(?:-R\s+)?777\b", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-SH-001",
                        rule_name="World-Writable File Permission (chmod 777)",
                        cwe_id="CWE-732",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="设置 `chmod 777` 允许任意本地用户篡改文件或脚本。",
                        remediation="遵循最小权限原则，改用 `chmod 750` 或 `chmod 644`。",
                    )
                )
            if re.search(r"curl\s+[^|]*\|\s*(?:bash|sh)\b", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-SH-002",
                        rule_name="Unverified Pipe-to-Shell Execution (curl | sh)",
                        cwe_id="CWE-829",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="直接将远程脚本管道输入 Shell 执行缺少哈希校验，易受源站或劫持投毒。",
                        remediation="先下载脚本并校验 SHA256 签名后再执行。",
                    )
                )
        return findings

    def _scan_go_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or "openguard: ignore" in stripped.lower():
                continue
            if re.search(r"InsecureSkipVerify\s*:\s*true", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-GO-001",
                        rule_name="Disabled TLS Certificate Verification in Go (InsecureSkipVerify)",
                        cwe_id="CWE-295",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="Go `tls.Config` 启用了 `InsecureSkipVerify: true`，使 HTTPS/TLS 连接易遭中间人攻击。",
                        remediation="移除 `InsecureSkipVerify: true` 并配置受信任的 `RootCAs`。",
                    )
                )
            if re.search(r'exec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"(?:-c|/C)"', line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-GO-002",
                        rule_name="Go Shell Command Execution Injection Risk",
                        cwe_id="CWE-78",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="通过 `exec.Command(\"sh\", \"-c\", ...)` 调用 Shell 解释器执行命令，存在命令注入风险。",
                        remediation="直接传入目标可执行文件与参数数组 `exec.Command(bin, arg1, arg2)` 避免 Shell 解析。",
                    )
                )
            if re.search(r'"crypto/(?:md5|sha1)"', line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-GO-003",
                        rule_name="Weak Cryptographic Hash Package in Go (crypto/md5 or crypto/sha1)",
                        cwe_id="CWE-327",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="导入弱散列包 `crypto/md5` 或 `crypto/sha1`，不可用于密码或数字签名场景。",
                        remediation="改用 `crypto/sha256` 或 `golang.org/x/crypto/argon2`。",
                    )
                )
        return findings

    def _scan_java_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        has_xxe_guard = "disallow-doctype-decl" in content.lower() or "external-general-entities" in content.lower()
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")) or "openguard: ignore" in stripped.lower():
                continue
            if re.search(r"\bObjectInputStream\b|\.\s*readObject\s*\(", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-JAVA-001",
                        rule_name="Unsafe Java Native Deserialization (ObjectInputStream.readObject)",
                        cwe_id="CWE-502",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="使用 Java 原生反序列化 `ObjectInputStream.readObject()` 解析不可信字节流可能触发 Gadget Chain 远程代码执行。",
                        remediation="改用 JSON/Protobuf 等安全格式，或通过 `ObjectInputFilter` / `resolveClass` 严格白名单限制反序列化类。",
                    )
                )
            if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-JAVA-002",
                        rule_name="Java OS Command Execution Risk (Runtime.exec)",
                        cwe_id="CWE-78",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="调用 `Runtime.getRuntime().exec()` 执行系统命令，若拼接外部输入易导致命令注入。",
                        remediation="改用 `ProcessBuilder` 并以参数数组传参，同时对外部参数做严格白名单校验。",
                    )
                )
            if not has_xxe_guard and re.search(r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-JAVA-003",
                        rule_name="Java XML External Entity Injection Risk (XXE)",
                        cwe_id="CWE-611",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="创建 XML 解析器实例未禁用外部实体/DTD (`disallow-doctype-decl`)，存在 XXE 文件读取与 SSRF 风险。",
                        remediation="显式调用 `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)` 禁用 DTD。",
                    )
                )
        return findings

    def _scan_cpp_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")) or "openguard: ignore" in stripped.lower():
                continue
            m_buf = re.search(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", line)
            if m_buf:
                fn = m_buf.group(1)
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-CPP-001",
                        rule_name=f"C/C++ Unbounded Buffer Copy/Input ({fn})",
                        cwe_id="CWE-120",
                        severity=Severity.CRITICAL if fn == "gets" else Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description=f"调用无长度边界检查的 C/C++ 函数 `{fn}()`，极易触发栈/堆缓冲区溢出漏洞。",
                        remediation="替换为带显式缓冲区长度上限的安全版本：`fgets()`、`snprintf()`、`strncpy()` 或 `std::string`。",
                    )
                )
            if re.search(r"\b(?:std::)?(?:system|popen)\s*\(", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-CPP-002",
                        rule_name="C/C++ OS Shell Command Execution (system/popen)",
                        cwe_id="CWE-78",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="调用 `system()`/`popen()` 通过 Shell 执行命令，存在命令注入风险。",
                        remediation="使用 `execve()`/`posix_spawn()` 直接传递参数数组以隔离 Shell 解析。",
                    )
                )
        return findings

    def _scan_rust_patterns(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")) or "openguard: ignore" in stripped.lower():
                continue
            if re.search(r"\b(?:std::mem::|core::mem::|mem::)?transmute\b", line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-RS-001",
                        rule_name="Rust Unsafe Type Reinterpretation (mem::transmute)",
                        cwe_id="CWE-704",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="使用 `mem::transmute` 强行按位重解释类型，极易引发未定义行为 (UB) 与内存安全破坏。",
                        remediation="优先使用安全的 `From`/`Into`、`TryFrom`、`bytemuck` 或 `to_ne_bytes`/`from_ne_bytes` 转换。",
                    )
                )
            if re.search(r'Command::new\s*\(\s*"(?:sh|bash|cmd)"\s*\)', line):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-SAST-RS-002",
                        rule_name="Rust Shell Command Execution Risk",
                        cwe_id="CWE-78",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="通过 `Command::new(\"sh\"/\"bash\")` 调起 Shell 解释器执行命令，存在命令注入风险。",
                        remediation="直接将目标程序传入 `Command::new(bin).args([...])` 避免 Shell 解析。",
                    )
                )
            if re.search(r"\bunsafe\s*\{", line):
                prev_line = lines[idx - 2].strip() if idx >= 2 else ""
                if "SAFETY:" not in prev_line and "SAFETY:" not in line:
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-SAST-RS-003",
                            rule_name="Undocumented Rust unsafe Block (Missing // SAFETY: Invariant)",
                            cwe_id="CWE-119",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description="`unsafe { ... }` 块上方缺少 `// SAFETY:` 不变量说明（对标 `clippy::undocumented_unsafe_blocks`）。",
                            remediation="在 `unsafe` 块前补充 `// SAFETY: ...` 明确说明为何满足内存与生命周期不变量，或消除不必要的 `unsafe`。",
                        )
                    )
        return findings
