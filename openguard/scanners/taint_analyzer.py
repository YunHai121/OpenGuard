"""Semgrep-Taint-inspired Intra-Procedural Python AST Taint Tracking Analyzer.

Tracks untrusted external input (HTTP request params, argv, stdin) across variable
assignments, f-strings, concatenations, and path joins within each function/module scope,
respecting common sanitizers (int/float/shlex.quote/os.path.basename/is_relative_to),
and flags flows into SQLi, Command Injection, SSRF, and Path Traversal sinks.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from openguard.models import CodeSecurityFinding, Severity

# Untrusted external data source prefixes / calls
TAINT_SOURCE_ATTR_ROOTS = {
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.data",
    "request.files",
    "request.query_params",
    "request.get",
    "request.post",
    "sys.argv",
}

TAINT_SOURCE_CALLS = {
    "input",
    "request.get_json",
    "request.get_data",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.query_params.get",
}

# Sanitizers that neutralize string-based injection / traversal
SANITIZER_CALLS = {
    "int",
    "float",
    "bool",
    "shlex.quote",
    "os.path.basename",
    "posixpath.basename",
    "ntpath.basename",
    "html.escape",
    "markupsafe.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "uuid.uuid",
}

# Sink definitions: call_name -> (rule_id, rule_name, cwe_id, severity, remediation)
SSRF_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
}

CMD_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

PATH_SINKS = {
    "open",
    "send_file",
    "flask.send_file",
    "shutil.copy",
    "shutil.copyfile",
    "os.remove",
    "os.unlink",
}


def _resolve_name(node: ast.AST) -> str:
    """Resolve dotted attribute/name chain in lowercase."""
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        parts = [node.attr.lower()]
        cur = node.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr.lower())
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id.lower())
            return ".".join(reversed(parts))
    return ""


def _is_sanitizer_call(node: ast.Call) -> bool:
    name = _resolve_name(node.func)
    if name in SANITIZER_CALLS:
        return True
    tail = name.rsplit(".", 1)[-1]
    return tail.startswith(("sanitize_", "validate_", "escape_", "clean_"))


def _expr_taint_origin(
    node: Optional[ast.AST],
    tainted_vars: Dict[str, str],
) -> Optional[str]:
    """Return taint origin description if `node` evaluates to untrusted data, else None."""
    if node is None:
        return None

    # Sanitizers clear taint
    if isinstance(node, ast.Call):
        if _is_sanitizer_call(node):
            return None
        call_name = _resolve_name(node.func)
        if call_name in TAINT_SOURCE_CALLS:
            return f"{call_name}()"
        for root in TAINT_SOURCE_ATTR_ROOTS:
            if call_name == root or call_name.startswith(root + "."):
                return f"{call_name}()"
        # Propagate through string / path helpers: str.format, os.path.join, .strip(), etc.
        if isinstance(node.func, ast.Attribute):
            base_taint = _expr_taint_origin(node.func.value, tainted_vars)
            if base_taint:
                return base_taint
        for arg in node.args:
            t = _expr_taint_origin(arg, tainted_vars)
            if t:
                return t
        for kw in node.keywords:
            t = _expr_taint_origin(kw.value, tainted_vars)
            if t:
                return t
        return None

    # Subscript: request.args["id"] or sys.argv[1] or tainted_dict["k"]
    if isinstance(node, ast.Subscript):
        base_name = _resolve_name(node.value)
        if base_name in TAINT_SOURCE_ATTR_ROOTS:
            return f"{base_name}[...]"
        return _expr_taint_origin(node.value, tainted_vars)

    # Attribute access: request.data or Path(x).name (sanitizer!)
    if isinstance(node, ast.Attribute):
        if node.attr == "name":
            return None
        full = _resolve_name(node)
        if full in TAINT_SOURCE_ATTR_ROOTS:
            return full
        return _expr_taint_origin(node.value, tainted_vars)

    # Variable reference
    if isinstance(node, ast.Name):
        return tainted_vars.get(node.id)

    # f-string / binary concat / format
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                t = _expr_taint_origin(val.value, tainted_vars)
                if t:
                    return t
        return None

    if isinstance(node, ast.BinOp):
        return _expr_taint_origin(node.left, tainted_vars) or _expr_taint_origin(node.right, tainted_vars)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            t = _expr_taint_origin(elt, tainted_vars)
            if t:
                return t
        return None

    if isinstance(node, ast.IfExp):
        return _expr_taint_origin(node.body, tainted_vars) or _expr_taint_origin(node.orelse, tainted_vars)

    return None


class PythonTaintAnalyzer:
    """Lightweight intraprocedural Python AST taint tracker for SQLi, RCE, SSRF, and Path Traversal."""

    def analyze(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        seen: Set[Tuple[int, str]] = set()

        # Analyze module top-level statements + each function/method body independently
        self._analyze_block(tree.body, {}, file_path, lines, findings, seen)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_block(node.body, {}, file_path, lines, findings, seen)

        return findings

    def _analyze_block(
        self,
        stmts: List[ast.stmt],
        tainted_vars: Dict[str, str],
        file_path: str,
        lines: List[str],
        findings: List[CodeSecurityFinding],
        seen: Set[Tuple[int, str]],
        path_guarded: bool = False,
    ) -> None:
        local_taint = dict(tainted_vars)

        for stmt in stmts:
            # Skip nested function defs in parent pass (analyzed in their own scope)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            # Detect path traversal guard (`is_relative_to` / `startswith`) in block
            stmt_src = ast.dump(stmt)
            if "is_relative_to" in stmt_src or "commonpath" in stmt_src:
                path_guarded = True

            # Handle assignments & annotated assignments
            if isinstance(stmt, ast.Assign):
                origin = _expr_taint_origin(stmt.value, local_taint)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if origin:
                            local_taint[target.id] = origin
                        else:
                            local_taint.pop(target.id, None)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                origin = _expr_taint_origin(stmt.value, local_taint) if stmt.value else None
                if origin:
                    local_taint[stmt.target.id] = origin
                else:
                    local_taint.pop(stmt.target.id, None)
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                origin = _expr_taint_origin(stmt.value, local_taint)
                if origin:
                    local_taint[stmt.target.id] = origin

            # Inspect all sink calls inside this statement (excluding nested bodies handled recursively)
            self._inspect_expr_sinks(stmt, local_taint, file_path, lines, findings, seen, path_guarded)

            # Recurse into control-flow sub-blocks
            for sub_attr in ("body", "orelse", "finalbody"):
                sub_stmts = getattr(stmt, sub_attr, None)
                if isinstance(sub_stmts, list) and sub_stmts and isinstance(sub_stmts[0], ast.stmt):
                    self._analyze_block(sub_stmts, local_taint, file_path, lines, findings, seen, path_guarded)
            if isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    self._analyze_block(handler.body, local_taint, file_path, lines, findings, seen, path_guarded)

    def _inspect_expr_sinks(
        self,
        stmt: ast.stmt,
        tainted_vars: Dict[str, str],
        file_path: str,
        lines: List[str],
        findings: List[CodeSecurityFinding],
        seen: Set[Tuple[int, str]],
        path_guarded: bool,
    ) -> None:
        # Walk expressions directly attached to stmt without re-walking compound sub-blocks
        expr_roots: List[ast.AST] = []
        for field, val in ast.iter_fields(stmt):
            if field in ("body", "orelse", "finalbody", "handlers"):
                continue
            if isinstance(val, ast.AST):
                expr_roots.append(val)
            elif isinstance(val, list):
                expr_roots.extend(v for v in val if isinstance(v, ast.AST))

        for root in expr_roots:
            for node in ast.walk(root):
                if not isinstance(node, ast.Call):
                    continue
                ln = getattr(node, "lineno", 1)
                snip = lines[ln - 1].strip()[:180] if 1 <= ln <= len(lines) else ""
                if "openguard: ignore" in snip.lower() or "nosec" in snip.lower():
                    continue

                call_name = _resolve_name(node.func)

                # 1. SQL Injection Sink: *.execute(tainted_query)
                if (call_name.endswith(".execute") or call_name.endswith(".executemany")) and node.args:
                    origin = _expr_taint_origin(node.args[0], tainted_vars)
                    if origin and (ln, "CWE-89") not in seen:
                        seen.add((ln, "CWE-89"))
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-TAINT-PY-001",
                                rule_name="Tainted SQL Injection via Dataflow Propagation",
                                cwe_id="CWE-89",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snip,
                                description=f"污点追踪发现外部输入 `{origin}` 经变量传播流入数据库查询 `{call_name}()`，存在 SQL 注入风险。",
                                remediation="使用参数化占位符查询 `cursor.execute('SELECT ... WHERE id = ?', (val,))`，严禁拼接外部输入。",
                            )
                        )

                # 2. Command Injection Sink: os.system / subprocess(..., shell=True) with tainted arg
                elif call_name in CMD_SINKS and node.args:
                    is_shell = call_name in ("os.system", "os.popen") or any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    if is_shell:
                        origin = _expr_taint_origin(node.args[0], tainted_vars)
                        if origin and (ln, "CWE-78") not in seen:
                            seen.add((ln, "CWE-78"))
                            findings.append(
                                CodeSecurityFinding(
                                    rule_id="OG-TAINT-PY-002",
                                    rule_name="Tainted OS Command Injection via Dataflow Propagation",
                                    cwe_id="CWE-78",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=ln,
                                    snippet=snip,
                                    description=f"污点追踪发现外部输入 `{origin}` 流入系统命令执行点 `{call_name}()`，存在远程命令执行 (RCE) 风险。",
                                    remediation="改用 `subprocess.run(['cmd', arg], shell=False)` 参数列表隔离，或使用 `shlex.quote()` 与严格白名单校验。",
                                )
                            )

                # 3. SSRF Sink: requests.get / httpx.get / urlopen with tainted URL
                elif call_name in SSRF_SINKS and (node.args or any(kw.arg == "url" for kw in node.keywords)):
                    url_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "url"), None)
                    origin = _expr_taint_origin(url_arg, tainted_vars)
                    if origin and (ln, "CWE-918") not in seen:
                        seen.add((ln, "CWE-918"))
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-TAINT-PY-003",
                                rule_name="Tainted Server-Side Request Forgery (SSRF)",
                                cwe_id="CWE-918",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snip,
                                description=f"污点追踪发现外部输入 `{origin}` 未经域名白名单校验直接流入出站网络请求 `{call_name}()`，存在 SSRF 内网探测/凭据窃取风险。",
                                remediation="校验目标 URL 协议（仅限 https）与域名白名单，并阻断 `127.0.0.0/8`、`169.254.169.254` 等内网元数据地址。",
                            )
                        )

                # 4. Path Traversal Sink: open(tainted_path) / send_file(tainted_path)
                elif not path_guarded and (
                    call_name in PATH_SINKS
                    or call_name.endswith((".read_text", ".read_bytes", ".write_text", ".write_bytes"))
                ):
                    target_arg = node.args[0] if (call_name in PATH_SINKS and node.args) else (
                        node.func.value if isinstance(node.func, ast.Attribute) else None
                    )
                    origin = _expr_taint_origin(target_arg, tainted_vars)
                    if origin and (ln, "CWE-22") not in seen:
                        seen.add((ln, "CWE-22"))
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-TAINT-PY-004",
                                rule_name="Tainted Path Traversal Risk",
                                cwe_id="CWE-22",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=ln,
                                snippet=snip,
                                description=f"污点追踪发现外部输入 `{origin}` 未经目录边界校验直接流入文件访问 `{call_name}()`，存在任意文件读写/目录穿越风险。",
                                remediation="使用 `os.path.basename()` 剥离目录部分，并在 `Path.resolve()` 后强制校验 `candidate.is_relative_to(safe_root)`。",
                            )
                        )
