"""Semgrep-JS / CodeQL-inspired JavaScript & TypeScript Cross-Statement Taint Analyzer.

Tracks untrusted Express / Next.js / Node.js inputs (`req.query`, `req.body`, `req.params`,
`req.headers`, `req.cookies`, `searchParams.get`, `process.argv`) across variable declarations,
object destructuring, template literals, and string/path operations while respecting standard
sanitizers (`DOMPurify.sanitize`, `Number`, `parseInt`, `path.basename`, `encodeURIComponent`).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from openguard.models import CodeSecurityFinding, Severity

JS_TAINT_SOURCE_RE = re.compile(
    r"\b(?:req\.(?:query|body|params|headers|cookies)|request\.(?:query|body|params|headers|cookies)|"
    r"searchParams\.get\s*\(|URLSearchParams\s*\(|process\.argv)\b"
)

JS_DESTRUCTURE_RE = re.compile(
    r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(?:req|request)\.(query|body|params|headers|cookies)\b"
)
JS_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$"
)

JS_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|encodeURIComponent|Number|parseInt|parseFloat|"
    r"path\.basename|validator\.escape|xss)\s*\("
)

JS_EXEC_SINK_RE = re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\((.+)\)")
JS_XSS_SINK_RE = re.compile(r"(?:\bres\.(?:send|end|write)\s*\((.+)\)|document\.write\s*\((.+)\)|\.innerHTML\s*=\s*(.+))")
JS_SSRF_SINK_RE = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|http\.get|https\.get|got)\s*\(([^,)]+)"
)
JS_PATH_SINK_RE = re.compile(
    r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|rm)\s*\(([^,)]+)"
)
JS_PROTO_POLLUTE_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*=")


class JSTaintAnalyzer:
    """Lightweight intraprocedural JavaScript/TypeScript taint analyzer for Express/Next.js/Node."""

    def analyze(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        seen: Set[Tuple[int, str]] = set()
        tainted: Dict[str, str] = {}
        path_guarded = False
        proto_guarded = False

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")) or "openguard: ignore" in stripped.lower():
                continue

            # Detect path traversal / prototype pollution guards in surrounding block
            if "startsWith(" in raw or "path.relative(" in raw:
                path_guarded = True
            if "__proto__" in raw and ("continue" in raw or "return" in raw or "throw" in raw or "!==" in raw):
                proto_guarded = True

            # 1. Track destructured taint sources: `const { id, url: targetUrl } = req.query`
            m_dest = JS_DESTRUCTURE_RE.search(raw)
            if m_dest:
                fields_raw, src_prop = m_dest.group(1), m_dest.group(2)
                for field in fields_raw.split(","):
                    part = field.strip().split("=", 1)[0].strip()
                    if not part:
                        continue
                    var_name = part.split(":", 1)[-1].strip()
                    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", var_name):
                        tainted[var_name] = f"req.{src_prop}.{part.split(':', 1)[0].strip()}"
                continue

            # 2. Track standard variable assignments & propagation
            m_assign = JS_ASSIGN_RE.match(raw)
            if m_assign:
                lhs, rhs = m_assign.group(1), m_assign.group(2)
                if not raw.lstrip().startswith(("return ", "throw ", "if ", "while ")):
                    origin = self._expr_taint_origin(rhs, tainted)
                    if origin:
                        tainted[lhs] = origin
                    elif lhs in tainted:
                        # Reassigned to sanitized/constant expression
                        tainted.pop(lhs, None)

            # 3. Inspect Sinks
            # 3a. Command Injection (CWE-78): child_process.exec(tainted)
            m_exec = JS_EXEC_SINK_RE.search(raw)
            if m_exec:
                origin = self._expr_taint_origin(m_exec.group(1), tainted)
                if origin and (idx, "CWE-78") not in seen:
                    seen.add((idx, "CWE-78"))
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-TAINT-JS-001",
                            rule_name="Tainted Node.js Command Injection (child_process.exec)",
                            cwe_id="CWE-78",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=f"污点追踪发现外部输入 `{origin}` 流入 `child_process.exec/execSync()`，存在远程命令执行 (RCE) 风险。",
                            remediation="改用 `execFile(bin, [arg1, arg2])` 或 `spawn` 数组传参并关闭 `shell: true`。",
                        )
                    )

            # 3b. Reflected / DOM XSS (CWE-79): res.send(tainted) / innerHTML = tainted
            m_xss = JS_XSS_SINK_RE.search(raw)
            if m_xss:
                expr = next((g for g in m_xss.groups() if g is not None), "")
                origin = self._expr_taint_origin(expr, tainted)
                if origin and (idx, "CWE-79") not in seen:
                    seen.add((idx, "CWE-79"))
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-TAINT-JS-002",
                            rule_name="Tainted Cross-Site Scripting (XSS) via Dataflow",
                            cwe_id="CWE-79",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=f"污点追踪发现外部输入 `{origin}` 未经转义或净化直接输出到 HTML/响应体，存在 XSS 注入风险。",
                            remediation="使用 `DOMPurify.sanitize()` / `escapeHtml()` 净化 HTML，或使用 `res.json()` 返回结构化数据。",
                        )
                    )

            # 3c. SSRF (CWE-918): fetch(tainted) / axios.get(tainted)
            m_ssrf = JS_SSRF_SINK_RE.search(raw)
            if m_ssrf:
                origin = self._expr_taint_origin(m_ssrf.group(1), tainted)
                if origin and (idx, "CWE-918") not in seen:
                    seen.add((idx, "CWE-918"))
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-TAINT-JS-003",
                            rule_name="Tainted Node.js/JS Server-Side Request Forgery (SSRF)",
                            cwe_id="CWE-918",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=f"污点追踪发现外部输入 `{origin}` 未经域名白名单校验直接作为出站请求 URL，存在 SSRF 风险。",
                            remediation="使用 `new URL()` 严格校验协议与白名单主机名，并拦截内网/回环 IP 地址。",
                        )
                    )

            # 3d. Path Traversal (CWE-22): fs.readFile(tainted)
            m_path = JS_PATH_SINK_RE.search(raw)
            if m_path and not path_guarded:
                origin = self._expr_taint_origin(m_path.group(1), tainted)
                if origin and (idx, "CWE-22") not in seen:
                    seen.add((idx, "CWE-22"))
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-TAINT-JS-004",
                            rule_name="Tainted Node.js Path Traversal (fs File Access)",
                            cwe_id="CWE-22",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=f"污点追踪发现外部输入 `{origin}` 未经路径边界检查流入 `fs` 文件操作，存在目录穿越风险。",
                            remediation="使用 `path.basename()` 剥离路径并在 `path.resolve()` 后校验 `resolved.startsWith(safeRoot)`。",
                        )
                    )

            # 3e. Prototype Pollution (CWE-1321): target[taintedKey] = ...
            m_proto = JS_PROTO_POLLUTE_RE.search(raw)
            if m_proto and not proto_guarded:
                key_var = m_proto.group(2)
                if key_var in tainted and (idx, "CWE-1321") not in seen:
                    seen.add((idx, "CWE-1321"))
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-TAINT-JS-005",
                            rule_name="Tainted Prototype Pollution via Dynamic Property Key",
                            cwe_id="CWE-1321",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped[:180],
                            description=f"动态属性写入键 `{key_var}` 来自外部输入 `{tainted[key_var]}` 且缺少 `__proto__`/`constructor`/`prototype` 过滤，存在原型链污染风险。",
                            remediation="改用 `Map` / `Object.create(null)`，或在写入前显式拒绝 `__proto__`、`constructor`、`prototype`。",
                        )
                    )

        return findings

    @staticmethod
    def _expr_taint_origin(expr: str, tainted: Dict[str, str]) -> Optional[str]:
        if not expr or JS_SANITIZER_RE.search(expr):
            return None
        m_src = JS_TAINT_SOURCE_RE.search(expr)
        if m_src:
            return m_src.group(0)
        for var_name, origin in tainted.items():
            if re.search(rf"\b{re.escape(var_name)}\b", expr):
                return origin
        return None
