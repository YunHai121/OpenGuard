"""AST and lexical context analyzers to drastically reduce secret-scanning false positives."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


SUPPRESSION_MARKERS = (
    "openguard: ignore",
    "openguard:ignore",
    "nosec",
    "pragma: allowlist secret",
    "gitleaks:allow",
)

TEST_PATH_HINTS = (
    "/test/",
    "/tests/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/mock/",
    "/mocks/",
    "/fixture/",
    "/fixtures/",
    "/benchmark/",
    "/benchmarks/",
)

DOC_PATH_HINTS = (
    "/docs/",
    "/doc/",
    "readme",
    "changelog",
    "contributing",
    ".md",
    ".rst",
)

ASSIGN_LEFT_RE = re.compile(r"^\s*(?:export\s+|const\s+|let\s+|var\s+|final\s+)?[\"']?([A-Za-z_][A-Za-z0-9_.\-]*)[\"']?\s*[:=]")


@dataclass
class CodeLineContext:
    """Semantic metadata for a single line of source code."""

    in_comment: bool = False
    in_docstring: bool = False
    in_test_scope: bool = False
    is_test_file: bool = False
    is_doc_file: bool = False
    is_regex_definition: bool = False
    is_env_lookup: bool = False
    is_type_annotation: bool = False
    inline_suppressed: bool = False
    assigned_var: Optional[str] = None
    call_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @property
    def summary_label(self) -> str:
        if self.tags:
            return ",".join(self.tags[:3])
        if self.assigned_var:
            return f"assign:{self.assigned_var}"
        return "generic"


def _is_test_path(file_path: str) -> bool:
    norm = "/" + file_path.replace("\\", "/").lower()
    fname = norm.rsplit("/", 1)[-1]
    if any(hint in norm for hint in TEST_PATH_HINTS):
        return True
    return fname.startswith("test_") or fname.endswith("_test.py") or ".test." in fname or ".spec." in fname


def _is_doc_path(file_path: str) -> bool:
    norm = "/" + file_path.replace("\\", "/").lower()
    return any(hint in norm for hint in DOC_PATH_HINTS)


def analyze_python_source(content: str, file_path: str = "") -> Dict[int, CodeLineContext]:
    """Use Python's stdlib `ast` module to annotate every relevant source line with semantic context."""
    contexts: Dict[int, CodeLineContext] = {}
    lines = content.splitlines()
    is_test_file = _is_test_path(file_path)
    is_doc_file = _is_doc_path(file_path)

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        lower = stripped.lower()
        ctx = CodeLineContext(
            in_comment=stripped.startswith("#"),
            is_test_file=is_test_file,
            is_doc_file=is_doc_file,
            inline_suppressed=any(marker in lower for marker in SUPPRESSION_MARKERS),
        )
        if ctx.in_comment:
            ctx.tags.append("comment")
        if is_test_file:
            ctx.tags.append("test_file")
        contexts[idx] = ctx

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return contexts

    def mark_docstring(node: ast.AST) -> None:
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                start = getattr(body[0], "lineno", 0)
                end = getattr(body[0], "end_lineno", start) or start
                for ln in range(start, end + 1):
                    if ln in contexts:
                        contexts[ln].in_docstring = True
                        if "docstring" not in contexts[ln].tags:
                            contexts[ln].tags.append("docstring")

    class _Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.in_test_depth = 0

        def visit_Module(self, node: ast.Module) -> None:
            mark_docstring(node)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            mark_docstring(node)
            entered = node.name.startswith("Test")
            if entered:
                self.in_test_depth += 1
            self.generic_visit(node)
            if entered:
                self.in_test_depth -= 1

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_func(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_func(node)

        def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            mark_docstring(node)
            entered = node.name.startswith("test_")
            if entered:
                self.in_test_depth += 1
            if self.in_test_depth > 0:
                start = node.lineno
                end = node.end_lineno or start
                for ln in range(start, end + 1):
                    if ln in contexts:
                        contexts[ln].in_test_scope = True
                        if "test_func" not in contexts[ln].tags:
                            contexts[ln].tags.append("test_func")
            self.generic_visit(node)
            if entered:
                self.in_test_depth -= 1

        def visit_Assign(self, node: ast.Assign) -> None:
            target_names = []
            for t in node.targets:
                if isinstance(t, ast.Name):
                    target_names.append(t.id)
                elif isinstance(t, ast.Attribute):
                    target_names.append(t.attr)
            var_name = target_names[0] if target_names else None
            start = node.lineno
            end = node.end_lineno or start
            for ln in range(start, end + 1):
                if ln in contexts and var_name:
                    contexts[ln].assigned_var = var_name
                    if "assign" not in contexts[ln].tags:
                        contexts[ln].tags.append(f"assign:{var_name}")
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            var_name = node.target.id if isinstance(node.target, ast.Name) else None
            ln = node.lineno
            if ln in contexts:
                contexts[ln].is_type_annotation = True
                if var_name:
                    contexts[ln].assigned_var = var_name
                    contexts[ln].tags.append(f"assign:{var_name}")
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                parent = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                func_name = f"{parent}.{node.func.attr}" if parent else node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            start = node.lineno
            end = node.end_lineno or start
            for ln in range(start, end + 1):
                if ln in contexts and func_name:
                    contexts[ln].call_name = func_name
                    if func_name in ("re.compile", "re.match", "re.search", "re.findall", "re.sub", "SecretRule"):
                        contexts[ln].is_regex_definition = True
                        if "regex_def" not in contexts[ln].tags:
                            contexts[ln].tags.append("regex_def")
                    if func_name in ("os.getenv", "os.environ.get", "getenv"):
                        contexts[ln].is_env_lookup = True
                        if "env_lookup" not in contexts[ln].tags:
                            contexts[ln].tags.append("env_lookup")
            self.generic_visit(node)

    _Visitor().visit(tree)
    return contexts


def analyze_generic_context(file_path: str, lines: List[str], line_idx_0: int) -> CodeLineContext:
    """Lightweight semantic & lexical context analysis for non-Python source/config files."""
    line = lines[line_idx_0] if 0 <= line_idx_0 < len(lines) else ""
    stripped = line.strip()
    lower = stripped.lower()

    is_comment = (
        stripped.startswith("//")
        or stripped.startswith("#")
        or stripped.startswith("/*")
        or stripped.startswith("* ")
        or stripped.startswith("--")
        or stripped.startswith("<!--")
    )
    is_test_file = _is_test_path(file_path)
    is_doc_file = _is_doc_path(file_path)
    is_regex = any(tok in lower for tok in ("new regexp(", "regexp(", "re.compile(", "pattern:", "regex:"))
    is_env = any(tok in lower for tok in ("process.env.", "os.getenv(", "os.environ"))
    inline_suppressed = any(marker in lower for marker in SUPPRESSION_MARKERS)

    assigned_var: Optional[str] = None
    m = ASSIGN_LEFT_RE.match(line)
    if m:
        assigned_var = m.group(1)

    tags: List[str] = []
    if is_comment:
        tags.append("comment")
    if is_test_file:
        tags.append("test_file")
    if is_doc_file:
        tags.append("doc_file")
    if is_regex:
        tags.append("regex_def")
    if is_env:
        tags.append("env_lookup")
    if assigned_var:
        tags.append(f"assign:{assigned_var}")

    return CodeLineContext(
        in_comment=is_comment,
        in_test_scope=is_test_file,
        is_test_file=is_test_file,
        is_doc_file=is_doc_file,
        is_regex_definition=is_regex,
        is_env_lookup=is_env,
        inline_suppressed=inline_suppressed,
        assigned_var=assigned_var,
        tags=tags,
    )
