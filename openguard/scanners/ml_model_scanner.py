"""Protect AI ModelScan & Trail of Bits Fickling-inspired ML Model Supply-Chain Scanner.

Performs 100% safe, zero-execution static disassembly of Python Pickle & PyTorch ZIP model
checkpoints (`*.pkl`, `*.pickle`, `*.pt`, `*.pth`, `*.ckpt`, `*.joblib`, `*.bin`) using Python's
standard library `pickletools.genops()` (NEVER invokes `pickle.load()`).

Detects malicious Pickle VM opcodes (`GLOBAL`, `INST`, `STACK_GLOBAL`) referencing dangerous
execution gadgets (`os.system`, `posix.system`, `nt.system`, `subprocess.*`, `builtins.eval`,
`builtins.exec`, `builtins.__import__`, `socket.socket`, `urllib.request.urlopen`, `runpy.*`,
`operator.attrgetter`, etc.) and recommends migrating to `safetensors`.
"""

from __future__ import annotations

import os
import pickletools
import zipfile
from pathlib import Path
from typing import List, Optional, Set, Tuple

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity

ML_MODEL_EXTS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".bin"})
MAX_RAW_PICKLE_BYTES = 8 * 1024 * 1024  # 8 MB cap for standalone raw pickle streams
MAX_ZIP_PKL_ENTRY_BYTES = 4 * 1024 * 1024  # 4 MB cap per pickle member inside PyTorch ZIP

DANGEROUS_MODULES = frozenset({
    "os",
    "posix",
    "nt",
    "subprocess",
    "commands",
    "pty",
    "popen2",
    "runpy",
    "webbrowser",
    "httplib",
    "http.client",
    "ftplib",
    "telnetlib",
    "socket",
})

DANGEROUS_CALLABLES = frozenset({
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("builtins", "compile"),
    ("builtins", "getattr"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("__builtin__", "__import__"),
    ("__builtin__", "compile"),
    ("importlib", "import_module"),
    ("urllib.request", "urlopen"),
    ("urllib.request", "urlretrieve"),
    ("requests", "get"),
    ("requests", "post"),
    ("operator", "attrgetter"),
    ("ctypes", "CDLL"),
    ("marshal", "loads"),
    ("types", "FunctionType"),
    ("sys", "exit"),
})

_STRING_PUSH_OPCODES = frozenset({
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "STRING",
    "SHORT_BINSTRING",
    "BINSTRING",
})


def _is_dangerous_global(module: str, name: str) -> bool:
    mod = module.strip()
    fn = name.strip()
    if not mod:
        return False
    if mod in DANGEROUS_MODULES:
        return True
    if (mod, fn) in DANGEROUS_CALLABLES:
        return True
    if mod.startswith("subprocess.") or mod.startswith("os."):
        return True
    return False


def _looks_like_pickle_stream(data: bytes) -> bool:
    if len(data) < 2:
        return False
    # Pickle protocol 2..5 starts with PROTO (0x80) followed by protocol version 2..5
    if data[0] == 0x80 and data[1] in (2, 3, 4, 5):
        return True
    # Protocol 0 ASCII pickle often starts with GLOBAL ('c'), MARK ('('), DICT ('}'), LIST (']'), etc.
    if data[0:1] in (b"c", b"(", b"}", b"]", b"I", b"S", b"V") and b"." in data[-16:]:
        return True
    return False


def inspect_pickle_bytes(data: bytes) -> List[str]:
    """Safely disassemble a pickle byte stream via `pickletools.genops` and return dangerous globals."""
    if not _looks_like_pickle_stream(data):
        return []

    dangerous_hits: List[str] = []
    seen: Set[str] = set()
    str_stack: List[str] = []
    memo: dict[int, str] = {}
    memo_idx = 0

    try:
        for opcode, arg, _pos in pickletools.genops(data):
            opname = opcode.name
            if opname in _STRING_PUSH_OPCODES and isinstance(arg, (str, bytes)):
                val = arg.decode("utf-8", errors="replace") if isinstance(arg, bytes) else arg
                str_stack.append(val)
                if len(str_stack) > 64:
                    str_stack = str_stack[-32:]
            elif opname == "MEMOIZE" and str_stack:
                memo[memo_idx] = str_stack[-1]
                memo_idx += 1
            elif opname in ("PUT", "BINPUT", "LONG_BINPUT") and isinstance(arg, int) and str_stack:
                memo[arg] = str_stack[-1]
            elif opname in ("GET", "BINGET", "LONG_BINGET") and isinstance(arg, int) and arg in memo:
                str_stack.append(memo[arg])
                if len(str_stack) > 64:
                    str_stack = str_stack[-32:]
            elif opname in ("GLOBAL", "INST") and isinstance(arg, str):
                parts = arg.split(" ", 1)
                if len(parts) == 2:
                    mod, fn = parts[0], parts[1]
                    if _is_dangerous_global(mod, fn):
                        key = f"{mod}.{fn}"
                        if key not in seen:
                            seen.add(key)
                            dangerous_hits.append(key)
            elif opname == "STACK_GLOBAL":
                if len(str_stack) >= 2:
                    fn = str_stack.pop()
                    mod = str_stack.pop()
                    if _is_dangerous_global(mod, fn):
                        key = f"{mod}.{fn}"
                        if key not in seen:
                            seen.add(key)
                            dangerous_hits.append(key)
    except Exception:
        # Malformed or truncated non-pickle binary stream; safely return any hits decoded so far
        pass

    return dangerous_hits


class MLModelScanner:
    """Static zero-execution scanner for Pickle & PyTorch ML model weight serialization attacks."""

    def scan_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[CodeSecurityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            return self.scan_file(root, root.parent)

        # Strip *.bin from default binary excludes so PyTorch pytorch_model.bin checkpoints are scanned
        raw_excludes = [p for p in (exclude_patterns or []) if p.lower() != "*.bin"]
        findings: List[CodeSecurityFinding] = []

        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in DEFAULT_EXCLUDE_DIRS
                and not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", raw_excludes)
            ]
            for fname in sorted(filenames):
                ext = Path(fname).suffix.lower()
                if ext not in ML_MODEL_EXTS:
                    continue
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root).as_posix()
                if is_path_excluded(rel, raw_excludes):
                    continue
                findings.extend(self.scan_file(fpath, root))
        return findings

    def scan_file(self, fpath: Path, root: Path) -> List[CodeSecurityFinding]:
        try:
            with fpath.open("rb") as fh:
                magic = fh.read(4)
        except OSError:
            return []

        rel = fpath.resolve().relative_to(root.resolve()).as_posix()
        hits: List[Tuple[str, List[str]]] = []

        # 1. ZIP-packaged PyTorch / TorchScript checkpoint (magic PK\x03\x04)
        if magic.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(fpath, "r") as zf:
                    for info in zf.infolist():
                        if info.is_dir() or info.file_size > MAX_ZIP_PKL_ENTRY_BYTES:
                            continue
                        low_name = info.filename.lower()
                        if low_name.endswith((".pkl", ".pickle")) or low_name.endswith("/data.pkl") or low_name == "data.pkl":
                            member_hits = inspect_pickle_bytes(zf.read(info))
                            if member_hits:
                                hits.append((info.filename, member_hits))
            except Exception:
                return []
        else:
            # 2. Standalone raw Pickle stream (skip plain-text Python site `.pth` files handled by InstallScriptScanner)
            try:
                if fpath.stat().st_size > MAX_RAW_PICKLE_BYTES:
                    return []
                raw = fpath.read_bytes()
            except OSError:
                return []
            if fpath.suffix.lower() == ".pth" and not (len(raw) >= 2 and raw[0] == 0x80 and raw[1] in (2, 3, 4, 5)):
                return []
            raw_hits = inspect_pickle_bytes(raw)
            if raw_hits:
                hits.append((fpath.name, raw_hits))

        if not hits:
            return []

        all_gadgets: List[str] = []
        members: List[str] = []
        for member_name, gadgets in hits:
            members.append(member_name)
            for g in gadgets:
                if g not in all_gadgets:
                    all_gadgets.append(g)

        return [
            CodeSecurityFinding(
                rule_id="OG-ML-001",
                rule_name="Malicious Pickle Execution Payload in ML Model Checkpoint",
                cwe_id="CWE-502",
                severity=Severity.CRITICAL,
                file_path=rel,
                line_number=1,
                snippet=f"Opcodes: {', '.join(all_gadgets[:6])}",
                description=(
                    f"AI/ML 模型权重文件 `{rel}`（条目: {', '.join(members[:3])}）包含高危 Pickle VM 执行指令："
                    f"`{', '.join(all_gadgets[:6])}`，调用 `torch.load()` / `pickle.load()` 将直接触发任意代码执行 (RCE)（对标 ModelScan / Fickling）。"
                ),
                remediation="严禁直接加载不可信 Pickle/PyTorch 权重！请改用无代码执行能力的 `safetensors` 格式，或在无网络隔离沙箱中转换验证。",
            )
        ]
