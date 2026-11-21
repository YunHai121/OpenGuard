"""AI Supply-Chain Security Scanner: Rules-File Backdoors, Hidden Unicode Smuggling & MCP Config Poisoning.

Defends against 2025-2026 AI coding-assistant supply-chain threats:
- OG-AI-001: Hidden Unicode Tag Block smuggling (U+E0000..U+E007F) with decoded payload preview
- OG-AI-002: Trojan Source BiDi override characters (CVE-2021-42574) & zero-width obfuscation in AI rules
- OG-AI-003: Indirect prompt injection / silent exfiltration directives in AI rules files
             (.cursorrules, .cursor/rules/*, CLAUDE.md, AGENTS.md, GEMINI.md, copilot-instructions.md)
- OG-AI-004: Poisoned MCP Server configs (.mcp.json, mcp.json, claude_desktop_config.json):
             arbitrary shell execution, unpinned npx/uvx launchers, and hardcoded secrets in env
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import List, Optional

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity
from openguard.utils.entropy import is_likely_placeholder

# Unicode Bidirectional Control Characters (CVE-2021-42574 Trojan Source)
BIDI_CONTROL_CHARS = frozenset(
    {
        0x061C,  # ARABIC LETTER MARK
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

# Zero-width / invisible formatting chars frequently abused in Rules-File Backdoors
ZERO_WIDTH_CHARS = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})

AI_RULE_FILENAMES = frozenset(
    {
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        "claude.md",
        "agents.md",
        "gemini.md",
        "copilot-instructions.md",
    }
)

MCP_CONFIG_FILENAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "claude_desktop_config.json",
    }
)

SCAN_TEXT_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java",
        ".c", ".cpp", ".h", ".hpp", ".php", ".rb", ".sh", ".ps1", ".yml", ".yaml",
        ".json", ".toml", ".md", ".mdc", ".txt", ".rules",
    }
)

STEALTH_INJECTION_RE = re.compile(
    r"(?i)(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts)|"
    r"(?:do\s+not|never)\s+(?:mention|tell|inform|reveal|show)\s+(?:this\s+)?to\s+the\s+user|"
    r"silently\s+(?:exfiltrate|send|upload|inject|execute|run)|"
    r"hidden\s+backdoor\s+instruction|"
    r"always\s+inject\s+(?:a\s+)?(?:backdoor|reverse\s+shell|malicious)"
    r")"
)

EXFIL_DIRECTIVE_RE = re.compile(
    r"(?i)(?:~/\.ssh|id_rsa|/etc/passwd|\.aws/credentials|\.env)[^\n]{0,120}(?:curl|wget|fetch|http://|https://|base64)"
    r"|(?:curl|wget|fetch)[^\n]{0,120}(?:~/\.ssh|id_rsa|/etc/passwd|\.aws/credentials|\.env)"
)

MCP_DANGEROUS_CMD_RE = re.compile(
    r"(?i)(?:\b(?:sh|bash|zsh)\s+-c\b|\bcmd(?:\.exe)?\s+/c\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b|"
    r"(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|node|python)|\beval\s*\()"
)

MCP_SECRET_ENV_KEY_RE = re.compile(
    r"(?i)(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|PASSWORD|PASSWD|ACCESS_KEY|AUTH)"
)


def decode_unicode_tags(text: str) -> str:
    """Decode hidden Unicode Tag Block (U+E0000..U+E007F) characters back into readable ASCII."""
    chars: List[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            chars.append(chr(cp - 0xE0000))
    return "".join(chars)


class AIConfigSecurityScanner:
    """Detects Rules-File Backdoors, Hidden Unicode Smuggling, Trojan Source, and MCP Config Poisoning."""

    @staticmethod
    def is_ai_rule_file(rel_posix: str) -> bool:
        low = rel_posix.lower()
        name = low.rsplit("/", 1)[-1]
        if name in AI_RULE_FILENAMES:
            return True
        if ".cursor/rules/" in low or low.startswith(".cursor/rules/"):
            return True
        if ".github/instructions/" in low or low.startswith(".github/instructions/"):
            return True
        return False

    @staticmethod
    def is_mcp_config_file(rel_posix: str) -> bool:
        low = rel_posix.lower()
        name = low.rsplit("/", 1)[-1]
        return name in MCP_CONFIG_FILENAMES

    def scan_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[CodeSecurityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            return self.scan_file(root, root.parent)

        excludes = exclude_patterns or []
        findings: List[CodeSecurityFinding] = []

        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in DEFAULT_EXCLUDE_DIRS
                and not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", excludes)
            ]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root).as_posix()
                if is_path_excluded(rel, excludes):
                    continue
                if (
                    self.is_ai_rule_file(rel)
                    or self.is_mcp_config_file(rel)
                    or fpath.suffix.lower() in SCAN_TEXT_EXTENSIONS
                ):
                    try:
                        if fpath.stat().st_size > 1024 * 1024:
                            continue
                    except OSError:
                        continue
                    findings.extend(self.scan_file(fpath, root))

        return findings

    def scan_file(self, fpath: Path, root: Path) -> List[CodeSecurityFinding]:
        try:
            raw_bytes = fpath.read_bytes()
        except OSError:
            return []
        if b"\x00" in raw_bytes[:4096]:
            return []
        content = raw_bytes.decode("utf-8", errors="replace")
        rel = fpath.resolve().relative_to(root.resolve()).as_posix()
        return self.scan_content(content, rel)

    def scan_content(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        is_rule = self.is_ai_rule_file(rel)
        is_mcp = self.is_mcp_config_file(rel)

        # Strip optional leading UTF-8 BOM only at file offset 0
        lines = content.splitlines()
        tag_reported = False
        bidi_reported = False

        for idx, line in enumerate(lines, start=1):
            if "openguard: ignore" in line.lower():
                continue

            # 1. OG-AI-001: Unicode Tag Block smuggling (U+E0000..U+E007F)
            tag_chars = [ch for ch in line if 0xE0000 <= ord(ch) <= 0xE007F]
            if tag_chars and not tag_reported:
                tag_reported = True
                decoded = decode_unicode_tags(line)[:120]
                preview = f" 解码载荷预览: `{decoded}`" if decoded else ""
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-AI-001",
                        rule_name="Hidden Unicode Tag Smuggling (Invisible Prompt Injection)",
                        cwe_id="CWE-94",
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=idx,
                        snippet=f"[发现 {len(tag_chars)} 个不可见 Unicode Tag 字符 U+E0000..U+E007F]",
                        description=f"文件包含不可见 Unicode Tags 隐写字节（Rules-File Backdoor / ASCII Smuggling），人工审查不可见但会被 AI 编程助手解析执行。{preview}",
                        remediation="立即删除所有 U+E0000–U+E007F 不可见字符并审查该文件的 Git 提交来源。",
                    )
                )

            # 2. OG-AI-002: Trojan Source BiDi override characters (CVE-2021-42574)
            bidi_hits = [f"U+{ord(ch):04X}" for ch in line if ord(ch) in BIDI_CONTROL_CHARS]
            if bidi_hits and not bidi_reported:
                bidi_reported = True
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-AI-002",
                        rule_name="Trojan Source Bidirectional Unicode Override (CVE-2021-42574)",
                        cwe_id="CWE-1007",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=f"[BiDi 控制字符: {', '.join(bidi_hits[:6])}]",
                        description="检测到 Unicode 双向文本控制字符（Trojan Source），可使代码或规则在编辑器中的视觉顺序与实际编译/解析逻辑完全相反。",
                        remediation="移除所有双向控制字符，在 CI/pre-commit 中启用 OpenGuard 拦截不可见控制字符。",
                    )
                )

            # Zero-width obfuscation cluster inside AI rule files
            if is_rule:
                check_line = line[1:] if (idx == 1 and line.startswith("\ufeff")) else line
                zw_count = sum(1 for ch in check_line if ord(ch) in ZERO_WIDTH_CHARS)
                if zw_count >= 4 and not bidi_reported:
                    bidi_reported = True
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-AI-002",
                            rule_name="Zero-Width Character Obfuscation in AI Rules File",
                            cwe_id="CWE-1007",
                            severity=Severity.HIGH,
                            file_path=rel,
                            line_number=idx,
                            snippet=f"[AI 规则文件单行含 {zw_count} 个零宽隐蔽字符]",
                            description=f"AI 助手指令文件 `{rel}` 中存在异常密集的零宽字符（U+200B/200C/200D/FEFF），疑似隐藏注入指令。",
                            remediation="以纯可见 ASCII/UTF-8 重写该规则文件并剔除全部零宽控制符。",
                        )
                    )

            # 3. OG-AI-003: Rules-File Indirect Prompt Injection / Exfiltration Directives
            if is_rule:
                if STEALTH_INJECTION_RE.search(line) or EXFIL_DIRECTIVE_RE.search(line):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-AI-003",
                            rule_name="AI Rules-File Backdoor / Indirect Prompt Injection",
                            cwe_id="CWE-77",
                            severity=Severity.HIGH,
                            file_path=rel,
                            line_number=idx,
                            snippet=line.strip()[:180],
                            description=f"AI 规则文件 `{rel}` 包含隐蔽覆盖系统指令、对用户隐瞒操作或窃取敏感文件（`.env`/`~/.ssh`）的投毒指令。",
                            remediation="立即审计并清除该规则文件中的恶意提示词，防止 Cursor/Claude/Copilot 在打开项目时被劫持。",
                        )
                    )

        # 4. OG-AI-004: MCP Server Configuration Poisoning
        if is_mcp:
            findings.extend(self._scan_mcp_config(content, rel))

        return findings

    def _scan_mcp_config(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        try:
            data = json.loads(content)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []

        servers = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers, dict):
            return []

        findings: List[CodeSecurityFinding] = []
        lines = content.splitlines()

        def find_line(needle: str) -> int:
            for idx, ln in enumerate(lines, start=1):
                if needle in ln:
                    return idx
            return 1

        for srv_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command") or "")
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            full_cmd = " ".join([cmd, *[str(a) for a in args]]).strip()
            ln = find_line(f'"{srv_name}"')

            # 4a. Arbitrary shell / piped remote execution in MCP launcher
            if full_cmd and MCP_DANGEROUS_CMD_RE.search(full_cmd):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-AI-004",
                        rule_name="Dangerous Shell/Remote Execution in MCP Server Config",
                        cwe_id="CWE-78",
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=ln,
                        snippet=f"{srv_name}: {full_cmd[:140]}",
                        description=f"MCP 服务 `{srv_name}` 配置了危险 Shell 解释器或管道远程执行命令，打开仓库时可触发宿主机任意代码执行。",
                        remediation="禁止在共享 MCP 配置中使用 `sh -c`/`curl | sh`/`powershell -e`，改用受控本地可执行文件。",
                    )
                )

            # 4b. Unpinned `npx -y <pkg>` or `uvx <pkg>` auto-download without version pin
            cmd_low = cmd.lower()
            if cmd_low in ("npx", "uvx", "bunx"):
                pkg_args = [str(a) for a in args if not str(a).startswith("-")]
                if pkg_args:
                    pkg = pkg_args[0]
                    # Version pinned if `@1.2.3` (after optional scope) or `==1.2.3`
                    body = pkg[1:] if pkg.startswith("@") else pkg
                    is_pinned = ("@" in body and not body.endswith("@latest")) or ("==" in body)
                    if not is_pinned:
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-AI-004",
                                rule_name="Unpinned Remote Package in MCP STDIO Config (Rug-Pull Risk)",
                                cwe_id="CWE-829",
                                severity=Severity.MEDIUM,
                                file_path=rel,
                                line_number=ln,
                                snippet=f"{srv_name}: {full_cmd[:140]}",
                                description=f"MCP 服务 `{srv_name}` 通过 `{cmd}` 自动拉取未锁定版本的远端包 `{pkg}`，存在 Rug-Pull 投毒风险。",
                                remediation=f"将 `{pkg}` 锁定到已审计的精确语义化版本（如 `{pkg}@1.2.3`）。",
                            )
                        )

            # 4c. Hardcoded secrets in MCP `env` block
            env_block = cfg.get("env")
            if isinstance(env_block, dict):
                for ek, ev in env_block.items():
                    if not isinstance(ev, str) or not ev.strip():
                        continue
                    if ev.strip().startswith(("$", "${", "{{")):
                        continue
                    if MCP_SECRET_ENV_KEY_RE.search(str(ek)):
                        is_ph, _ = is_likely_placeholder(ev)
                        if not is_ph and len(ev.strip()) >= 12:
                            findings.append(
                                CodeSecurityFinding(
                                    rule_id="OG-AI-004",
                                    rule_name="Hardcoded Credential in MCP Server env Block",
                                    cwe_id="CWE-798",
                                    severity=Severity.HIGH,
                                    file_path=rel,
                                    line_number=find_line(f'"{ek}"'),
                                    snippet=f"{srv_name}.env.{ek}=****",
                                    description=f"MCP 配置 `{rel}` 中 `{srv_name}` 的 `env.{ek}` 硬编码了明文凭据。",
                                    remediation="改用 `${ENV_VAR}` 占位引用或系统密钥环注入，切勿将凭据提交至仓库 MCP 配置文件。",
                                )
                            )

        return findings
