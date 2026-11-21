"""Trivy & Hadolint-inspired Dockerfile static security & supply-chain scanner."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity
from openguard.utils.entropy import is_likely_placeholder

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", re.I)
USER_RE = re.compile(r"^\s*USER\s+([^\s#]+)", re.I)
ADD_URL_RE = re.compile(r"^\s*ADD\s+(?:--\S+\s+)*https?://", re.I)
ENV_SECRET_RE = re.compile(
    r"^\s*(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*)\s*(?:=|\s+)\s*['\"]?([^'\"\s#]+)['\"]?",
    re.I,
)
PIPE_SHELL_RE = re.compile(r"(?:curl|wget)\s+[^|\n]*\|\s*(?:sh|bash|zsh|python)\b", re.I)


class DockerfileScanner:
    """Scans Dockerfile manifests for container supply-chain and privilege misconfigurations."""

    @staticmethod
    def is_dockerfile(filename: str) -> bool:
        low = filename.lower()
        return low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile")

    def scan_repository(
        self,
        root_path: Path,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[CodeSecurityFinding]:
        root = Path(root_path).resolve()
        if root.is_file():
            if self.is_dockerfile(root.name):
                return self.scan_file(root, root.parent)
            return []

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
                if not self.is_dockerfile(fname):
                    continue
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root).as_posix()
                if not is_path_excluded(rel, excludes):
                    findings.extend(self.scan_file(fpath, root))
        return findings

    def scan_file(self, fpath: Path, root: Path) -> List[CodeSecurityFinding]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        rel = fpath.resolve().relative_to(root.resolve()).as_posix()
        return self.scan_content(content, rel)

    def scan_content(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        last_user: Optional[str] = None
        last_user_line: int = 1
        has_from = False
        first_from_line = 1

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "openguard: ignore" in stripped.lower():
                continue

            # 1. FROM unpinned / :latest
            m_from = FROM_RE.match(raw)
            if m_from:
                if not has_from:
                    has_from = True
                    first_from_line = idx
                img = m_from.group(1)
                if img.lower() != "scratch" and not img.startswith("$"):
                    if "@sha256:" not in img:
                        if ":" not in img or img.lower().endswith(":latest"):
                            findings.append(
                                CodeSecurityFinding(
                                    rule_id="OG-DOCKER-001",
                                    rule_name="Unpinned or :latest Container Base Image",
                                    cwe_id="CWE-1104",
                                    severity=Severity.MEDIUM,
                                    file_path=rel,
                                    line_number=idx,
                                    snippet=stripped[:180],
                                    description=f"基础镜像 `{img}` 未锁定具体版本或使用了 `:latest`，存在构建漂移与上游镜像投毒风险。",
                                    remediation="将基础镜像锁定到明确语义化版本或不可变摘要（如 `python:3.11.10-slim@sha256:...`）。",
                                )
                            )

            # 2. USER tracking
            m_user = USER_RE.match(raw)
            if m_user:
                last_user = m_user.group(1).strip().lower()
                last_user_line = idx

            # 3. RUN curl | sh
            if PIPE_SHELL_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-DOCKER-003",
                        rule_name="Unverified Remote Script Pipe-to-Shell in Dockerfile",
                        cwe_id="CWE-829",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="Dockerfile 构建阶段直接将远程脚本管道输入 Shell 执行，缺少完整性校验。",
                        remediation="先下载并校验 SHA256 后执行，或通过锁定版本的系统包管理器安装。",
                    )
                )

            # 4. ENV / ARG hardcoded secret
            m_sec = ENV_SECRET_RE.match(raw)
            if m_sec:
                var_name, val = m_sec.group(1), m_sec.group(2)
                is_ph, _ = is_likely_placeholder(val)
                if not val.startswith("$") and not is_ph:
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-DOCKER-004",
                            rule_name="Hardcoded Secret in Dockerfile ENV/ARG",
                            cwe_id="CWE-798",
                            severity=Severity.CRITICAL,
                            file_path=rel,
                            line_number=idx,
                            snippet=f"{var_name}=****",
                            description=f"Dockerfile 通过 ENV/ARG 硬编码敏感变量 `{var_name}`，该凭据会永久固化在容器镜像层历史 (`docker history`) 中。",
                            remediation="使用 Docker BuildKit `--mount=type=secret` 或运行时环境变量注入，切勿写入镜像层。",
                        )
                    )

            # 5. ADD remote URL
            if ADD_URL_RE.match(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-DOCKER-005",
                        rule_name="Unverified Remote URL in Dockerfile ADD Instruction",
                        cwe_id="CWE-829",
                        severity=Severity.MEDIUM,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="使用 `ADD http(s)://...` 自动拉取远程文件缺少哈希校验且会自动解压归档。",
                        remediation="改用 `RUN curl -fsSL ... && echo '<sha256> file' | sha256sum -c` 并优先使用 `COPY`。",
                    )
                )

        # 6. Final stage running as root
        if has_from and (last_user is None or last_user in ("root", "0", "0:0", "root:root")):
            findings.append(
                CodeSecurityFinding(
                    rule_id="OG-DOCKER-002",
                    rule_name="Container Runs as Privileged Root User",
                    cwe_id="CWE-250",
                    severity=Severity.HIGH,
                    file_path=rel,
                    line_number=last_user_line if last_user else first_from_line,
                    snippet=lines[(last_user_line if last_user else first_from_line) - 1].strip()[:180],
                    description="Dockerfile 未切换非特权运行用户（默认以 `root` 身份运行），容器逃逸后风险极大。",
                    remediation="在最终阶段创建并切换至非 root 用户（如 `RUN useradd -r appuser && USER appuser`）。",
                )
            )

        return findings
