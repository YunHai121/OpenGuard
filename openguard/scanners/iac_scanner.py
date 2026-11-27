"""Checkov & Trivy-Config-inspired Cloud-Native IaC Misconfiguration Scanner.

Audits:
- Docker Compose (`docker-compose*.yml`, `compose*.yml`): privileged mode, docker.sock mount,
  host network mode, and public 0.0.0.0 database/cache port exposure.
- Kubernetes Manifests (`apiVersion` + `kind` YAML): privileged containers, hostNetwork/hostPID/hostIPC,
  and explicit root execution (`runAsUser: 0` / `runAsNonRoot: false`).
- Terraform HCL (`*.tf`): unrestricted `0.0.0.0/0` ingress rules, public S3 ACL/block-public-access
  disabled, and disabled encryption (`encrypted = false` / `storage_encrypted = false`).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded
from openguard.models import CodeSecurityFinding, Severity

K8S_WORKLOAD_KINDS = frozenset({"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"})
SENSITIVE_EXPOSED_PORTS = {"22", "2375", "3306", "5432", "6379", "9200", "27017"}

TF_PUBLIC_CIDR_RE = re.compile(r'["\'](?:0\.0\.0\.0/0|::/0)["\']')
TF_PUBLIC_S3_RE = re.compile(
    r'(?i)(?:acl\s*=\s*["\']public-read(?:-write)?["\']|block_public_(?:acls|policy)\s*=\s*false)'
)
TF_NO_ENCRYPT_RE = re.compile(r"(?i)\b(?:storage_encrypted|encrypted)\s*=\s*false\b")

SENSITIVE_EXACT_FILENAMES = frozenset({
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".pypirc",
    ".netrc",
    ".htpasswd",
    "privkey.pem",
    "private.pem",
    "private.key",
    "id_rsa.key",
})
SENSITIVE_KEYSTORE_EXTS = (".p12", ".pfx", ".jks", ".keystore", ".ppk", ".ovpn")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".test", ".openguard.local")


class IaCScanner:
    """Zero-dependency static IaC security scanner for Docker Compose, Kubernetes, and Terraform."""

    @staticmethod
    def is_compose_file(filename: str) -> bool:
        low = filename.lower()
        return (
            low in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
            or (low.startswith("docker-compose.") and low.endswith((".yml", ".yaml")))
            or (low.startswith("compose.") and low.endswith((".yml", ".yaml")))
        )

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
                low = fname.lower()
                # Sensitive committed credential/keystore artifact hygiene checks (Trivy/Gitleaks/Checkov)
                if low in SENSITIVE_EXACT_FILENAMES or low.endswith(SENSITIVE_KEYSTORE_EXTS):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-HYG-001",
                            rule_name="Committed Private Key, Keystore or Registry Credential File",
                            cwe_id="CWE-312",
                            severity=Severity.CRITICAL,
                            file_path=rel,
                            line_number=1,
                            snippet=fname,
                            description=f"代码仓中直接提交了高危密钥/证书库或包仓库凭据文件 `{rel}`（二进制证书库常绕过纯文本密钥扫描器）。",
                            remediation="立即从 Git 仓库与历史中清除该文件，将其加入 `.gitignore`，并轮换其中包含的私钥或凭据。",
                        )
                    )
                    continue
                if (low == ".env" or low.startswith(".env.")) and not any(low.endswith(sfx) for sfx in SAFE_ENV_SUFFIXES):
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-HYG-002",
                            rule_name="Committed Live .env Environment File in Repository",
                            cwe_id="CWE-538",
                            severity=Severity.HIGH,
                            file_path=rel,
                            line_number=1,
                            snippet=fname,
                            description=f"仓库中包含运行时环境配置文件 `{rel}`（非 `.env.example`/`.env.sample` 模板），极易泄露生产密钥与数据库口令。",
                            remediation="将其从版本控制移除并追加 `.env` / `.env.*` 到 `.gitignore`，仅提交脱敏后的 `.env.example`。",
                        )
                    )
                    continue
                if low.endswith(".tf") or self.is_compose_file(low) or low.endswith((".yml", ".yaml")):
                    # Skip GitHub/GitLab CI YAML handled by CIWorkflowScanner
                    if ".github/workflows/" in f"/{rel.lower()}" or low == ".gitlab-ci.yml":
                        continue
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
        low = Path(rel).name.lower()
        if low.endswith(".tf"):
            return self._scan_terraform(content, rel)
        if self.is_compose_file(low):
            return self._scan_docker_compose(content, rel)
        if low.endswith((".yml", ".yaml")) and "apiVersion:" in content and "kind:" in content:
            return self._scan_kubernetes_yaml(content, rel)
        return []

    @staticmethod
    def _find_line(lines: List[str], needle: str, default: int = 1) -> int:
        low_n = needle.lower()
        for idx, raw in enumerate(lines, start=1):
            if low_n in raw.lower():
                return idx
        return default

    def _scan_docker_compose(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        try:
            data = yaml.safe_load(content)
        except Exception:
            return []
        if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
            return []

        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        for svc_name, svc in data["services"].items():
            if not isinstance(svc, dict):
                continue

            if svc.get("privileged") is True:
                ln = self._find_line(lines, "privileged:")
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-001",
                        rule_name="Docker Compose Privileged Container Mode",
                        cwe_id="CWE-250",
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=ln,
                        snippet=f"{svc_name}: privileged: true",
                        description=f"服务 `{svc_name}` 开启了 `privileged: true`，容器几乎等同于宿主机 root 权限，极易发生容器逃逸。",
                        remediation="移除 `privileged: true`，仅通过 `cap_add` 授予必需的最小 Linux Capability。",
                    )
                )

            volumes = svc.get("volumes") or []
            if isinstance(volumes, list):
                for vol in volumes:
                    vol_str = str(vol)
                    if "/var/run/docker.sock" in vol_str:
                        ln = self._find_line(lines, "docker.sock")
                        findings.append(
                            CodeSecurityFinding(
                                rule_id="OG-IAC-002",
                                rule_name="Docker Daemon Socket Mounted Inside Container",
                                cwe_id="CWE-250",
                                severity=Severity.CRITICAL,
                                file_path=rel,
                                line_number=ln,
                                snippet=vol_str[:160],
                                description=f"服务 `{svc_name}` 挂载了宿主机 `/var/run/docker.sock`，一旦容器被攻破即可直接控制宿主机全部容器与文件。",
                                remediation="移除 `docker.sock` 挂载，或使用只读受限代理（docker-socket-proxy）。",
                            )
                        )

            if str(svc.get("network_mode") or "").lower() == "host":
                ln = self._find_line(lines, "network_mode")
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-003",
                        rule_name="Docker Compose Host Network Namespace Sharing",
                        cwe_id="CWE-284",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=ln,
                        snippet=f"{svc_name}: network_mode: host",
                        description=f"服务 `{svc_name}` 共享宿主机网络命名空间 (`network_mode: host`)，绕过容器网络隔离。",
                        remediation="改用独立 Docker bridge 网络并按需显式映射最小端口。",
                    )
                )

            ports = svc.get("ports") or []
            if isinstance(ports, list):
                for p in ports:
                    p_str = str(p).strip().strip("'\"")
                    if p_str.startswith("0.0.0.0:"):
                        segs = p_str.split(":")
                        host_port = segs[1] if len(segs) >= 2 else ""
                        if host_port in SENSITIVE_EXPOSED_PORTS:
                            ln = self._find_line(lines, p_str)
                            findings.append(
                                CodeSecurityFinding(
                                    rule_id="OG-IAC-003",
                                    rule_name="Sensitive Database/Admin Port Exposed on 0.0.0.0",
                                    cwe_id="CWE-284",
                                    severity=Severity.HIGH,
                                    file_path=rel,
                                    line_number=ln,
                                    snippet=f"{svc_name}: ports: {p_str}",
                                    description=f"服务 `{svc_name}` 将敏感端口 `{host_port}` 绑定至全网地址 `0.0.0.0`，易遭公网扫描与未授权访问。",
                                    remediation=f"将端口绑定限制为本地回环 `127.0.0.1:{host_port}:...` 或仅在内部容器网络通信。",
                                )
                            )
        return findings

    def _scan_kubernetes_yaml(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        lines = content.splitlines()
        findings: List[CodeSecurityFinding] = []
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            return []

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = str(doc.get("kind") or "")
            if kind not in K8S_WORKLOAD_KINDS:
                continue

            pod_spec: Dict[str, Any] = {}
            spec = doc.get("spec")
            if isinstance(spec, dict):
                if kind == "Pod":
                    pod_spec = spec
                elif kind == "CronJob":
                    pod_spec = (
                        spec.get("jobTemplate", {})
                        .get("spec", {})
                        .get("template", {})
                        .get("spec", {})
                        or {}
                    )
                else:
                    pod_spec = spec.get("template", {}).get("spec", {}) or {}
            if not isinstance(pod_spec, dict):
                continue

            # OG-IAC-005: hostNetwork / hostPID / hostIPC
            for host_key in ("hostNetwork", "hostPID", "hostIPC"):
                if pod_spec.get(host_key) is True:
                    ln = self._find_line(lines, f"{host_key}:")
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-IAC-005",
                            rule_name=f"Kubernetes Pod Shares Host Namespace ({host_key})",
                            cwe_id="CWE-250",
                            severity=Severity.HIGH,
                            file_path=rel,
                            line_number=ln,
                            snippet=f"{kind}: {host_key}: true",
                            description=f"Kubernetes `{kind}` 启用了 `{host_key}: true`，破坏 Pod 与宿主机节点的隔离边界。",
                            remediation=f"移除 `{host_key}: true` 或设置为 `false`。",
                        )
                    )

            pod_sc = pod_spec.get("securityContext") or {}
            if isinstance(pod_sc, dict) and (pod_sc.get("runAsUser") == 0 or pod_sc.get("runAsNonRoot") is False):
                ln = self._find_line(lines, "runAs")
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-006",
                        rule_name="Kubernetes Workload Runs as Root User",
                        cwe_id="CWE-250",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=ln,
                        snippet=f"{kind}.securityContext: runAsUser=0 / runAsNonRoot=false",
                        description=f"Kubernetes `{kind}` 显式允许以 root 身份运行容器。",
                        remediation="配置 `securityContext.runAsNonRoot: true` 并指定非零 `runAsUser`（如 `1000`）。",
                    )
                )

            containers = [
                *(pod_spec.get("containers") or []),
                *(pod_spec.get("initContainers") or []),
            ]
            for c in containers:
                if not isinstance(c, dict):
                    continue
                cname = str(c.get("name") or "container")
                sc = c.get("securityContext") or {}
                if not isinstance(sc, dict):
                    continue
                if sc.get("privileged") is True or sc.get("allowPrivilegeEscalation") is True:
                    ln = self._find_line(lines, "privileged:" if sc.get("privileged") is True else "allowPrivilegeEscalation:")
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-IAC-004",
                            rule_name="Kubernetes Privileged Container / Privilege Escalation Enabled",
                            cwe_id="CWE-250",
                            severity=Severity.CRITICAL,
                            file_path=rel,
                            line_number=ln,
                            snippet=f"{cname}: privileged={sc.get('privileged')}, allowPrivilegeEscalation={sc.get('allowPrivilegeEscalation')}",
                            description=f"容器 `{cname}` 启用了特权模式或允许权限提升，存在集群节点接管风险。",
                            remediation="设置 `privileged: false`、`allowPrivilegeEscalation: false` 并 `capabilities.drop: ['ALL']`。",
                        )
                    )
                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    ln = self._find_line(lines, "runAs")
                    findings.append(
                        CodeSecurityFinding(
                            rule_id="OG-IAC-006",
                            rule_name="Kubernetes Container Configured to Run as Root",
                            cwe_id="CWE-250",
                            severity=Severity.HIGH,
                            file_path=rel,
                            line_number=ln,
                            snippet=f"{cname}: runAsUser={sc.get('runAsUser')}",
                            description=f"容器 `{cname}` 配置以 root 用户运行。",
                            remediation="在 `securityContext` 中设置 `runAsNonRoot: true` 与非零 `runAsUser`。",
                        )
                    )
        return findings

    def _scan_terraform(self, content: str, rel: str) -> List[CodeSecurityFinding]:
        findings: List[CodeSecurityFinding] = []
        in_ingress = False
        brace_depth = 0

        for idx, raw in enumerate(content.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "//")) or "openguard: ignore" in stripped.lower():
                continue

            if re.match(r"^\s*ingress\s*\{", raw):
                in_ingress = True
                brace_depth = raw.count("{") - raw.count("}")
            elif in_ingress:
                brace_depth += raw.count("{") - raw.count("}")
                if brace_depth <= 0:
                    in_ingress = False

            if in_ingress and TF_PUBLIC_CIDR_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-007",
                        rule_name="Terraform Security Group Allows Unrestricted Public Ingress (0.0.0.0/0)",
                        cwe_id="CWE-284",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="Terraform 入站规则向 `0.0.0.0/0` 或 `::/0` 全公网开放，可能导致管理端口或内部服务直接暴露。",
                        remediation="将 `cidr_blocks` 收敛至企业出口 IP/VPC 网段，避免对非公网网关服务开放全网访问。",
                    )
                )

            if TF_PUBLIC_S3_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-008",
                        rule_name="Terraform Publicly Accessible Cloud Storage Bucket (S3)",
                        cwe_id="CWE-732",
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="Terraform 存储桶配置了公开读/写 ACL 或关闭了公网访问阻断，极易引发大规模数据泄露。",
                        remediation="设置 `acl = \"private\"` 并启用全部 `block_public_acls = true` / `block_public_policy = true`。",
                    )
                )

            if TF_NO_ENCRYPT_RE.search(raw):
                findings.append(
                    CodeSecurityFinding(
                        rule_id="OG-IAC-009",
                        rule_name="Terraform Storage / Database Encryption Disabled",
                        cwe_id="CWE-311",
                        severity=Severity.HIGH,
                        file_path=rel,
                        line_number=idx,
                        snippet=stripped[:180],
                        description="Terraform 显式禁用了卷或数据库静态加密 (`encrypted = false`)。",
                        remediation="将 `encrypted` / `storage_encrypted` 设置为 `true` 并绑定 KMS 密钥。",
                    )
                )

        return findings
