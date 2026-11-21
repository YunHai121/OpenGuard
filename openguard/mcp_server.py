"""Zero-dependency JSON-RPC 2.0 stdio MCP Server for AI Coding Agents.

Exposes OpenGuard capabilities directly to Claude Code, Cursor, Antigravity,
and other MCP-compatible coding assistants so AI agents can verify code snippets,
vet new third-party packages against slopsquatting/typosquatting/CVEs before running
`pip install`/`npm install`, and audit repositories autonomously.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from openguard import __version__
from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.dx import run_doctor
from openguard.models import DependencyComponent
from openguard.reporters.markdown_reporter import render_pr_comment
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx
from openguard.sbom_tools import load_cyclonedx_json, score_sbom_quality
from openguard.scanners.vuln_scanner import POPULAR_PACKAGES_FOR_TYPOSQUAT, VulnScanner

MCP_PROTOCOL_VERSION = "2024-11-05"

# Common AI-hallucinated ("slopsquatting") package naming patterns
SLOPSQUAT_SUSPICIOUS_RE = re.compile(
    r"(?:^python[-_](?:utils|helpers|tools|common|core|sdk|client|api)$|"
    r"^(?:py|node|js|go)[-_](?:helper|util|common|core|security|auth)$|"
    r"-(?:official|sdk-official|pro-utils|helper-lib)$)",
    re.I,
)

MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "audit_repository",
        "description": (
            "Run a full OpenGuard security, supply-chain, CI/CD, Dockerfile, license, "
            "and governance audit on a local repository path."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute or relative repository directory path."},
                "offline": {"type": "boolean", "default": True, "description": "Use offline CVE DB only (fast)."},
                "include_git_history": {"type": "boolean", "default": False, "description": "Scan Git commit history for ghost secrets."},
                "diff_ref": {"type": "string", "description": "Optional git base ref (e.g. 'origin/main') for diff-only PR scanning."},
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "audit_code_snippet",
        "description": (
            "Audit an in-memory source code snippet for hardcoded secrets and SAST vulnerabilities "
            "(SQLi, RCE, unsafe deserialization, XSS, disabled TLS) before writing it to disk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code text to inspect."},
                "filename": {"type": "string", "default": "snippet.py", "description": "Virtual filename with extension (e.g. app.py, index.ts, main.go)."},
            },
            "required": ["code"],
        },
    },
    {
        "name": "check_package_safety",
        "description": (
            "Pre-install guardrail for AI coding agents: vet a package name/version against "
            "known CVEs, typosquatting of popular libraries, and AI slopsquatting heuristics "
            "before executing pip/npm/go install."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string", "description": "Package name to vet (e.g. 'reqeusts', 'pyyaml', 'lodash')."},
                "ecosystem": {"type": "string", "default": "PyPI", "enum": ["PyPI", "npm", "Go", "Maven", "crates.io"]},
                "version": {"type": "string", "default": "unspecified", "description": "Optional version string."},
                "offline": {"type": "boolean", "default": True},
            },
            "required": ["package_name"],
        },
    },
    {
        "name": "generate_pr_comment",
        "description": "Generate a compact GitHub PR / GitLab MR Markdown security review comment for a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Repository path."},
                "diff_ref": {"type": "string", "description": "Optional git base ref for diff-aware review."},
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "diagnose_repo_posture",
        "description": (
            "Run OpenGuard Doctor 7-point security posture & environment readiness diagnostics on a repository "
            "(Python runtime, Git, .openguard.yml validity, pre-commit guard, CI/CD + Dependabot/CODEOWNERS, "
            "MCP readiness, and custom policy/ecosystem manifests) with actionable fix commands."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Local repository directory path to diagnose."},
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "evaluate_sbom_quality",
        "description": (
            "Score a CycloneDX SBOM JSON file (or generate one on the fly from a repository directory) "
            "against the 7 NTIA/CISA Minimum Elements (0.0–10.0 quality score, grade, and per-element gaps)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Path to a CycloneDX JSON file OR a repository directory to generate and score.",
                },
            },
            "required": ["target_path"],
        },
    },
]


def _handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "audit_repository":
        target = str(arguments["target_path"])
        cfg = AuditConfig(
            offline=bool(arguments.get("offline", True)),
            include_git_history=bool(arguments.get("include_git_history", False)),
            diff_ref=arguments.get("diff_ref") or None,
        )
        report = OpenGuardAuditor(cfg).audit(target)
        payload = {
            "target_name": report.target_name,
            "total_score": report.summary.total_score,
            "grade": report.summary.grade,
            "quality_gate": report.summary.quality_gate.model_dump() if report.summary.quality_gate else None,
            "severity_counts": report.summary.severity_counts,
            "secrets_count": len(report.secrets),
            "git_history_secrets_count": len(report.git_history_secrets),
            "vulnerabilities_count": len(report.vulnerabilities),
            "license_conflicts_count": len(report.license_conflicts),
            "code_security_count": len(report.code_security_findings),
            "top_secrets": [s.model_dump() for s in report.secrets[:10]],
            "top_vulnerabilities": [v.model_dump() for v in report.vulnerabilities[:10]],
            "top_code_security": [c.model_dump() for c in report.code_security_findings[:10]],
            "roadmap": report.summary.roadmap[:5],
        }
        return payload

    if name == "audit_code_snippet":
        code = str(arguments["code"])
        filename = str(arguments.get("filename", "snippet.py"))
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit_snippet(code, filename=filename)
        return {
            "filename": filename,
            "total_score": report.summary.total_score,
            "grade": report.summary.grade,
            "safe": len(report.secrets) == 0 and len(report.code_security_findings) == 0,
            "secrets": [s.model_dump() for s in report.secrets],
            "code_security_findings": [c.model_dump() for c in report.code_security_findings],
            "suppressed_count": report.suppressed_count,
        }

    if name == "check_package_safety":
        pkg = str(arguments["package_name"]).strip()
        eco = str(arguments.get("ecosystem", "PyPI"))
        ver = str(arguments.get("version", "unspecified"))
        offline = bool(arguments.get("offline", True))

        comp = DependencyComponent(name=pkg, version=ver, ecosystem=eco, source_file="mcp-pre-install", direct=True)
        findings = VulnScanner(offline=offline).scan_components([comp])

        slopsquat_warning: Optional[str] = None
        if SLOPSQUAT_SUSPICIOUS_RE.search(pkg) and pkg.lower() not in {p.lower() for p in POPULAR_PACKAGES_FOR_TYPOSQUAT.get(eco, [])}:
            slopsquat_warning = (
                f"包名 `{pkg}` 命中典型 AI 幻觉包（Slopsquatting）高危命名模式，请在安装前人工核验官方仓库主页与维护者信誉。"
            )

        risk_level = "SAFE"
        if any(str(f.severity) in ("CRITICAL", "HIGH") for f in findings):
            risk_level = "BLOCK"
        elif findings or slopsquat_warning:
            risk_level = "WARN"

        return {
            "package_name": pkg,
            "ecosystem": eco,
            "version": ver,
            "risk_level": risk_level,
            "slopsquatting_warning": slopsquat_warning,
            "findings": [f.model_dump() for f in findings],
        }

    if name == "generate_pr_comment":
        target = str(arguments["target_path"])
        cfg = AuditConfig(offline=True, diff_ref=arguments.get("diff_ref") or None)
        report = OpenGuardAuditor(cfg).audit(target)
        return {"markdown": render_pr_comment(report)}

    if name == "diagnose_repo_posture":
        target = Path(str(arguments["target_path"]))
        return run_doctor(target)

    if name == "evaluate_sbom_quality":
        target = Path(str(arguments["target_path"]))
        if not target.exists():
            raise FileNotFoundError(f"目标路径不存在: {target}")
        if target.is_file():
            sbom_data = load_cyclonedx_json(target)
        else:
            report = OpenGuardAuditor(AuditConfig(offline=True)).audit(target)
            sbom_data = render_cyclonedx(report)
        qr = score_sbom_quality(sbom_data)
        return {
            "target_path": str(target.resolve()),
            "overall_score": qr.overall_score,
            "grade": qr.grade,
            "component_count": qr.component_count,
            "checks": qr.checks,
        }

    raise ValueError(f"Unknown OpenGuard MCP tool: {name}")


def handle_jsonrpc_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single MCP JSON-RPC 2.0 message and return response dict (or None for notifications)."""
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params") or {}

    # JSON-RPC notifications have no id
    if method.startswith("notifications/"):
        return None

    try:
        if method == "initialize":
            result: Any = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "openguard-mcp", "version": __version__},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": MCP_TOOLS}
        elif method == "tools/call":
            tool_name = str(params.get("name", ""))
            tool_args = params.get("arguments") or {}
            payload = _handle_tool_call(tool_name, tool_args)
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(payload, indent=2, ensure_ascii=False),
                    }
                ],
                "isError": False,
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32000, "message": str(exc)},
        }


def run_stdio_server() -> None:
    """Run newline-delimited JSON-RPC 2.0 MCP server over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        resp = handle_jsonrpc_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
