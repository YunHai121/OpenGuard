"""FastAPI Web Workbench server and RESTful API endpoints."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from openguard import __version__
from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig, load_config
from openguard.dx import run_doctor
from openguard.remediation.dep_remediator import DependencyRemediator
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.secret_remediator import SecretRemediator
from openguard.reporters.badge_generator import render_badge_svg
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.markdown_reporter import render_markdown_report, render_pr_comment
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif, render_spdx
from openguard.reporters.slsa_provenance import render_slsa_provenance
from openguard.sbom_tools import score_sbom_quality
from openguard.scanners.secret_rules import build_builtin_secret_rules
from openguard.utils.entropy import mask_secret
from openguard.web.storage import AuditHistoryStore

STATIC_DIR = Path(__file__).resolve().parent / "static"


class ScanRequest(BaseModel):
    target: str
    include_git_history: bool = False
    offline: bool = True
    license_override: Optional[str] = None


class SnippetRequest(BaseModel):
    code: str
    filename: str = "snippet.py"


class AutofixRequest(BaseModel):
    target: str
    fix_secrets: bool = True
    fix_docs: bool = True
    fix_deps: bool = False
    allow_major: bool = True
    license_id: str = "MIT"


class TriageIgnoreRequest(BaseModel):
    target: str
    file_path: str
    line_number: int = 1
    mode: str = "inline"  # "inline" | "ignorefile"


def create_app(db_path: Optional[Path] = None) -> FastAPI:
    """Construct the OpenGuard FastAPI application."""
    fastapi_app = FastAPI(
        title="OpenGuard (开源卫士) Web Workbench",
        version=__version__,
        description="开源供应链安全、许可证合规与工程规范自动化审计平台",
    )
    store = AuditHistoryStore(db_path=db_path)

    if STATIC_DIR.is_dir():
        fastapi_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @fastapi_app.get("/", response_class=HTMLResponse)
    def serve_index() -> HTMLResponse:
        index_file = STATIC_DIR / "index.html"
        if not index_file.is_file():
            return HTMLResponse("<h1>OpenGuard Web UI missing</h1>", status_code=404)
        return HTMLResponse(index_file.read_text(encoding="utf-8"))

    @fastapi_app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "version": __version__, "service": "OpenGuard Web Workbench"}

    @fastapi_app.get("/api/presets")
    def list_presets() -> List[Dict[str, str]]:
        pkg_root = Path(__file__).resolve().parents[2]
        presets: List[Dict[str, str]] = []
        demo_dir = pkg_root / "examples" / "vulnerable_demo_repo"
        if demo_dir.is_dir():
            presets.append(
                {
                    "name": "内置问题靶场示例 (vulnerable_demo_repo)",
                    "path": str(demo_dir),
                    "description": "含云密钥、大模型 Key、GPL 冲突、已知 CVE、仿冒包、SAST 漏洞与缺失文档的典型问题仓",
                }
            )
        presets.append(
            {
                "name": "OpenGuard 自身代码仓 (Self-Audit)",
                "path": str(pkg_root),
                "description": "使用 OpenGuard 对自身源码仓库执行供应链安全与工程规范自检",
            }
        )
        return presets

    @fastapi_app.post("/api/scan")
    def run_scan(req: ScanRequest) -> Dict[str, Any]:
        target_str = req.target.strip()
        if not target_str:
            raise HTTPException(status_code=400, detail="请提供本地项目路径或远程 Git 仓库 URL。")

        tpath = Path(target_str)
        if tpath.exists():
            root = tpath.parent if tpath.is_file() else tpath
            cfg = load_config(root)
        else:
            cfg = AuditConfig()

        cfg.include_git_history = req.include_git_history
        cfg.offline = req.offline
        if req.license_override:
            cfg.project_license_override = req.license_override

        try:
            report = OpenGuardAuditor(cfg).audit(target_str)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"扫描失败: {exc}") from exc

        store.save_report(report)
        return report.model_dump()

    @fastapi_app.post("/api/scan/snippet")
    def scan_snippet(req: SnippetRequest) -> Dict[str, Any]:
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit_snippet(req.code, filename=req.filename)
        return report.model_dump()

    @fastapi_app.get("/api/history")
    def get_history(limit: int = 30) -> List[Dict[str, Any]]:
        return store.list_history(limit=limit)

    @fastapi_app.get("/api/history/{scan_id}")
    def get_history_item(scan_id: str) -> Dict[str, Any]:
        report = store.get_report(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"未找到扫描记录: {scan_id}")
        return report.model_dump()

    @fastapi_app.get("/api/diff/{before_id}/{after_id}")
    def diff_scans(before_id: str, after_id: str) -> Dict[str, Any]:
        diff = store.diff_reports(before_id, after_id)
        if not diff:
            raise HTTPException(status_code=404, detail="指定的对比扫描 ID 不存在。")
        return diff

    @fastapi_app.post("/api/autofix/preview")
    def autofix_preview(req: AutofixRequest) -> Dict[str, Any]:
        return _execute_autofix(req, apply=False)

    @fastapi_app.post("/api/autofix/apply")
    def autofix_apply(req: AutofixRequest) -> Dict[str, Any]:
        return _execute_autofix(req, apply=True)

    def _execute_autofix(req: AutofixRequest, apply: bool) -> Dict[str, Any]:
        target_path = Path(req.target).resolve()
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"目标路径不存在: {target_path}")

        cfg = load_config(target_path if target_path.is_dir() else target_path.parent)
        cfg.offline = True
        auditor = OpenGuardAuditor(cfg)
        secret_res_dict: Dict[str, Any] = {"files_modified": 0, "findings_remediated": 0, "previews": [], "notes": []}
        dep_res_dict: Dict[str, Any] = {
            "files_modified": 0,
            "packages_upgraded": 0,
            "previews": [],
            "breaking_warnings": [],
            "skipped_breaking": [],
        }
        doc_actions: Dict[str, str] = {}
        cached_report = None

        if req.fix_secrets:
            cached_report = auditor.audit(target_path)
            rem = SecretRemediator().remediate(target_path, cached_report, apply=apply)
            secret_res_dict = {
                "applied": rem.applied,
                "files_modified": rem.files_modified,
                "findings_remediated": rem.findings_remediated,
                "backup_dir": rem.backup_dir,
                "notes": rem.notes,
                "previews": [
                    {
                        "file_path": p.file_path,
                        "unified_diff": p.unified_diff,
                        "env_vars_added": p.env_vars_added,
                        "findings_fixed": p.findings_fixed,
                    }
                    for p in rem.previews
                ],
            }

        if req.fix_deps:
            if cached_report is None:
                cached_report = auditor.audit(target_path)
            drem = DependencyRemediator().remediate(target_path, cached_report, apply=apply, allow_major=req.allow_major)
            dep_res_dict = {
                "applied": drem.applied,
                "files_modified": drem.files_modified,
                "packages_upgraded": drem.packages_upgraded,
                "breaking_warnings": drem.breaking_warnings,
                "skipped_breaking": drem.skipped_breaking,
                "previews": [
                    {
                        "file_path": p.file_path,
                        "unified_diff": p.unified_diff,
                        "upgraded_packages": p.upgraded_packages,
                    }
                    for p in drem.previews
                ],
            }

        if req.fix_docs:
            doc_actions = DocGenerator().generate(target_path, license_id=req.license_id, apply=apply)

        return {"applied": apply, "secrets": secret_res_dict, "deps": dep_res_dict, "docs": doc_actions}

    def _resolve_safe_target_file(target: str, file_path: str) -> tuple[Path, Path]:
        root = Path(target).resolve()
        if root.is_file():
            root = root.parent
        if not root.is_dir():
            raise HTTPException(status_code=404, detail=f"目标根目录不存在: {root}")
        candidate = (root / file_path).resolve()
        if not candidate.is_relative_to(root):
            raise HTTPException(status_code=403, detail="禁止访问目标仓库目录之外的路径。")
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail=f"文件不存在: {file_path}")
        return root, candidate

    @fastapi_app.get("/api/file-context")
    def get_file_context(
        target: str,
        file_path: str,
        line: int = 1,
        radius: int = 6,
    ) -> Dict[str, Any]:
        _, fpath = _resolve_safe_target_file(target, file_path)
        raw_lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        rules = build_builtin_secret_rules()

        start_ln = max(1, line - max(1, min(radius, 20)))
        end_ln = min(len(raw_lines), line + max(1, min(radius, 20)))

        context_lines: List[Dict[str, Any]] = []
        for ln_no in range(start_ln, end_ln + 1):
            txt = raw_lines[ln_no - 1]
            # Mask any secret token on the line so plaintext secrets are never exposed
            for rule in rules:
                for m in rule.pattern.finditer(txt):
                    try:
                        val = m.group(rule.extract_group) if rule.extract_group > 0 else m.group(0)
                    except IndexError:
                        val = m.group(0)
                    if val and len(val) >= 8:
                        txt = txt.replace(val, mask_secret(val))
            context_lines.append({"num": ln_no, "text": txt, "highlight": ln_no == line})

        return {
            "file_path": file_path,
            "start_line": start_ln,
            "highlight_line": line,
            "lines": context_lines,
        }

    @fastapi_app.post("/api/triage/ignore")
    def triage_ignore(req: TriageIgnoreRequest) -> Dict[str, Any]:
        root, fpath = _resolve_safe_target_file(req.target, req.file_path)
        mode = req.mode.lower().strip()

        if mode == "ignorefile":
            ig_file = root / ".openguardignore"
            existing = ig_file.read_text(encoding="utf-8", errors="replace") if ig_file.is_file() else ""
            norm_rel = req.file_path.replace("\\", "/").lstrip("./")
            if norm_rel not in existing.splitlines():
                sep = "\n" if existing and not existing.endswith("\n") else ""
                ig_file.write_text(existing + sep + norm_rel + "\n", encoding="utf-8")
            return {"status": "ignored_in_file", "target": norm_rel}

        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        idx = req.line_number - 1
        if not (0 <= idx < len(lines)):
            raise HTTPException(status_code=400, detail=f"行号越界: {req.line_number}")

        cur_line = lines[idx]
        if "openguard: ignore" not in cur_line.lower():
            ext = fpath.suffix.lower()
            marker = "// openguard: ignore" if ext in (".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rs") else "# openguard: ignore"
            ending = "\n" if cur_line.endswith("\n") else ""
            body = cur_line.rstrip("\r\n")
            lines[idx] = f"{body}  {marker}{ending}"
            fpath.write_text("".join(lines), encoding="utf-8")

        return {"status": "inline_ignored", "file_path": req.file_path, "line_number": req.line_number}

    @fastapi_app.get("/api/doctor")
    def api_doctor(target: str) -> Dict[str, Any]:
        if not target.strip():
            raise HTTPException(status_code=400, detail="请提供有效的目标路径。")
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"诊断目标路径不存在: {target}")
        return run_doctor(target_path)

    @fastapi_app.get("/api/sbom-quality/{scan_id}")
    def api_sbom_quality(scan_id: str) -> Dict[str, Any]:
        report = store.get_report(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"未找到扫描记录: {scan_id}")
        cdx = render_cyclonedx(report)
        qr = score_sbom_quality(cdx)
        return {
            "scan_id": scan_id,
            "target_name": report.target_name,
            "overall_score": qr.overall_score,
            "grade": qr.grade,
            "component_count": qr.component_count,
            "checks": qr.checks,
        }

    @fastapi_app.get("/api/compliance/{scan_id}")
    def api_compliance(scan_id: str) -> Dict[str, Any]:
        from openguard.compliance import evaluate_compliance

        report = store.get_report(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"未找到扫描记录: {scan_id}")
        return evaluate_compliance(report)

    @fastapi_app.get("/api/aibom")
    def api_aibom(target: str) -> Dict[str, Any]:
        from openguard.aibom import discover_ai_assets, render_cyclonedx_aibom

        if not target.strip():
            raise HTTPException(status_code=400, detail="请提供有效的目标路径。")
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"目标路径不存在: {target}")
        cfg = load_config(target_path if target_path.is_dir() else target_path.parent)
        rep = discover_ai_assets(target_path, exclude_patterns=cfg.exclude_patterns)
        return {
            "target_name": rep.target_name,
            "model_count": rep.model_count,
            "dataset_count": rep.dataset_count,
            "cyclonedx_aibom": render_cyclonedx_aibom(rep),
        }

    @fastapi_app.get("/api/export/{scan_id}/{fmt}")
    def export_scan(scan_id: str, fmt: str) -> Response:
        report = store.get_report(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"未找到扫描记录: {scan_id}")

        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", scan_id)
        fmt_l = fmt.lower().strip()
        if fmt_l == "html":
            return Response(
                content=render_html_report(report),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.html"'},
            )
        if fmt_l == "pdf":
            return Response(
                content=render_pdf_bytes(report),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.pdf"'},
            )
        if fmt_l in ("md", "markdown"):
            return Response(
                content=render_markdown_report(report),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.md"'},
            )
        if fmt_l in ("pr-comment", "pr_comment"):
            return Response(
                content=render_pr_comment(report),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{safe_id}_pr_comment.md"'},
            )
        if fmt_l == "sarif":
            return JSONResponse(
                content=render_sarif(report),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.sarif.json"'},
            )
        if fmt_l == "cyclonedx":
            return JSONResponse(
                content=render_cyclonedx(report),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.cyclonedx.json"'},
            )
        if fmt_l == "spdx":
            return JSONResponse(
                content=render_spdx(report),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.spdx.json"'},
            )
        if fmt_l == "slsa":
            return JSONResponse(
                content=render_slsa_provenance(report),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.slsa.json"'},
            )
        if fmt_l == "compliance":
            from openguard.compliance import evaluate_compliance

            return JSONResponse(
                content=evaluate_compliance(report),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}_compliance.json"'},
            )
        if fmt_l == "aibom":
            from openguard.aibom import AIBOMReport, discover_ai_assets, render_cyclonedx_aibom

            tpath = Path(report.target_path)
            if tpath.exists():
                cfg = load_config(tpath if tpath.is_dir() else tpath.parent)
                rep = discover_ai_assets(tpath, exclude_patterns=cfg.exclude_patterns)
            else:
                rep = AIBOMReport(target_name=report.target_name)
            return JSONResponse(
                content=render_cyclonedx_aibom(rep),
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.aibom.cdx.json"'},
            )
        if fmt_l == "badge":
            return Response(content=render_badge_svg(report), media_type="image/svg+xml")
        if fmt_l == "json":
            return Response(
                content=report.model_dump_json(indent=2),
                media_type="application/json; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{safe_id}.json"'},
            )
        raise HTTPException(status_code=400, detail=f"不支持的导出格式: {fmt}")

    return fastapi_app


app = create_app()
