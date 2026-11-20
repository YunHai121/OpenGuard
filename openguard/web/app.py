"""FastAPI Web Workbench server and RESTful API endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from openguard import __version__
from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig, load_config
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.secret_remediator import SecretRemediator
from openguard.reporters.badge_generator import render_badge_svg
from openguard.reporters.html_reporter import render_html_report
from openguard.reporters.markdown_reporter import render_markdown_report
from openguard.reporters.pdf_reporter import render_pdf_bytes
from openguard.reporters.sarif_sbom_reporter import render_cyclonedx, render_sarif, render_spdx
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
    license_id: str = "MIT"


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

        auditor = OpenGuardAuditor(AuditConfig(offline=True))
        secret_res_dict: Dict[str, Any] = {"files_modified": 0, "findings_remediated": 0, "previews": [], "notes": []}
        doc_actions: Dict[str, str] = {}

        if req.fix_secrets:
            report = auditor.audit(target_path)
            rem = SecretRemediator().remediate(target_path, report, apply=apply)
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

        if req.fix_docs:
            doc_actions = DocGenerator().generate(target_path, license_id=req.license_id, apply=apply)

        return {"applied": apply, "secrets": secret_res_dict, "docs": doc_actions}

    @fastapi_app.get("/api/export/{scan_id}/{fmt}")
    def export_scan(scan_id: str, fmt: str) -> Response:
        report = store.get_report(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"未找到扫描记录: {scan_id}")

        fmt_l = fmt.lower().strip()
        if fmt_l == "html":
            return Response(
                content=render_html_report(report),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.html"'},
            )
        if fmt_l == "pdf":
            return Response(
                content=render_pdf_bytes(report),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.pdf"'},
            )
        if fmt_l in ("md", "markdown"):
            return Response(
                content=render_markdown_report(report),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.md"'},
            )
        if fmt_l == "sarif":
            return JSONResponse(
                content=render_sarif(report),
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.sarif.json"'},
            )
        if fmt_l == "cyclonedx":
            return JSONResponse(
                content=render_cyclonedx(report),
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.cyclonedx.json"'},
            )
        if fmt_l == "spdx":
            return JSONResponse(
                content=render_spdx(report),
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.spdx.json"'},
            )
        if fmt_l == "badge":
            return Response(content=render_badge_svg(report), media_type="image/svg+xml")
        if fmt_l == "json":
            return Response(
                content=report.model_dump_json(indent=2),
                media_type="application/json; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'},
            )
        raise HTTPException(status_code=400, detail=f"不支持的导出格式: {fmt}")

    return fastapi_app


app = create_app()
