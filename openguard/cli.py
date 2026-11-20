"""Rich-powered Typer CLI for OpenGuard."""

from __future__ import annotations

import json
import sys
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from openguard import __version__
from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig, load_config
from openguard.models import SEVERITY_ORDER, AuditReport, Severity
from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.hook_installer import HookInstaller
from openguard.remediation.secret_remediator import SecretRemediator
from openguard.utils.loc_counter import count_repository_loc

# Ensure Windows stdout handles UTF-8 gracefully
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="openguard",
    help="OpenGuard (开源卫士) — 面向开源供应链的敏感信息检测、许可证合规与工程规范自动化审计工具",
    add_completion=False,
)
console = Console()


def _grade_color(grade: str) -> str:
    if grade.startswith("A"):
        return "bold green"
    if grade.startswith("B"):
        return "bold cyan"
    if grade == "C":
        return "bold yellow"
    return "bold red"


def _print_report_summary(report: AuditReport) -> None:
    s = report.summary
    color = _grade_color(s.grade)
    qg = s.quality_gate
    qg_str = (
        f"[bold green]PASSED[/bold green]"
        if (qg and qg.status == "PASSED")
        else f"[bold red]FAILED[/bold red]"
    ) if qg else "N/A"
    header = (
        f"[bold]项目名称:[/bold] {report.target_name}   "
        f"[bold]主许可证:[/bold] {report.project_license}   "
        f"[bold]综合评分:[/bold] [{color}]{s.total_score:.1f}/100 ({s.grade})[/{color}]   "
        f"[bold]质量门禁:[/bold] {qg_str}\n"
        f"[bold]扫描规模:[/bold] {s.files_scanned} 文件 / {s.lines_scanned} 行   "
        f"[bold]耗时:[/bold] {s.scan_duration_ms:.1f} ms   "
        f"[bold]AST+熵值过滤低置信误报:[/bold] {report.suppressed_count} 条"
    )
    console.print(Panel(header, title="OpenGuard 安全与合规审计总览", border_style="cyan"))

    dim_table = Table(show_header=True, header_style="bold magenta")
    dim_table.add_column("评估维度", style="bold")
    dim_table.add_column("得分", justify="right")
    dim_table.add_column("权重", justify="right")
    dim_table.add_column("问题数", justify="right")
    dim_table.add_column("诊断摘要")

    for d in s.dimensions:
        sc_style = "green" if d.score >= 85 else ("yellow" if d.score >= 65 else "red")
        dim_table.add_row(
            d.name,
            f"[{sc_style}]{d.score:.1f}[/{sc_style}]",
            f"{int(d.weight * 100)}%",
            str(d.issue_count),
            d.summary,
        )
    console.print(dim_table)

    all_secrets = [*report.secrets, *report.git_history_secrets]
    if all_secrets:
        sec_tbl = Table(title=f"敏感信息与 Git 历史泄露 ({len(all_secrets)})", show_header=True)
        sec_tbl.add_column("级别")
        sec_tbl.add_column("规则")
        sec_tbl.add_column("位置")
        sec_tbl.add_column("脱敏值")
        sec_tbl.add_column("上下文/提交")
        for f in all_secrets[:15]:
            ctx = f"历史 {f.commit_hash}" if f.is_historical_only else f"{f.confidence:.2f} ({f.ast_context})"
            sec_tbl.add_row(str(f.severity), f.rule_name, f"{f.file_path}:{f.line_number}", f.matched_masked, ctx)
        console.print(sec_tbl)

    if report.license_conflicts:
        lic_tbl = Table(title=f"许可证冲突与传染性警告 ({len(report.license_conflicts)})", show_header=True)
        lic_tbl.add_column("组件")
        lic_tbl.add_column("许可证")
        lic_tbl.add_column("判定")
        lic_tbl.add_column("传播路径")
        for lc in report.license_conflicts[:15]:
            lic_tbl.add_row(
                f"{lc.component_name}@{lc.component_version}",
                lc.component_license,
                f"{lc.compatibility} ({lc.severity})",
                " -> ".join(lc.dependency_path),
            )
        console.print(lic_tbl)

    if report.vulnerabilities:
        v_tbl = Table(title=f"供应链已知漏洞、仿冒包与安装脚本告警 ({len(report.vulnerabilities)})", show_header=True)
        v_tbl.add_column("编号")
        v_tbl.add_column("组件")
        v_tbl.add_column("可达性")
        v_tbl.add_column("级别/CVSS")
        v_tbl.add_column("修复版本")
        v_tbl.add_column("说明")
        for v in report.vulnerabilities[:15]:
            reach_str = (
                "[red]可达[/red]" if v.reachable is True else ("[dim]未导入[/dim]" if v.reachable is False else "-")
            )
            v_tbl.add_row(v.id, f"{v.component_name}@{v.component_version}", reach_str, f"{v.severity} ({v.cvss_score})", v.fixed_version, v.summary)
        console.print(v_tbl)


def _check_fail_threshold(report: AuditReport, fail_on: str) -> bool:
    thr_key = fail_on.upper().strip()
    if thr_key in ("NONE", ""):
        return False
    if thr_key not in Severity.__members__:
        return False
    min_level = SEVERITY_ORDER[Severity[thr_key]]
    for item in [
        *report.secrets,
        *report.git_history_secrets,
        *report.vulnerabilities,
        *report.license_conflicts,
        *report.code_security_findings,
    ]:
        sev_str = str(item.severity).upper()
        if sev_str in Severity.__members__:
            if SEVERITY_ORDER[Severity[sev_str]] >= min_level:
                return True
    return False


@app.command()
def scan(
    target: str = typer.Argument(".", help="待扫描的本地目录、单文件或远程 Git 仓库 URL"),
    git_history: bool = typer.Option(False, "--git-history", help="回溯扫描 Git 历史 Commit 中的幽灵密钥"),
    max_commits: int = typer.Option(100, "--max-commits", help="历史提交扫描上限"),
    staged: bool = typer.Option(False, "--staged", help="仅扫描 git staged 暂存区变更（适用于 pre-commit）"),
    offline: bool = typer.Option(False, "--offline", help="离线模式（跳过 OSV API 请求，纯本地库检测）"),
    license_override: Optional[str] = typer.Option(None, "--license", help="手动覆盖项目主 SPDX 许可证（如 MIT / Apache-2.0）"),
    fmt: Optional[str] = typer.Option(None, "--format", help="导出格式: html|pdf|json|sarif|md|cyclonedx|spdx|badge|all"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="导出文件路径或目录（--format all 时为目录）"),
    fail_on: str = typer.Option("none", "--fail-on", help="门禁退出阈值: critical|high|medium|low|none"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="自定义 .openguard.yml 配置文件路径"),
) -> None:
    """对代码仓执行全维度敏感信息、供应链漏洞、许可证合规与工程规范审计。"""
    target_path = Path(target)
    if target_path.exists():
        root = target_path.parent if target_path.is_file() else target_path
        cfg = load_config(root, config_path=config_file)
    else:
        cfg = AuditConfig()

    cfg.include_git_history = git_history or cfg.include_git_history
    cfg.max_git_commits = max_commits
    cfg.staged_only = staged
    cfg.offline = offline or cfg.offline
    if license_override:
        cfg.project_license_override = license_override

    auditor = OpenGuardAuditor(cfg)
    report = auditor.audit(target, config_path=config_file)
    _print_report_summary(report)

    if fmt:
        default_out = output or Path(
            "openguard_reports" if fmt.lower() == "all" else f"openguard_report.{fmt.lower()}"
        )
        written = auditor.export_report(report, fmt, default_out)
        for wp in written:
            console.print(f"[green]已导出报告:[/green] {wp}")

    if _check_fail_threshold(report, fail_on):
        console.print(f"[bold red]触发安全门禁阈值 (--fail-on {fail_on})，返回非零退出码。[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def autofix(
    target: Path = typer.Argument(..., help="目标开源仓库目录"),
    secrets: bool = typer.Option(False, "--secrets", help="自动剥离硬编码密钥为环境变量并生成 .env.example"),
    docs: bool = typer.Option(False, "--docs", help="一键补齐缺失的标准开源规范文档与 .gitignore"),
    license_id: str = typer.Option("MIT", "--license", help="生成的许可证模板类型: MIT|Apache-2.0|MulanPSL-2.0"),
    apply: bool = typer.Option(False, "--apply", help="真正写入修改（默认仅 dry-run 预览 diff）"),
    force: bool = typer.Option(False, "--force", help="文档生成时强制覆盖已有文件"),
) -> None:
    """自动修复硬编码敏感凭据与补齐缺失开源工程文档（默认预览模式，加 --apply 执行写入）。"""
    if not secrets and not docs:
        secrets = True
        docs = True

    root = target.resolve()
    auditor = OpenGuardAuditor(AuditConfig(offline=True))

    if secrets:
        report = auditor.audit(root)
        res = SecretRemediator().remediate(root, report, apply=apply)
        console.print(
            Panel(
                f"模式: {'[red]实际写入 (已备份至 .openguard_backup)[/red]' if apply else '[yellow]Dry-Run 预览[/yellow]'}\n"
                f"涉及文件: {res.files_modified} 个 | 处理凭据: {res.findings_remediated} 处",
                title="敏感信息自动脱敏重构",
            )
        )
        for preview in res.previews:
            console.print(f"\n[bold cyan]>>> {preview.file_path}[/bold cyan] (变量: {', '.join(preview.env_vars_added)})")
            console.print(preview.unified_diff or "(无文本差异)")

    if docs:
        actions = DocGenerator().generate(root, license_id=license_id, apply=apply, force=force)
        doc_tbl = Table(title="开源规范文档自动补齐清单", show_header=True)
        doc_tbl.add_column("文件")
        doc_tbl.add_column("状态")
        for fname, status in actions.items():
            doc_tbl.add_row(fname, status)
        console.print(doc_tbl)


@app.command()
def sbom(
    target: Path = typer.Argument(".", help="目标项目目录"),
    spec: str = typer.Option("cyclonedx", "--spec", help="SBOM 标准规范: cyclonedx | spdx"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="输出文件路径"),
) -> None:
    """生成符合 CycloneDX 1.5 或 SPDX 2.3 规范的软件物料清单 (SBOM)。"""
    auditor = OpenGuardAuditor(AuditConfig(offline=True))
    report = auditor.audit(target)
    out_path = output or Path(f"sbom.{spec.lower()}.json")
    auditor.export_report(report, spec, out_path)
    console.print(f"[green]已生成 {spec.upper()} SBOM ({len(report.components)} 个组件):[/green] {out_path}")


@app.command()
def hook(
    action: str = typer.Argument(..., help="操作类型: install | uninstall | status | ci"),
    target: Path = typer.Argument(".", help="目标 Git 仓库根目录"),
    ci_platform: str = typer.Option("gitlab", "--ci-platform", help="CI 平台模板: gitlab (适配 git.hust.edu.cn) | github"),
) -> None:
    """管理 Git pre-commit 密钥拦截钩子或生成 GitLab CI / GitHub Actions 流水线。"""
    act = action.lower().strip()
    if act == "install":
        res = HookInstaller.install_pre_commit(target)
    elif act == "uninstall":
        res = HookInstaller.uninstall_pre_commit(target)
    elif act == "status":
        res = HookInstaller.status_pre_commit(target)
    elif act == "ci":
        res = HookInstaller.generate_ci_config(target, platform=ci_platform)
    else:
        console.print(f"[red]未知 hook 操作: {action}[/red]")
        raise typer.Exit(code=2)
    console.print_json(data=res)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="监听主机地址"),
    port: int = typer.Option(8080, "--port", help="监听端口号"),
    open_browser: bool = typer.Option(False, "--open", help="启动后自动打开浏览器"),
) -> None:
    """启动 OpenGuard 可视化 Web 安全审计工作台。"""
    import uvicorn

    url = f"http://{host}:{port}"
    console.print(f"[bold green]OpenGuard Web 工作台启动中:[/bold green] {url}")
    if open_browser:
        webbrowser.open(url)
    uvicorn.run("openguard.web.app:app", host=host, port=port, log_level="info")


@app.command()
def cloc(
    target: Path = typer.Argument(".", help="待统计有效代码行数的项目目录"),
    exclude_subpaths: Optional[str] = typer.Option(
        None, "--exclude-subpaths", help="逗号分隔的排除子目录（如 examples/vulnerable_demo_repo）"
    ),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="将统计结果导出为 JSON 文件"),
) -> None:
    """内置多语言有效代码行数统计工具（统计范围与排除项清晰可审计）。"""
    subs = [s.strip() for s in exclude_subpaths.split(",") if s.strip()] if exclude_subpaths else []
    stats = count_repository_loc(target, exclude_subpaths=subs)

    tbl = Table(title=f"有效代码行数统计 - {Path(target).resolve().name}", show_header=True)
    tbl.add_column("语言")
    tbl.add_column("文件数", justify="right")
    tbl.add_column("总行数", justify="right")
    tbl.add_column("空行", justify="right")
    tbl.add_column("注释/文档行", justify="right")
    tbl.add_column("有效代码行", justify="right", style="bold green")

    for lang, info in stats["by_language"].items():
        tbl.add_row(
            lang,
            str(info["files"]),
            str(info["total"]),
            str(info["blank"]),
            str(info["comment"]),
            str(info["code"]),
        )
    tot = stats["totals"]
    tbl.add_row(
        "合计",
        str(tot["files"]),
        str(tot["total"]),
        str(tot["blank"]),
        str(tot["comment"]),
        str(tot["code"]),
        style="bold cyan",
    )
    console.print(tbl)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]统计结果已保存:[/green] {json_out}")


@app.command()
def benchmark(
    output_dir: Path = typer.Option(Path("benchmarks"), "--output-dir", help="Benchmark 输出目录"),
) -> None:
    """运行三阶混合引擎 vs 纯正则 / 纯熵值基线对比评测实验。"""
    from benchmarks.run_benchmark import run_full_benchmark

    results = run_full_benchmark(output_dir=output_dir)
    console.print(f"[green]Benchmark 运行完成，报告目录:[/green] {output_dir}")
    console.print_json(data=results["summary_table"])


@app.command()
def version() -> None:
    """输出当前 OpenGuard 版本信息。"""
    console.print(f"OpenGuard (开源卫士) v{__version__}")


if __name__ == "__main__":
    app()
