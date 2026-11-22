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
from openguard.auditor import OpenGuardAuditor, _is_remote_git_url
from openguard.baseline import save_baseline
from openguard.config import AuditConfig, load_config
from openguard.dx import (
    EXIT_POLICY_VIOLATION,
    EXIT_RUNTIME_ERROR,
    EXIT_USER_ERROR,
    init_repository,
    run_doctor,
)
from openguard.models import SEVERITY_ORDER, AuditReport, Severity
from openguard.remediation.dep_remediator import DependencyRemediator
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
err_console = Console(stderr=True)


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
            if v.reachability_level == "call_reachable":
                reach_str = "[bold red]函数可达[/bold red]"
            elif v.reachability_level == "import_only" or v.reachable is True:
                reach_str = "[yellow]已导入[/yellow]"
            elif v.reachability_level == "unreachable" or v.reachable is False:
                reach_str = "[dim]未导入[/dim]"
            else:
                reach_str = "-"
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
    diff: Optional[str] = typer.Option(None, "--diff", help="Diff-Aware 增量扫描基准分支/提交（如 origin/main 或 HEAD~1）"),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="基线文件路径（自动忽略基线中已有存量问题，仅拦截新增风险）"),
    cache: bool = typer.Option(False, "--cache", help="启用基于 SHA-256 内容哈希的增量文件扫描缓存 (.openguard_cache)"),
    offline: bool = typer.Option(False, "--offline", help="离线模式（跳过 OSV API 请求，纯本地库检测）"),
    license_override: Optional[str] = typer.Option(None, "--license", help="手动覆盖项目主 SPDX 许可证（如 MIT / Apache-2.0）"),
    fmt: Optional[str] = typer.Option(None, "--format", help="导出格式: html|pdf|json|sarif|md|pr-comment|cyclonedx|spdx|slsa|badge|all"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="导出文件路径或目录（--format all 时为目录）"),
    json_output: bool = typer.Option(False, "--json", help="向 stdout 输出纯净 JSON 报告（静默所有 Rich 装饰，便于 jq/CI 管道消费）"),
    audit_mode: bool = typer.Option(False, "--audit-mode", help="非阻塞观察模式（即使触发 --fail-on 仍返回退出码 0，适合老项目渐进式接入 CI）"),
    fail_on: str = typer.Option("none", "--fail-on", help="门禁退出阈值: critical|high|medium|low|none"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="自定义 .openguard.yml 配置文件路径"),
) -> None:
    """对代码仓执行全维度敏感信息、供应链漏洞、许可证合规与工程规范审计。

    退出码约定: 0=通过/观察模式, 1=触发安全门禁阈值, 2=用户输入/路径/配置错误, 3=运行时异常。
    """
    thr_key = fail_on.upper().strip()
    if thr_key not in ("NONE", "") and thr_key not in Severity.__members__:
        err_console.print(f"[bold red]无效的 --fail-on 阈值:[/bold red] {fail_on}（可选: critical|high|medium|low|none）")
        raise typer.Exit(code=EXIT_USER_ERROR)

    if config_file is not None and not config_file.is_file():
        err_console.print(f"[bold red]指定的配置文件不存在:[/bold red] {config_file}")
        raise typer.Exit(code=EXIT_USER_ERROR)

    is_remote = _is_remote_git_url(target)
    target_path = Path(target)
    if not is_remote and not target_path.exists():
        err_console.print(f"[bold red]审计目标路径不存在:[/bold red] {target}")
        raise typer.Exit(code=EXIT_USER_ERROR)

    try:
        if target_path.exists():
            root = target_path.parent if target_path.is_file() else target_path
            cfg = load_config(root, config_path=config_file)
        else:
            cfg = AuditConfig()

        cfg.include_git_history = git_history or cfg.include_git_history
        cfg.max_git_commits = max_commits
        cfg.staged_only = staged
        if diff:
            cfg.diff_ref = diff
        if baseline:
            cfg.baseline_path = str(baseline)
        if cache:
            cfg.use_cache = True
        cfg.offline = offline or cfg.offline
        if license_override:
            cfg.project_license_override = license_override

        auditor = OpenGuardAuditor(cfg)
        report = auditor.audit(target, config_path=config_file)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]输入路径错误:[/bold red] {exc}")
        raise typer.Exit(code=EXIT_USER_ERROR)
    except ValueError as exc:
        err_console.print(f"[bold red]配置或参数校验失败:[/bold red] {exc}")
        raise typer.Exit(code=EXIT_USER_ERROR)
    except Exception as exc:
        err_console.print(f"[bold red]审计运行时异常:[/bold red] {exc}")
        raise typer.Exit(code=EXIT_RUNTIME_ERROR)

    if json_output:
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
        sys.stdout.flush()
    else:
        _print_report_summary(report)

    if fmt:
        default_out = output or Path(
            "openguard_reports" if fmt.lower() == "all" else f"openguard_report.{fmt.lower()}"
        )
        written = auditor.export_report(report, fmt, default_out)
        notice_console = err_console if json_output else console
        for wp in written:
            notice_console.print(f"[green]已导出报告:[/green] {wp}")

    if _check_fail_threshold(report, fail_on):
        if audit_mode:
            if not json_output:
                console.print(
                    f"[bold yellow]已命中 --fail-on {fail_on} 阈值，但当前处于 --audit-mode 观察模式，返回退出码 0。[/bold yellow]"
                )
        else:
            notice_console = err_console if json_output else console
            notice_console.print(f"[bold red]触发安全门禁阈值 (--fail-on {fail_on})，返回退出码 {EXIT_POLICY_VIOLATION}。[/bold red]")
            raise typer.Exit(code=EXIT_POLICY_VIOLATION)


@app.command()
def autofix(
    target: Path = typer.Argument(..., help="目标开源仓库目录"),
    secrets: bool = typer.Option(False, "--secrets", help="自动剥离硬编码密钥为环境变量并生成 .env.example"),
    docs: bool = typer.Option(False, "--docs", help="一键补齐缺失的标准开源规范文档与 .gitignore"),
    deps: bool = typer.Option(False, "--deps", help="自动将存在已知 CVE 的依赖升级至最小安全版本（支持 PyPI/npm/Go/Cargo/Maven）"),
    no_major: bool = typer.Option(False, "--no-major", help="跳过跨主版本破坏性依赖升级（类似 Renovate major=false 保护）"),
    license_id: str = typer.Option("MIT", "--license", help="生成的许可证模板类型: MIT|Apache-2.0|MulanPSL-2.0"),
    apply: bool = typer.Option(False, "--apply", help="真正写入修改（默认仅 dry-run 预览 diff）"),
    force: bool = typer.Option(False, "--force", help="文档生成时强制覆盖已有文件"),
) -> None:
    """自动修复硬编码敏感凭据、补齐缺失开源工程文档与升级漏洞依赖（默认预览模式，加 --apply 执行写入）。"""
    if not secrets and not docs and not deps:
        secrets = True
        docs = True

    root = target.resolve()
    auditor = OpenGuardAuditor(AuditConfig(offline=True))
    cached_report: Optional[AuditReport] = None

    if secrets:
        cached_report = auditor.audit(root)
        res = SecretRemediator().remediate(root, cached_report, apply=apply)
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

    if deps:
        if cached_report is None:
            cached_report = auditor.audit(root)
        dep_res = DependencyRemediator().remediate(root, cached_report, apply=apply, allow_major=not no_major)
        console.print(
            Panel(
                f"模式: {'[red]实际写入 (已备份至 .openguard_backup)[/red]' if apply else '[yellow]Dry-Run 预览[/yellow]'}\n"
                f"涉及清单: {dep_res.files_modified} 个 | 升级组件: {dep_res.packages_upgraded} 项 | 跨主版本警告: {len(dep_res.breaking_warnings)} 项",
                title="多生态漏洞依赖安全自动升级 (PyPI/npm/Go/Cargo/Maven)",
            )
        )
        for warn in dep_res.breaking_warnings:
            console.print(f"[bold yellow]⚠ {warn}[/bold yellow]")
        for skipped in dep_res.skipped_breaking:
            console.print(f"[dim]↷ 已跳过 (--no-major): {skipped}[/dim]")
        for preview in dep_res.previews:
            console.print(f"\n[bold cyan]>>> {preview.file_path}[/bold cyan] ({', '.join(preview.upgraded_packages)})")
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
def baseline(
    action: str = typer.Argument("create", help="操作: create (生成存量问题基线快照)"),
    target: Path = typer.Argument(".", help="目标仓库目录"),
    output: Path = typer.Option(Path(".openguard-baseline.json"), "--output", "-o", help="基线输出文件路径"),
    offline: bool = typer.Option(True, "--offline/--online", help="是否仅用离线漏洞库"),
) -> None:
    """生成存量风险基线文件，帮助老项目零痛苦接入 OpenGuard CI 门禁（仅拦截新增隐患）。"""
    if action.lower().strip() != "create":
        console.print(f"[red]未知 baseline 操作: {action}（当前支持: create）[/red]")
        raise typer.Exit(code=2)
    report = OpenGuardAuditor(AuditConfig(offline=offline)).audit(target)
    saved = save_baseline(report, output)
    data = json.loads(saved.read_text(encoding="utf-8"))
    console.print(f"[green]已生成基线快照 ({len(data.get('fingerprints', []))} 条存量指纹):[/green] {saved}")


@app.command()
def mcp() -> None:
    """启动 OpenGuard MCP Server (JSON-RPC 2.0 stdio)，为 Claude Code / Cursor / Antigravity 提供安全防护工具。"""
    from openguard.mcp_server import run_stdio_server

    run_stdio_server()


@app.command()
def attest(
    action: str = typer.Argument(..., help="操作: generate | verify"),
    target: Path = typer.Argument(".", help="目标仓库目录（generate 时为仓库；verify 时为 provenance JSON 文件）"),
    repo: Optional[Path] = typer.Option(None, "--repo", help="verify 时用于校验文件 SHA-256 完整性的仓库目录"),
    output: Path = typer.Option(Path("slsa_provenance.json"), "--output", "-o", help="generate 时的输出路径"),
) -> None:
    """生成或校验 in-toto v1 / SLSA Provenance v1.0 供应链完整度证明。"""
    from openguard.reporters.slsa_provenance import verify_slsa_provenance

    act = action.lower().strip()
    if act == "generate":
        report = OpenGuardAuditor(AuditConfig(offline=True)).audit(target)
        written = OpenGuardAuditor.export_report(report, "slsa", output)
        console.print(f"[green]已生成 SLSA v1.0 / in-toto 证明文件:[/green] {written[0]}")
    elif act == "verify":
        ok, errs = verify_slsa_provenance(target, repo_root=repo)
        if ok:
            console.print(f"[bold green]SLSA Provenance 校验通过:[/bold green] {target}")
        else:
            for e in errs:
                console.print(f"[bold red]校验失败:[/bold red] {e}")
            raise typer.Exit(code=1)
    else:
        console.print(f"[red]未知 attest 操作: {action}（支持 generate | verify）[/red]")
        raise typer.Exit(code=2)


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
def batch(
    parent_dir: Path = typer.Argument(..., help="包含多个子仓库的父目录路径"),
    offline: bool = typer.Option(True, "--offline/--online", help="是否使用离线高速模式"),
    cache: bool = typer.Option(False, "--cache", help="启用每文件 SHA-256 增量扫描缓存"),
    jsonl_out: Optional[Path] = typer.Option(None, "--jsonl-out", help="流式导出 JSONL 汇总结果路径（适配 SIEM/BI）"),
    md_out: Optional[Path] = typer.Option(None, "--md-out", help="导出多仓组合 Markdown 排行榜报告路径"),
    fail_on_gate: bool = typer.Option(False, "--fail-on-gate", help="若有任意仓库 Quality Gate 失败则返回非零退出码"),
) -> None:
    """组织级/竞赛评审级批量多仓审计：一键扫描目录下所有子项目并输出汇总矩阵与 JSONL 流。"""
    from openguard.portfolio import PortfolioAuditor, discover_child_repositories

    repos = discover_child_repositories(parent_dir)
    if not repos:
        console.print(f"[yellow]未在 {parent_dir} 下发现可审计的子项目目录。[/yellow]")
        return

    res = PortfolioAuditor().audit_repositories(
        repos,
        offline=offline,
        use_cache=cache,
        jsonl_out=jsonl_out,
        md_out=md_out,
    )
    tbl = Table(title=f"OpenGuard 多仓组合审计汇总 ({res.total_repos} 个仓库 | 平均 {res.average_score:.1f} 分)", show_header=True)
    tbl.add_column("仓库")
    tbl.add_column("得分/等级", justify="right")
    tbl.add_column("门禁")
    tbl.add_column("密钥", justify="right")
    tbl.add_column("P0/KEV", justify="right")
    tbl.add_column("许可证冲突", justify="right")
    tbl.add_column("SAST/配置", justify="right")
    for r in res.repos:
        gate_fmt = "[green]PASSED[/green]" if r.quality_gate == "PASSED" else f"[red]{r.quality_gate}[/red]"
        tbl.add_row(
            r.repo_name,
            f"{r.total_score:.1f} ({r.grade})",
            gate_fmt,
            str(r.secrets_count),
            f"{r.p0_vulns_count}/{r.kev_vulns_count}",
            str(r.license_conflicts_count),
            str(r.code_security_count),
        )
    console.print(tbl)
    if jsonl_out:
        console.print(f"[green]已导出 JSONL 流式结果:[/green] {jsonl_out}")
    if md_out:
        console.print(f"[green]已导出 Portfolio Markdown 报告:[/green] {md_out}")
    if fail_on_gate and res.failed_gates > 0:
        raise typer.Exit(code=1)


@app.command(name="sbom-diff")
def sbom_diff(
    before: Path = typer.Argument(..., help="变更前的 CycloneDX SBOM JSON 文件路径"),
    after: Path = typer.Argument(..., help="变更后的 CycloneDX SBOM JSON 文件路径"),
    md_out: Optional[Path] = typer.Option(None, "--md-out", "-o", help="导出 PR 友好型 SBOM Diff Markdown 路径"),
    fail_on_drift: bool = typer.Option(False, "--fail-on-drift", help="若引入新漏洞或强传染许可证漂移则返回非零退出码"),
) -> None:
    """对比两份 CycloneDX SBOM，检测新增/升级/移除组件、许可证漂移与新增漏洞。"""
    from openguard.sbom_tools import diff_cyclonedx_sboms, load_cyclonedx_json, render_sbom_diff_markdown

    diff = diff_cyclonedx_sboms(load_cyclonedx_json(before), load_cyclonedx_json(after))
    md = render_sbom_diff_markdown(diff)
    console.print(md)
    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(md, encoding="utf-8")
        console.print(f"[green]已保存 SBOM Diff 报告:[/green] {md_out}")
    if fail_on_drift and diff.has_risky_drift:
        console.print("[bold red]检测到高风险供应链漂移（新漏洞或 Copyleft 许可证引入），门禁拦截！[/bold red]")
        raise typer.Exit(code=1)


@app.command(name="sbom-score")
def sbom_score(
    target: Path = typer.Argument(".", help="CycloneDX JSON 文件路径或待现场生成 SBOM 评分的仓库目录"),
    min_score: float = typer.Option(0.0, "--min-score", help="最低质量门槛分 (0-10.0)，低于则退出码非零"),
) -> None:
    """依据 NTIA/CISA Minimum Elements 对 CycloneDX SBOM 执行 0-10.0 完整度质量评分（对标 sbomqs）。"""
    from openguard.reporters.sarif_sbom_reporter import render_cyclonedx
    from openguard.sbom_tools import load_cyclonedx_json, score_sbom_quality

    if target.is_file():
        sbom_data = load_cyclonedx_json(target)
    else:
        rep = OpenGuardAuditor(AuditConfig(offline=True)).audit(target)
        sbom_data = render_cyclonedx(rep)

    qr = score_sbom_quality(sbom_data)
    tbl = Table(title=f"NTIA SBOM 质量评分: {qr.overall_score:.2f} / 10.0 (等级 {qr.grade} · {qr.component_count} 组件)")
    tbl.add_column("编号")
    tbl.add_column("NTIA 最小要素检查项")
    tbl.add_column("得分", justify="right")
    tbl.add_column("状态")
    for c in qr.checks:
        tbl.add_row(c["id"], c["name"], f"{c['score']:.2f}/{c['max']:.1f}", "[green]PASS[/green]" if c["passed"] else "[yellow]WARN[/yellow]")
    console.print(tbl)
    if min_score > 0 and qr.overall_score < min_score:
        console.print(f"[bold red]SBOM 质量分 {qr.overall_score:.2f} 低于门槛 {min_score:.2f}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def init(
    target: Path = typer.Argument(".", help="待初始化 OpenGuard 配置的目标仓库目录"),
    force: bool = typer.Option(False, "--force", help="强制覆盖已存在的配置文件"),
    json_output: bool = typer.Option(False, "--json", help="向 stdout 输出纯净 JSON 初始化结果"),
) -> None:
    """自动探测仓库技术栈与生态，幂等生成定制化 .openguard.yml、.openguardignore 与自定义策略模板。"""
    try:
        res = init_repository(target, force=force)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=EXIT_USER_ERROR)

    if json_output:
        sys.stdout.write(json.dumps(res, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return

    stack = res["stack"]
    ecos = ", ".join(stack["ecosystems"]) if stack["ecosystems"] else "未探测到特定包生态（通用源码模式）"
    console.print(
        Panel(
            f"[bold]目标仓库:[/bold] {res['repo_root']}\n"
            f"[bold]自动探测生态:[/bold] {ecos}\n"
            f"[bold]主许可证:[/bold] {stack['project_license']}",
            title="OpenGuard 零摩擦仓库初始化 (init)",
            border_style="cyan",
        )
    )
    tbl = Table(show_header=True)
    tbl.add_column("配置文件")
    tbl.add_column("状态")
    for rel_path, status in res["files"].items():
        st_fmt = f"[green]{status}[/green]" if status in ("created", "overwritten") else f"[yellow]{status}[/yellow]"
        tbl.add_row(rel_path, st_fmt)
    console.print(tbl)
    console.print("[dim]下一步建议: 运行 `openguard doctor .` 体检环境，或执行 `openguard scan . --offline --cache` 开始首次审计。[/dim]")


@app.command()
def doctor(
    target: Path = typer.Argument(".", help="待执行环境与供应链安全就绪度体检的仓库目录"),
    json_output: bool = typer.Option(False, "--json", help="向 stdout 输出纯净 JSON 诊断结果"),
) -> None:
    """全面诊断运行环境、Git/Pre-commit/CI 安全防线、配置文件与 MCP Server 就绪状态。"""
    try:
        res = run_doctor(target)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=EXIT_USER_ERROR)

    if json_output:
        sys.stdout.write(json.dumps(res, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    else:
        st_color = "bold green" if res["status"] == "HEALTHY" else ("bold yellow" if res["status"] == "DEGRADED" else "bold red")
        tbl = Table(
            title=f"OpenGuard 环境与安全就绪度诊断 [{st_color}]{res['status']}[/{st_color}] "
            f"(OK={res['ok_count']} | WARN={res['warn_count']} | ERROR={res['error_count']})",
            show_header=True,
        )
        tbl.add_column("编号")
        tbl.add_column("检查项")
        tbl.add_column("状态")
        tbl.add_column("详情")
        tbl.add_column("修复建议")
        for c in res["checks"]:
            st = c["status"]
            st_badge = "[green]OK[/green]" if st == "OK" else ("[yellow]WARN[/yellow]" if st == "WARN" else "[bold red]ERROR[/bold red]")
            tbl.add_row(c["id"], c["name"], st_badge, c["details"], c["fix_hint"] or "-")
        console.print(tbl)

    if not res["healthy"]:
        raise typer.Exit(code=EXIT_POLICY_VIOLATION)


@app.command()
def compliance(
    target: Path = typer.Argument(".", help="待执行 EU CRA / NIST SSDF / OWASP SCVS 合规映射的仓库目录"),
    offline: bool = typer.Option(True, "--offline/--online", help="是否使用离线高速模式"),
    json_output: bool = typer.Option(False, "--json", help="向 stdout 输出纯净 JSON 合规报告"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="导出合规审计报告 Markdown 文件路径"),
    fail_on_noncompliant: bool = typer.Option(False, "--fail-on-noncompliant", help="若未 100% 合规则返回退出码 1"),
) -> None:
    """输出 EU CRA (网络弹性法案) / NIST SSDF / OWASP SCVS 8 项供应链合规映射报告。"""
    from openguard.compliance import evaluate_compliance, render_compliance_markdown

    if not target.exists():
        err_console.print(f"[bold red]目标路径不存在:[/bold red] {target}")
        raise typer.Exit(code=EXIT_USER_ERROR)

    report = OpenGuardAuditor(AuditConfig(offline=offline)).audit(target)
    data = evaluate_compliance(report)

    if output:
        md = render_compliance_markdown(data)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md, encoding="utf-8")
        notice_console = err_console if json_output else console
        notice_console.print(f"[green]已导出合规映射报告:[/green] {output}")

    if json_output:
        sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    else:
        st_color = "bold green" if data["status"] == "COMPLIANT" else ("bold yellow" if data["status"] == "PARTIAL" else "bold red")
        tbl = Table(
            title=f"EU CRA / NIST SSDF / OWASP SCVS 合规映射 [{st_color}]{data['status']}[/{st_color}] "
            f"({data['passed_count']}/{data['total_controls']} · {data['compliance_rate']:.1f}%)",
            show_header=True,
        )
        tbl.add_column("编号")
        tbl.add_column("合规控制项")
        tbl.add_column("EU CRA")
        tbl.add_column("NIST SSDF")
        tbl.add_column("状态")
        tbl.add_column("审计证据")
        for c in data["controls"]:
            st = "[green]PASS[/green]" if c["passed"] else "[bold red]FAIL[/bold red]"
            tbl.add_row(c["id"], c["name"], c["eu_cra"], c["nist_ssdf"], st, c["evidence"])
        console.print(tbl)

    if fail_on_noncompliant and data["status"] != "COMPLIANT":
        raise typer.Exit(code=EXIT_POLICY_VIOLATION)


@app.command()
def aibom(
    target: Path = typer.Argument(".", help="待静态发现 AI 模型、权重文件与数据集的目标仓库目录"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="导出 CycloneDX 1.6 ML-BOM JSON 文件路径"),
    json_output: bool = typer.Option(False, "--json", help="向 stdout 输出纯净 CycloneDX 1.6 AIBOM JSON"),
) -> None:
    """静态发现仓库引用的 AI 模型、本地权重（SafeTensors/GGUF/ONNX/PyTorch）与数据集，生成 CycloneDX 1.6 ML-BOM (AIBOM)。"""
    from openguard.aibom import discover_ai_assets, render_cyclonedx_aibom

    if not target.exists():
        err_console.print(f"[bold red]目标路径不存在:[/bold red] {target}")
        raise typer.Exit(code=EXIT_USER_ERROR)

    cfg = load_config(target if target.is_dir() else target.parent)
    rep = discover_ai_assets(target, exclude_patterns=cfg.exclude_patterns)
    cdx = render_cyclonedx_aibom(rep)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(cdx, indent=2, ensure_ascii=False), encoding="utf-8")
        notice_console = err_console if json_output else console
        notice_console.print(f"[green]已导出 CycloneDX 1.6 AIBOM ({len(rep.assets)} 项 AI 资产):[/green] {output}")

    if json_output:
        sys.stdout.write(json.dumps(cdx, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return

    tbl = Table(
        title=f"OpenGuard CycloneDX 1.6 AI 物料清单 (AIBOM) — 模型 {rep.model_count} 项 | 数据集 {rep.dataset_count} 项",
        show_header=True,
    )
    tbl.add_column("资产名称")
    tbl.add_column("类型")
    tbl.add_column("来源/格式")
    tbl.add_column("提供方")
    tbl.add_column("位置")
    tbl.add_column("安全/锁定状态")
    for a in rep.assets:
        status = (
            "[green]安全格式[/green]"
            if a.safe_format is True
            else ("[bold red]Pickle 反序列化风险[/bold red]" if a.safe_format is False else ("[green]已锁版本[/green]" if a.pinned else "[yellow]未锁 revision[/yellow]"))
        )
        tbl.add_row(a.name, a.asset_type, a.format_name, a.provider, f"{a.source_file}:{a.line_number}", status)
    console.print(tbl)


@app.command()
def version() -> None:
    """输出当前 OpenGuard 版本信息。"""
    console.print(f"OpenGuard (开源卫士) v{__version__}")


if __name__ == "__main__":
    app()
