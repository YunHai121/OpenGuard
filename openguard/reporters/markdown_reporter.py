"""GitHub / GitLab-flavored Markdown report generator."""

from __future__ import annotations

from typing import List

from openguard.models import AuditReport


def render_markdown_report(report: AuditReport) -> str:
    """Render a structured Markdown summary report suitable for PR comments or documentation."""
    s = report.summary
    qg = s.quality_gate
    qg_label = f" | **质量门禁**: `{qg.status}`" if qg else ""
    lines: List[str] = [
        f"# OpenGuard 安全与开源合规审计报告 — `{report.target_name}`",
        "",
        f"> **综合评分**: **{s.total_score:.1f} / 100**（等级 **{s.grade}**）{qg_label} | "
        f"**项目许可证**: `{report.project_license}` | "
        f"**扫描编号**: `{report.scan_id}` | "
        f"**扫描耗时**: `{s.scan_duration_ms:.1f} ms`",
        "",
        "## 1. 五维合规评分概览",
        "",
        "| 评估维度 | 得分 | 权重 | 加权得分 | 问题数 | 诊断摘要 |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]

    for d in s.dimensions:
        lines.append(
            f"| {d.name} | **{d.score:.1f}** | {int(d.weight * 100)}% | {d.weighted_score:.1f} | {d.issue_count} | {d.summary} |"
        )

    lines.extend([
        "",
        "## 2. 风险严重程度分布",
        "",
        f"- **CRITICAL**: {s.severity_counts.get('CRITICAL', 0)}  |  "
        f"**HIGH**: {s.severity_counts.get('HIGH', 0)}  |  "
        f"**MEDIUM**: {s.severity_counts.get('MEDIUM', 0)}  |  "
        f"**LOW**: {s.severity_counts.get('LOW', 0)}",
        f"- 扫描文件数：`{s.files_scanned}`，代码总行数：`{s.lines_scanned}`，AST+熵值自动过滤低置信误报：`{report.suppressed_count}` 条。",
        "",
    ])

    all_secrets = [*report.secrets, *report.git_history_secrets]
    if all_secrets:
        lines.extend([
            "## 3. 敏感信息与 Git 历史泄密清单",
            "",
            "| 类型 | 级别 | 规则 | 文件与行号 | 脱敏凭据 | 置信度 / AST 上下文 | 历史提交 |",
            "| :--- | :---: | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in all_secrets[:50]:
            hist = f"`{f.commit_hash}` ({f.commit_date})" if f.is_historical_only else "工作区当前文件"
            lines.append(
                f"| {'历史残留' if f.is_historical_only else '工作区'} | **{f.severity}** | {f.rule_name} | "
                f"`{f.file_path}:{f.line_number}` | `{f.matched_masked}` | {f.confidence:.2f} (`{f.ast_context}`) | {hist} |"
            )
        lines.append("")

    if report.license_conflicts:
        lines.extend([
            "## 4. 开源许可证传染性冲突",
            "",
            "| 组件 | 版本 | 组件许可证 | 项目许可证 | 判定 | 依赖传播链 |",
            "| :--- | :--- | :---: | :---: | :---: | :--- |",
        ])
        for lc in report.license_conflicts:
            chain = " -> ".join(lc.dependency_path)
            lines.append(
                f"| `{lc.component_name}` | `{lc.component_version}` | `{lc.component_license}` | "
                f"`{lc.project_license}` | **{lc.compatibility}** ({lc.severity}) | `{chain}` |"
            )
        lines.append("")

    if report.vulnerabilities:
        lines.extend([
            "## 5. 供应链已知漏洞 (CVE) 与投毒告警",
            "",
            "| 编号 | 组件 | 当前版本 | 级别 / CVSS | 修复建议版本 | 摘要 |",
            "| :--- | :--- | :--- | :---: | :--- | :--- |",
        ])
        for v in report.vulnerabilities:
            lines.append(
                f"| `{v.id}` | `{v.component_name}` ({v.ecosystem}) | `{v.component_version}` | "
                f"**{v.severity}** ({v.cvss_score}) | `{v.fixed_version}` | {v.summary} |"
            )
        lines.append("")

    if report.code_security_findings:
        lines.extend([
            "## 6. 静态代码安全隐患 (SAST)",
            "",
            "| 规则 / CWE | 级别 | 位置 | 说明 |",
            "| :--- | :---: | :--- | :--- |",
        ])
        for cs in report.code_security_findings:
            lines.append(
                f"| `{cs.rule_id}` ({cs.cwe_id}) | **{cs.severity}** | `{cs.file_path}:{cs.line_number}` | {cs.description} |"
            )
        lines.append("")

    lines.extend([
        "## 7. 开源工程规范体检 (12 项)",
        "",
        "| 检查项 | 类别 | 状态 | 得分 | 详情 |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ])
    for g in report.governance_checks:
        icon = "PASS" if g.passed else "FAIL"
        lines.append(f"| {g.name} | {g.category} | **{icon}** | {g.score:.0f}/{g.max_score:.0f} | {g.details} |")

    if s.roadmap:
        lines.extend(["", "## 8. 优先整改路线图", ""])
        for step in s.roadmap:
            lines.append(f"- **[{step['priority']}] {step['title']}**：{step['action']}")

    lines.append("")
    return "\n".join(lines)


def render_pr_comment(report: AuditReport) -> str:
    """Render a compact Semgrep/Socket-style PR / MR review comment in Markdown."""
    s = report.summary
    qg = s.quality_gate
    gate_badge = (
        "PASSED" if (qg and qg.status == "PASSED") else ("FAILED" if qg else "N/A")
    )
    scope_note = (
        f"Diff vs `{report.diff_base_ref}`" if report.diff_base_ref else "Full repository scan"
    )

    lines: List[str] = [
        f"<!-- openguard-pr-comment -->",
        f"## OpenGuard Security & Compliance Check — **{gate_badge}**",
        "",
        f"| Metric | Value |",
        f"| :--- | :--- |",
        f"| **Quality Gate** | **{gate_badge}** |",
        f"| **Score / Grade** | **{s.total_score:.1f} / 100** (`{s.grade}`) |",
        f"| **Scope** | {scope_note} ({s.files_scanned} files, {s.scan_duration_ms:.0f} ms) |",
        f"| **Findings** | CRITICAL: `{s.severity_counts.get('CRITICAL', 0)}` · HIGH: `{s.severity_counts.get('HIGH', 0)}` · MEDIUM: `{s.severity_counts.get('MEDIUM', 0)}` · LOW: `{s.severity_counts.get('LOW', 0)}` |",
    ]
    if report.baseline_suppressed_count > 0:
        lines.append(f"| **Baseline Suppressed** | `{report.baseline_suppressed_count}` pre-existing findings skipped |")

    lines.append("")

    if qg and qg.conditions:
        failed_conds = [c for c in qg.conditions if not c.passed]
        if failed_conds:
            lines.append("### Blocking Gate Conditions")
            for c in failed_conds:
                lines.append(f"- **FAIL** {c.label}: actual `{c.actual}` (threshold `{c.threshold}`)")
            lines.append("")

    actionable: List[str] = []
    for sec in [*report.secrets, *report.git_history_secrets][:8]:
        actionable.append(
            f"| `{sec.severity}` | Secret (`{sec.rule_id}`) | `{sec.file_path}:{sec.line_number}` | {sec.rule_name} (`{sec.matched_masked}`) |"
        )
    for v in [x for x in report.vulnerabilities if x.reachable is not False][:8]:
        reach = v.reachability_level
        actionable.append(
            f"| `{v.severity}` | Supply Chain (`{v.id}`) | `{v.source_file or v.component_name}` | `{v.component_name}@{v.component_version}` ({reach}) -> upgrade `{v.fixed_version}` |"
        )
    for cs in report.code_security_findings[:8]:
        actionable.append(
            f"| `{cs.severity}` | Code/CI/Docker (`{cs.rule_id}`) | `{cs.file_path}:{cs.line_number}` | {cs.rule_name} ({cs.cwe_id}) |"
        )
    for lc in report.license_conflicts[:5]:
        actionable.append(
            f"| `{lc.severity}` | License | `{lc.component_name}` | `{lc.component_license}` vs `{lc.project_license}` ({lc.compatibility}) |"
        )

    if actionable:
        lines.extend([
            "### Actionable Findings",
            "",
            "| Severity | Category | Location | Details |",
            "| :---: | :--- | :--- | :--- |",
            *actionable,
            "",
        ])
    else:
        lines.append("No new blocking security, supply-chain, CI/CD, or compliance issues detected.")
        lines.append("")

    lines.append(f"<sub>Generated by OpenGuard v{report.tool_version} · `openguard autofix . --secrets --deps`</sub>")
    return "\n".join(lines) + "\n"
