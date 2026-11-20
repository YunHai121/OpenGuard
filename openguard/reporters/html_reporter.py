"""Self-contained interactive single-file HTML audit report (Editorial Light-First Design, Zero CDN)."""

from __future__ import annotations

import html
import json
from typing import List

from openguard.models import AuditReport


def _build_dim_bars_html(report: AuditReport) -> str:
    rows: List[str] = []
    for d in report.summary.dimensions:
        color = "#16a34a" if d.score >= 85 else ("#d97706" if d.score >= 60 else "#dc2626")
        rows.append(
            f'<div class="dim-item">'
            f'<div class="dim-head"><span><strong>{html.escape(d.name)}</strong> '
            f'<span class="muted">({int(d.weight * 100)}%)</span></span>'
            f'<span class="mono"><strong>{d.score:.1f}</strong> · {d.issue_count} 项</span></div>'
            f'<div class="dim-track"><div class="dim-fill" style="width:{max(2.0, d.score):.1f}%;background:{color};"></div></div>'
            f'<div class="muted-xs">{html.escape(d.summary)}</div>'
            f'</div>'
        )
    return "\n".join(rows)


def render_html_report(report: AuditReport) -> str:
    """Render a clean, self-contained HTML security & compliance audit report."""
    s = report.summary
    qg = s.quality_gate
    is_pass = qg.status == "PASSED" if qg else (s.total_score >= 80)

    def esc(val: object) -> str:
        return html.escape(str(val or ""))

    def sev_badge(sev: str) -> str:
        sv = str(sev).upper()
        return f'<span class="badge sev-{sv.lower()}">{esc(sv)}</span>'

    conds_html = "".join(
        f'<div class="qg-cond {"pass" if c.passed else "fail"}">'
        f'<span>{esc(c.label)}</span>'
        f'<strong class="mono">{c.actual} <span class="muted">({esc(c.threshold)})</span></strong>'
        f'</div>'
        for c in (qg.conditions if qg else [])
    )

    finding_cards: List[str] = []
    for f in [*report.secrets, *report.git_history_secrets]:
        kind = "history" if f.is_historical_only else "secret"
        tag = f"GHOST {f.commit_hash}" if f.is_historical_only else "明文凭据"
        meta = (
            f"作者 {f.commit_author} ({f.commit_date})"
            if f.is_historical_only
            else f"置信度 {f.confidence:.2f} · Shannon 熵 {f.entropy:.2f} · AST: {f.ast_context}"
        )
        runbook = "".join(f"<li>{esc(step)}</li>" for step in (f.runbook_steps or [f.remediation]))
        finding_cards.append(
            f'<div class="finding-card" data-kind="{kind}">'
            f'<div class="finding-head">{sev_badge(str(f.severity))}'
            f'<span class="kind-pill">{esc(tag)}</span>'
            f'<strong>{esc(f.rule_name)}</strong>'
            f'<code class="loc">{esc(f.file_path)}:{f.line_number}</code></div>'
            f'<div class="muted-xs" style="margin-bottom:6px;">脱敏凭据：<code>{esc(f.matched_masked)}</code> · {esc(meta)}</div>'
            f'<pre class="code-snip">{esc(f.snippet)}</pre>'
            f'<ul class="runbook-ul">{runbook}</ul>'
            f'</div>'
        )

    for lc in report.license_conflicts:
        chain = " -> ".join(lc.dependency_path)
        finding_cards.append(
            f'<div class="finding-card" data-kind="license">'
            f'<div class="finding-head">{sev_badge(str(lc.severity))}'
            f'<span class="kind-pill">{esc(lc.compatibility)}</span>'
            f'<strong>{esc(lc.component_name)} ({esc(lc.component_license)} vs {esc(lc.project_license)})</strong>'
            f'<code class="loc">{esc(chain)}</code></div>'
            f'<div style="font-size:13px;">{esc(lc.explanation)}</div>'
            f'<div class="fix-tip">建议：{esc(lc.remediation)}</div>'
            f'</div>'
        )

    for v in report.vulnerabilities:
        reach_pill = (
            "INSTALL SCRIPT"
            if v.source == "install_script"
            else ("TYPOSQUAT" if v.source == "typosquatting" else ("REACHABLE" if v.reachable is True else ("UNREACHABLE" if v.reachable is False else f"CVSS {v.cvss_score}")))
        )
        locs = f" · 调用点: {', '.join(v.import_locations)}" if v.import_locations else ""
        finding_cards.append(
            f'<div class="finding-card" data-kind="vuln">'
            f'<div class="finding-head">{sev_badge(str(v.severity))}'
            f'<span class="kind-pill">{esc(reach_pill)}</span>'
            f'<strong>{esc(v.id)} · {esc(v.component_name)}@{esc(v.component_version)}</strong>'
            f'<code class="loc">{esc(v.ecosystem)} · 安全版本 {esc(v.fixed_version)}</code></div>'
            f'<div style="font-size:13px;">{esc(v.summary)}<span class="muted-xs">{esc(locs)}</span></div>'
            f'<div class="fix-tip">建议：{esc(v.remediation)}</div>'
            f'</div>'
        )

    for cs in report.code_security_findings:
        finding_cards.append(
            f'<div class="finding-card" data-kind="sast">'
            f'<div class="finding-head">{sev_badge(str(cs.severity))}'
            f'<span class="kind-pill">SAST · {esc(cs.cwe_id)}</span>'
            f'<strong>{esc(cs.rule_name)}</strong>'
            f'<code class="loc">{esc(cs.file_path)}:{cs.line_number}</code></div>'
            f'<div style="font-size:13px;">{esc(cs.description)}</div>'
            f'<pre class="code-snip">{esc(cs.snippet)}</pre>'
            f'<div class="fix-tip">建议：{esc(cs.remediation)}</div>'
            f'</div>'
        )

    findings_html = "\n".join(finding_cards) or '<div class="empty-ok">未检出安全隐患或合规冲突，质量门禁全部通过。</div>'

    sbom_rows = "\n".join(
        f"<tr><td><code>{esc(c.name)}</code></td><td class='mono'>{esc(c.version)}</td><td>{esc(c.ecosystem)}</td>"
        f"<td>{'已导入调用' if c.used_in_code else '未直接引用'}</td>"
        f"<td><code>{esc(c.license_id)}</code></td><td><code>{esc(c.source_file)}</code></td></tr>"
        for c in report.components
    ) or '<tr><td colspan="6" class="muted">未解析到外部依赖清单。</td></tr>'

    gov_rows = "\n".join(
        f"<tr><td><strong>{esc(g.name)}</strong></td><td class='muted'>{esc(g.category)}</td>"
        f"<td><span class='badge {'sev-ok' if g.passed else 'sev-medium'}'>{'通过' if g.passed else '待完善'}</span></td>"
        f"<td class='mono'>{g.score:.0f}/{g.max_score:.0f}</td><td>{esc(g.details)}</td></tr>"
        for g in report.governance_checks
    )

    dim_bars_html = _build_dim_bars_html(report)
    reach_count = sum(1 for v in report.vulnerabilities if v.reachable is True)
    unreach_count = sum(1 for v in report.vulnerabilities if v.reachable is False)
    roadmap_html = "\n".join(
        f"<div class='roadmap-item'><span class='badge sev-high'>{esc(r['priority'])}</span> "
        f"<strong>{esc(r['title'])}</strong><div class='muted-xs' style='margin-top:4px;'>{esc(r['action'])}</div></div>"
        for r in s.roadmap
    ) or "<div class='empty-ok'>无紧急整改项。</div>"

    meta_json = json.dumps({"scan_id": report.scan_id, "score": s.total_score}, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenGuard 审计报告 - {esc(report.target_name)}</title>
<style>
  :root {{
    --bg: #f8f9fb; --surface: #ffffff; --surface-sub: #f2f4f7; --border: #e4e7ec;
    --text: #101828; --text-muted: #667085; --primary: #111827; --code-bg: #f6f8fa;
  }}
  body.theme-dark {{
    --bg: #09090b; --surface: #111113; --surface-sub: #18181b; --border: #27272a;
    --text: #fafafa; --text-muted: #a1a1aa; --primary: #fafafa; --code-bg: #141417;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); font-size: 13.5px; line-height: 1.5; }}
  .container {{ max-width: 1180px; margin: 0 auto; padding: 24px 20px 56px; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 18px; }}
  .brand {{ font-size: 18px; font-weight: 700; letter-spacing: -0.2px; }}
  .btn {{ background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12.5px; font-weight: 500; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 18px; margin-bottom: 16px; }}
  .card h2 {{ margin: 0 0 12px; font-size: 14px; font-weight: 600; }}
  .qg-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }}
  .qg-pill {{ padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }}
  .qg-passed {{ background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }}
  .qg-failed {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
  .qg-conds {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 8px; }}
  .qg-cond {{ display: flex; justify-content: space-between; padding: 7px 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); font-size: 12px; }}
  .qg-cond.pass {{ border-left: 3px solid #15803d; }} .qg-cond.fail {{ border-left: 3px solid #b91c1c; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }}
  .dim-item {{ margin-bottom: 11px; }}
  .dim-head {{ display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px; }}
  .dim-track {{ height: 7px; background: var(--surface-sub); border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }}
  .dim-fill {{ height: 100%; border-radius: 999px; }}
  .kpi-row {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 12px; }}
  .kpi {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 9px 11px; }}
  .kpi .num {{ font-size: 18px; font-weight: 700; }}
  .muted {{ color: var(--text-muted); }} .muted-xs {{ color: var(--text-muted); font-size: 12px; }}
  .mono, code, pre {{ font-family: "Cascadia Code", Consolas, monospace; }}
  code {{ background: var(--surface-sub); padding: 1px 5px; border-radius: 4px; font-size: 11.5px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: var(--text-muted); background: var(--bg); font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .sev-critical {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
  .sev-high {{ background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }}
  .sev-medium {{ background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }}
  .sev-low {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
  .sev-ok {{ background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }}
  .kind-pill {{ font-size: 11px; padding: 2px 7px; border-radius: 999px; background: var(--surface-sub); border: 1px solid var(--border); font-weight: 600; }}
  .toolbar {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }}
  .tab {{ background: var(--bg); border: 1px solid var(--border); color: var(--text-muted); padding: 5px 10px; border-radius: 999px; cursor: pointer; font-size: 12px; }}
  .tab.active {{ background: var(--primary); color: var(--bg); border-color: var(--primary); }}
  .search-input {{ margin-left: auto; background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 6px; min-width: 220px; font-size: 12.5px; }}
  .finding-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; margin-bottom: 10px; }}
  .finding-head {{ display: flex; align-items: center; gap: 7px; flex-wrap: wrap; margin-bottom: 6px; }}
  .finding-head .loc {{ margin-left: auto; }}
  .code-snip {{ margin: 6px 0; padding: 8px 10px; background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; overflow-x: auto; font-size: 12px; }}
  .runbook-ul {{ margin: 6px 0 0; padding-left: 18px; font-size: 12px; color: var(--text-muted); }}
  .fix-tip {{ color: #15803d; font-size: 12px; margin-top: 6px; }}
  .roadmap-item {{ padding: 8px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; }}
  .empty-ok {{ padding: 18px; text-align: center; color: #15803d; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
    <div class="brand" style="display:flex;align-items:center;gap:8px;">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3"/><path d="M9 12l2 2l4 -4"/></svg>
      <span>OpenGuard 供应链安全与合规审计报告 · {esc(report.target_name)}</span>
    </div>
      <div class="muted-xs">主许可证: <code>{esc(report.project_license)}</code> | 扫描 ID: <code>{esc(report.scan_id)}</code> | {esc(report.scanned_at)} | 耗时 {s.scan_duration_ms:.1f} ms</div>
    </div>
    <button class="btn" onclick="document.body.classList.toggle('theme-dark')">切换浅色 / 深色模式</button>
  </div>

  <div class="card">
    <div class="qg-top">
      <div><span class="qg-pill {"qg-passed" if is_pass else "qg-failed"}">QUALITY GATE {esc(qg.status if qg else "DONE")}</span></div>
      <div style="font-size:22px;font-weight:700;">{s.total_score:.1f} <span class="muted" style="font-size:13px;">/ 100 · 等级 {esc(s.grade)}</span></div>
    </div>
    <div class="qg-conds">{conds_html}</div>
  </div>

  <div class="grid-2">
    <div class="card"><h2>五维安全与合规评估指标</h2>{dim_bars_html}</div>
    <div class="card">
      <h2>漏洞可达性与整改路线图</h2>
      <div class="kpi-row">
        <div class="kpi"><div class="num" style="color:#b91c1c;">{reach_count}</div><div class="muted-xs">源码可达 CVE/投毒</div></div>
        <div class="kpi"><div class="num">{unreach_count}</div><div class="muted-xs">未直接导入 CVE</div></div>
        <div class="kpi"><div class="num" style="color:#15803d;">{report.suppressed_count}</div><div class="muted-xs">AST+熵值过滤误报</div></div>
      </div>
      {roadmap_html}
    </div>
  </div>

  <div class="card">
    <h2>风险发现与溯源详情 ({len(finding_cards)})</h2>
    <div class="toolbar">
      <button class="tab active" onclick="filterFindings('all', this)">全部 ({len(finding_cards)})</button>
      <button class="tab" onclick="filterFindings('secret', this)">工作区密钥 ({len(report.secrets)})</button>
      <button class="tab" onclick="filterFindings('history', this)">Git 历史密钥 ({len(report.git_history_secrets)})</button>
      <button class="tab" onclick="filterFindings('license', this)">许可证冲突 ({len(report.license_conflicts)})</button>
      <button class="tab" onclick="filterFindings('vuln', this)">漏洞与投毒 ({len(report.vulnerabilities)})</button>
      <button class="tab" onclick="filterFindings('sast', this)">SAST ({len(report.code_security_findings)})</button>
      <input class="search-input" type="search" placeholder="过滤文件 / CVE / 规则..." oninput="searchFindings(this.value)">
    </div>
    <div>{findings_html}</div>
  </div>

  <div class="card">
    <h2>软件物料清单 SBOM ({len(report.components)} 组件)</h2>
    <table>
      <thead><tr><th>组件</th><th>版本</th><th>生态</th><th>代码引用状态</th><th>SPDX 许可证</th><th>来源文件</th></tr></thead>
      <tbody>{sbom_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>开源工程规范治理体检 (12 项)</h2>
    <table>
      <thead><tr><th>检查项</th><th>类别</th><th>状态</th><th>得分</th><th>详情</th></tr></thead>
      <tbody>{gov_rows}</tbody>
    </table>
  </div>
</div>
<script>
  const OG_META = {meta_json};
  let activeKind = 'all', queryText = '';
  function applyFilters() {{
    document.querySelectorAll('.finding-card').forEach(el => {{
      const k = el.getAttribute('data-kind');
      const okKind = activeKind === 'all' || k === activeKind;
      const okSearch = !queryText || el.textContent.toLowerCase().includes(queryText);
      el.style.display = (okKind && okSearch) ? '' : 'none';
    }});
  }}
  function filterFindings(kind, btn) {{
    activeKind = kind;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    if (btn) btn.classList.add('active');
    applyFilters();
  }}
  function searchFindings(val) {{
    queryText = (val || '').trim().toLowerCase();
    applyFilters();
  }}
</script>
</body>
</html>
"""
