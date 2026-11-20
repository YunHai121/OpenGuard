"""Self-contained interactive single-file HTML audit report generator (offline, zero CDN)."""

from __future__ import annotations

import html
import json
import math
from typing import List

from openguard.models import AuditReport


def _build_radar_svg(report: AuditReport) -> str:
    """Compute a pure SVG 5-axis radar chart for the 5 audit dimensions."""
    dims = report.summary.dimensions
    cx, cy, r = 140.0, 125.0, 82.0
    n = len(dims) or 5
    short_labels = ["密钥安全", "供应链漏洞", "许可证合规", "代码安全", "工程治理"]

    grid_rings = []
    for ratio in (0.25, 0.5, 0.75, 1.0):
        pts = []
        for i in range(n):
            ang = -math.pi / 2 + (2 * math.pi * i) / n
            pts.append(f"{cx + r * ratio * math.cos(ang):.1f},{cy + r * ratio * math.sin(ang):.1f}")
        grid_rings.append(f'<polygon points="{" ".join(pts)}" fill="none" stroke="var(--border)" stroke-width="1"/>')

    axes = []
    labels = []
    data_pts = []
    dots = []
    for i, dim in enumerate(dims):
        ang = -math.pi / 2 + (2 * math.pi * i) / n
        ax_x = cx + r * math.cos(ang)
        ax_y = cy + r * math.sin(ang)
        axes.append(f'<line x1="{cx}" y1="{cy}" x2="{ax_x:.1f}" y2="{ax_y:.1f}" stroke="var(--border)" stroke-width="1"/>')

        val_ratio = max(0.05, min(1.0, dim.score / 100.0))
        px = cx + r * val_ratio * math.cos(ang)
        py = cy + r * val_ratio * math.sin(ang)
        data_pts.append(f"{px:.1f},{py:.1f}")
        dots.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="#6366f1" stroke="#fff" stroke-width="1.5"/>')

        lx = cx + (r + 24) * math.cos(ang)
        ly = cy + (r + 18) * math.sin(ang) + 4
        anchor = "middle"
        if math.cos(ang) > 0.25:
            anchor = "start"
            lx -= 6
        elif math.cos(ang) < -0.25:
            anchor = "end"
            lx += 6
        lbl = short_labels[i] if i < len(short_labels) else dim.name
        labels.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" font-size="11" fill="var(--text-muted)" font-weight="600">'
            f'{html.escape(lbl)} ({dim.score:.0f})</text>'
        )

    return f"""<svg viewBox="0 0 280 250" width="280" height="250" aria-label="五维安全评分雷达图">
  {"".join(grid_rings)}
  {"".join(axes)}
  <polygon points="{" ".join(data_pts)}" fill="rgba(99,102,241,0.25)" stroke="#6366f1" stroke-width="2.2"/>
  {"".join(dots)}
  {"".join(labels)}
</svg>"""


def _build_gauge_svg(score: float, grade: str) -> str:
    radius = 58
    circumference = 2 * math.pi * radius
    offset = circumference * (1 - max(0.0, min(100.0, score)) / 100.0)
    color = "#10b981" if score >= 90 else ("#3b82f6" if score >= 80 else ("#f59e0b" if score >= 70 else "#ef4444"))
    return f"""<svg viewBox="0 0 150 150" width="146" height="146">
  <circle cx="75" cy="75" r="{radius}" fill="none" stroke="var(--border)" stroke-width="12"/>
  <circle cx="75" cy="75" r="{radius}" fill="none" stroke="{color}" stroke-width="12"
          stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{offset:.1f}"
          stroke-linecap="round" transform="rotate(-90 75 75)"/>
  <text x="75" y="70" text-anchor="middle" font-size="28" font-weight="800" fill="var(--text)">{score:.1f}</text>
  <text x="75" y="94" text-anchor="middle" font-size="14" font-weight="700" fill="{color}">等级 {html.escape(grade)}</text>
</svg>"""


def render_html_report(report: AuditReport) -> str:
    """Render an interactive, self-contained HTML security & compliance dashboard report."""
    s = report.summary
    gauge_svg = _build_gauge_svg(s.total_score, s.grade)
    radar_svg = _build_radar_svg(report)

    def esc(val: object) -> str:
        return html.escape(str(val or ""))

    def sev_badge(sev: str) -> str:
        sv = str(sev).upper()
        cls = sv.lower()
        return f'<span class="badge sev-{cls}">{esc(sv)}</span>'

    # Unified table rows for interactive filtering
    finding_cards: List[str] = []
    for f in [*report.secrets, *report.git_history_secrets]:
        kind = "history" if f.is_historical_only else "secret"
        tag = "Git历史残留" if f.is_historical_only else "明文密钥/敏感信息"
        meta = f"Commit {f.commit_hash} ({f.commit_author}, {f.commit_date})" if f.is_historical_only else f"置信度 {f.confidence:.2f} | 熵值 {f.entropy:.2f} | AST上下文: {f.ast_context}"
        finding_cards.append(
            f'<div class="finding-card" data-kind="{kind}" data-sev="{esc(f.severity)}">'
            f'<div class="finding-head">{sev_badge(str(f.severity))}'
            f'<span class="kind-pill">{tag}</span>'
            f'<strong>{esc(f.rule_name)}</strong>'
            f'<code class="loc">{esc(f.file_path)}:{f.line_number}</code></div>'
            f'<div class="finding-body">'
            f'<div>脱敏值：<code>{esc(f.matched_masked)}</code> &nbsp;|&nbsp; <span class="muted">{esc(meta)}</span></div>'
            f'<pre class="code-snip">{esc(f.snippet)}</pre>'
            f'<div class="fix-tip">建议：{esc(f.remediation)}</div>'
            f'</div></div>'
        )

    for lc in report.license_conflicts:
        chain = " -> ".join(lc.dependency_path)
        finding_cards.append(
            f'<div class="finding-card" data-kind="license" data-sev="{esc(lc.severity)}">'
            f'<div class="finding-head">{sev_badge(str(lc.severity))}'
            f'<span class="kind-pill">许可证冲突</span>'
            f'<strong>{esc(lc.component_name)} ({esc(lc.component_license)} vs {esc(lc.project_license)})</strong>'
            f'<code class="loc">{esc(lc.compatibility)}</code></div>'
            f'<div class="finding-body">'
            f'<div>依赖传播路径：<code>{esc(chain)}</code></div>'
            f'<div style="margin-top:6px;">{esc(lc.explanation)}</div>'
            f'<div class="fix-tip">建议：{esc(lc.remediation)}</div>'
            f'</div></div>'
        )

    for v in report.vulnerabilities:
        finding_cards.append(
            f'<div class="finding-card" data-kind="vuln" data-sev="{esc(v.severity)}">'
            f'<div class="finding-head">{sev_badge(str(v.severity))}'
            f'<span class="kind-pill">{"仿冒包告警" if v.source == "typosquatting" else "供应链 CVE"}</span>'
            f'<strong>{esc(v.id)} · {esc(v.component_name)}@{esc(v.component_version)}</strong>'
            f'<code class="loc">{esc(v.ecosystem)} · CVSS {v.cvss_score}</code></div>'
            f'<div class="finding-body">'
            f'<div>{esc(v.summary)}</div>'
            f'<div class="fix-tip">建议版本：<code>{esc(v.fixed_version)}</code> — {esc(v.remediation)}</div>'
            f'</div></div>'
        )

    for cs in report.code_security_findings:
        finding_cards.append(
            f'<div class="finding-card" data-kind="sast" data-sev="{esc(cs.severity)}">'
            f'<div class="finding-head">{sev_badge(str(cs.severity))}'
            f'<span class="kind-pill">SAST · {esc(cs.cwe_id)}</span>'
            f'<strong>{esc(cs.rule_name)}</strong>'
            f'<code class="loc">{esc(cs.file_path)}:{cs.line_number}</code></div>'
            f'<div class="finding-body">'
            f'<div>{esc(cs.description)}</div>'
            f'<pre class="code-snip">{esc(cs.snippet)}</pre>'
            f'<div class="fix-tip">建议：{esc(cs.remediation)}</div>'
            f'</div></div>'
        )

    findings_html = "\n".join(finding_cards) if finding_cards else '<div class="empty-ok">未检出高危密钥、许可证冲突、漏洞或 SAST 缺陷。</div>'

    sbom_rows = "\n".join(
        f"<tr><td><code>{esc(c.name)}</code></td><td>{esc(c.version)}</td><td>{esc(c.ecosystem)}</td>"
        f"<td><span class='lic-tag'>{esc(c.license_id)}</span></td><td>{'直接依赖' if c.direct else '传递依赖'}</td>"
        f"<td><code>{esc(c.source_file)}</code></td></tr>"
        for c in report.components
    ) or '<tr><td colspan="6" class="muted">未解析到第三方依赖清单。</td></tr>'

    gov_rows = "\n".join(
        f"<tr><td>{esc(g.name)}</td><td>{esc(g.category)}</td>"
        f"<td><span class='badge {'sev-ok' if g.passed else 'sev-medium'}'>{'通过' if g.passed else '待完善'}</span></td>"
        f"<td>{g.score:.0f} / {g.max_score:.0f}</td><td>{esc(g.details)}</td></tr>"
        for g in report.governance_checks
    )

    roadmap_html = "\n".join(
        f"<div class='roadmap-item'><span class='badge sev-high'>{esc(r['priority'])}</span> "
        f"<strong>{esc(r['title'])}</strong><p>{esc(r['action'])} <span class='muted'>({esc(r['impact'])})</span></p></div>"
        for r in s.roadmap
    ) or "<div class='empty-ok'>项目整体状况优秀，暂无紧急整改项。</div>"

    dim_rows = "\n".join(
        f"<tr><td><strong>{esc(d.name)}</strong></td><td>{d.score:.1f}</td><td>{int(d.weight*100)}%</td>"
        f"<td>{d.weighted_score:.1f}</td><td>{d.issue_count}</td><td>{esc(d.summary)}</td></tr>"
        for d in s.dimensions
    )

    report_json_safe = json.dumps({"scan_id": report.scan_id, "score": s.total_score}, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenGuard 审计报告 - {esc(report.target_name)}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface-2: #0b1220; --border: #334155;
    --text: #f1f5f9; --text-muted: #94a3b8; --accent: #6366f1;
  }}
  body.light {{
    --bg: #f8fafc; --surface: #ffffff; --surface-2: #f1f5f9; --border: #cbd5e1;
    --text: #0f172a; --text-muted: #475569; --accent: #4f46e5;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); line-height: 1.55; }}
  .container {{ max-width: 1220px; margin: 0 auto; padding: 24px 20px 56px; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 22px; }}
  .brand {{ font-size: 22px; font-weight: 800; letter-spacing: -0.3px; }}
  .brand span {{ color: var(--accent); }}
  .meta-line {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
  .btn {{ background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 7px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; }}
  .btn:hover {{ border-color: var(--accent); }}
  .grid-top {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 18px; margin-bottom: 22px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
  .card h2 {{ margin: 0 0 12px; font-size: 15px; color: var(--text); border-left: 3px solid var(--accent); padding-left: 10px; }}
  .flex-center {{ display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; flex: 1; min-width: 170px; }}
  .kpi {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }}
  .kpi .num {{ font-size: 20px; font-weight: 800; }}
  .kpi .lbl {{ font-size: 12px; color: var(--text-muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 9px 10px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: var(--text-muted); font-weight: 600; background: var(--surface-2); }}
  code {{ font-family: Consolas, Monaco, monospace; background: var(--surface-2); padding: 2px 6px; border-radius: 5px; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }}
  .sev-critical {{ background: #dc2626; }} .sev-high {{ background: #ea580c; }} .sev-medium {{ background: #d97706; color: #111827; }}
  .sev-low {{ background: #2563eb; }} .sev-info {{ background: #64748b; }} .sev-ok {{ background: #059669; }}
  .kind-pill {{ font-size: 11px; padding: 2px 8px; border-radius: 6px; background: rgba(99,102,241,0.16); color: #a5b4fc; border: 1px solid rgba(99,102,241,0.35); font-weight: 600; }}
  body.light .kind-pill {{ color: #4338ca; }}
  .lic-tag {{ padding: 2px 7px; border-radius: 5px; border: 1px solid var(--border); font-size: 12px; }}
  .toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }}
  .tab {{ background: var(--surface-2); border: 1px solid var(--border); color: var(--text-muted); padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; }}
  .tab.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
  .search-input {{ margin-left: auto; background: var(--surface-2); border: 1px solid var(--border); color: var(--text); padding: 7px 12px; border-radius: 8px; min-width: 220px; font-size: 13px; }}
  .finding-card {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 13px 15px; margin-bottom: 11px; }}
  .finding-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }}
  .finding-head .loc {{ margin-left: auto; }}
  .finding-body {{ font-size: 13px; }}
  .code-snip {{ margin: 8px 0; padding: 8px 10px; background: #020617; color: #e2e8f0; border-radius: 7px; overflow-x: auto; font-size: 12px; font-family: Consolas, monospace; }}
  .fix-tip {{ color: #34d399; font-size: 12.5px; margin-top: 6px; }}
  body.light .fix-tip {{ color: #047857; }}
  .muted {{ color: var(--text-muted); }}
  .empty-ok {{ padding: 20px; text-align: center; color: #10b981; font-weight: 600; }}
  .roadmap-item {{ padding: 10px 12px; background: var(--surface-2); border-radius: 8px; border: 1px solid var(--border); margin-bottom: 8px; }}
  .roadmap-item p {{ margin: 5px 0 0; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="brand">OpenGuard <span>开源卫士</span> · 供应链安全与合规审计报告</div>
      <div class="meta-line">
        目标项目：<strong>{esc(report.target_name)}</strong> &nbsp;|&nbsp;
        主许可证：<code>{esc(report.project_license)}</code> &nbsp;|&nbsp;
        扫描 ID：<code>{esc(report.scan_id)}</code> &nbsp;|&nbsp;
        时间：{esc(report.scanned_at)} &nbsp;|&nbsp;
        耗时：{s.scan_duration_ms:.1f} ms
      </div>
    </div>
    <button class="btn" onclick="document.body.classList.toggle('light')">切换明暗主题</button>
  </div>

  <div class="grid-top">
    <div class="card">
      <h2>综合健康度评分</h2>
      <div class="flex-center">
        {gauge_svg}
        <div class="kpi-grid">
          <div class="kpi"><div class="num" style="color:#ef4444">{s.severity_counts.get('CRITICAL', 0)}</div><div class="lbl">严重 (CRITICAL)</div></div>
          <div class="kpi"><div class="num" style="color:#f97316">{s.severity_counts.get('HIGH', 0)}</div><div class="lbl">高危 (HIGH)</div></div>
          <div class="kpi"><div class="num">{len(report.components)}</div><div class="lbl">SBOM 依赖数</div></div>
          <div class="kpi"><div class="num" style="color:#10b981">{report.suppressed_count}</div><div class="lbl">AST+熵值过滤误报</div></div>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>五维合规雷达图</h2>
      <div class="flex-center">{radar_svg}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <h2>维度得分明细与优先整改路线图</h2>
    <table style="margin-bottom:14px;">
      <thead><tr><th>评估维度</th><th>得分</th><th>权重</th><th>加权分</th><th>问题数</th><th>诊断摘要</th></tr></thead>
      <tbody>{dim_rows}</tbody>
    </table>
    {roadmap_html}
  </div>

  <div class="card" style="margin-bottom:20px;">
    <h2>风险发现详情与精确溯源 ({len(finding_cards)})</h2>
    <div class="toolbar">
      <button class="tab active" onclick="filterFindings('all', this)">全部 ({len(finding_cards)})</button>
      <button class="tab" onclick="filterFindings('secret', this)">工作区密钥 ({len(report.secrets)})</button>
      <button class="tab" onclick="filterFindings('history', this)">Git 历史密钥 ({len(report.git_history_secrets)})</button>
      <button class="tab" onclick="filterFindings('license', this)">许可证冲突 ({len(report.license_conflicts)})</button>
      <button class="tab" onclick="filterFindings('vuln', this)">漏洞与投毒 ({len(report.vulnerabilities)})</button>
      <button class="tab" onclick="filterFindings('sast', this)">SAST 代码安全 ({len(report.code_security_findings)})</button>
      <input class="search-input" type="search" placeholder="搜索文件名 / CVE / 规则..." oninput="searchFindings(this.value)">
    </div>
    <div id="findings-list">{findings_html}</div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <h2>软件物料清单 SBOM ({len(report.components)} 组件)</h2>
    <table>
      <thead><tr><th>组件名称</th><th>版本</th><th>生态</th><th>SPDX 许可证</th><th>依赖层级</th><th>来源清单</th></tr></thead>
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
  const OG_META = {report_json_safe};
  let activeKind = 'all';
  let queryText = '';
  function applyFilters() {{
    document.querySelectorAll('.finding-card').forEach(el => {{
      const k = el.getAttribute('data-kind');
      const txt = el.textContent.toLowerCase();
      const okKind = activeKind === 'all' || k === activeKind;
      const okSearch = !queryText || txt.includes(queryText);
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
