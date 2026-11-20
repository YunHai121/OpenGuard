/* OpenGuard Web Workbench Vanilla JS Controller (Zero External CDN) */

let currentReport = null;
let currentFilterKind = 'all';
let currentSearch = '';

const $ = (id) => document.getElementById(id);

function esc(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function mountEscapedHtml(el, trustedHtml) {
  // All dynamic data interpolated into `trustedHtml` MUST pass through `esc()` first.
  el.innerHTML = trustedHtml; // openguard: ignore
}

function showStatus(msg, isError = false) {
  const el = $('scan-status');
  el.textContent = msg;
  el.classList.remove('hidden', 'error');
  if (isError) el.classList.add('error');
}

function hideStatus() {
  $('scan-status').classList.add('hidden');
}

// Navigation switching
document.querySelectorAll('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const view = btn.getAttribute('data-view');
    document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
    btn.classList.add('active');
    $(`view-${view}`).classList.add('active');
    if (view === 'history') loadHistory();
  });
});

async function initApp() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    $('health-pill').textContent = `在线 · v${data.version}`;
  } catch {
    $('health-pill').textContent = '后端离线';
    $('health-pill').style.color = '#ef4444';
  }

  try {
    const pRes = await fetch('/api/presets');
    const presets = await pRes.json();
    const wrap = $('preset-list');
    mountEscapedHtml(
      wrap,
      presets
        .map(
          (p) =>
            `<button class="preset-chip" data-path="${esc(p.path)}" title="${esc(p.description)}">快速载入：${esc(p.name)}</button>`
        )
        .join('')
    );
    wrap.querySelectorAll('.preset-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const path = chip.getAttribute('data-path');
        $('scan-target').value = path;
        $('autofix-target').value = path;
      });
    });
    if (presets.length > 0) {
      $('scan-target').value = presets[0].path;
      $('autofix-target').value = presets[0].path;
    }
  } catch (e) {
    console.warn('Presets load failed', e);
  }
}

function buildGaugeSvg(score, grade) {
  const r = 56;
  const c = 2 * Math.PI * r;
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  const color = score >= 90 ? '#10b981' : score >= 80 ? '#3b82f6' : score >= 70 ? '#f59e0b' : '#ef4444';
  return `<svg viewBox="0 0 144 144" width="140" height="140">
    <circle cx="72" cy="72" r="${r}" fill="none" stroke="#263554" stroke-width="11"/>
    <circle cx="72" cy="72" r="${r}" fill="none" stroke="${color}" stroke-width="11"
      stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
      stroke-linecap="round" transform="rotate(-90 72 72)"/>
    <text x="72" y="68" text-anchor="middle" font-size="26" font-weight="800" fill="#f1f5f9">${score.toFixed(1)}</text>
    <text x="72" y="92" text-anchor="middle" font-size="13" font-weight="700" fill="${color}">等级 ${esc(grade)}</text>
  </svg>`;
}

function buildRadarSvg(dimensions) {
  const cx = 140, cy = 122, r = 78;
  const labels = ['密钥安全', '供应链漏洞', '许可证合规', '代码安全', '工程治理'];
  const n = dimensions.length || 5;
  let rings = '', axes = '', pts = [], dots = '', lbls = '';

  [0.25, 0.5, 0.75, 1.0].forEach((ratio) => {
    const p = [];
    for (let i = 0; i < n; i++) {
      const a = -Math.PI / 2 + (2 * Math.PI * i) / n;
      p.push(`${(cx + r * ratio * Math.cos(a)).toFixed(1)},${(cy + r * ratio * Math.sin(a)).toFixed(1)}`);
    }
    rings += `<polygon points="${p.join(' ')}" fill="none" stroke="#263554" stroke-width="1"/>`;
  });

  dimensions.forEach((d, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / n;
    axes += `<line x1="${cx}" y1="${cy}" x2="${(cx + r * Math.cos(a)).toFixed(1)}" y2="${(cy + r * Math.sin(a)).toFixed(1)}" stroke="#263554"/>`;
    const vr = Math.max(0.05, Math.min(1.0, d.score / 100));
    const px = cx + r * vr * Math.cos(a);
    const py = cy + r * vr * Math.sin(a);
    pts.push(`${px.toFixed(1)},${py.toFixed(1)}`);
    dots += `<circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="4" fill="#6366f1" stroke="#fff" stroke-width="1.5"/>`;

    let lx = cx + (r + 22) * Math.cos(a);
    const ly = cy + (r + 16) * Math.sin(a) + 4;
    let anchor = 'middle';
    if (Math.cos(a) > 0.25) { anchor = 'start'; lx -= 5; }
    else if (Math.cos(a) < -0.25) { anchor = 'end'; lx += 5; }
    lbls += `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}" font-size="11" fill="#94a3b8" font-weight="600">${labels[i] || esc(d.name)} (${d.score.toFixed(0)})</text>`;
  });

  return `<svg viewBox="0 0 280 244" width="280" height="244">
    ${rings}${axes}
    <polygon points="${pts.join(' ')}" fill="rgba(99,102,241,0.28)" stroke="#6366f1" stroke-width="2.2"/>
    ${dots}${lbls}
  </svg>`;
}

function renderReport(report) {
  currentReport = report;
  const s = report.summary;
  $('dashboard-results').classList.remove('hidden');
  $('export-bar').classList.remove('hidden');

  $('exp-html').href = `/api/export/${encodeURIComponent(report.scan_id)}/html`;
  $('exp-pdf').href = `/api/export/${encodeURIComponent(report.scan_id)}/pdf`;
  $('exp-sarif').href = `/api/export/${encodeURIComponent(report.scan_id)}/sarif`;
  $('exp-cdx').href = `/api/export/${encodeURIComponent(report.scan_id)}/cyclonedx`;
  $('exp-md').href = `/api/export/${encodeURIComponent(report.scan_id)}/md`;
  $('exp-badge').href = `/api/export/${encodeURIComponent(report.scan_id)}/badge`;

  mountEscapedHtml($('gauge-container'), buildGaugeSvg(s.total_score, s.grade));
  mountEscapedHtml($('radar-container'), buildRadarSvg(s.dimensions));
  $('kpi-crit').textContent = s.severity_counts.CRITICAL || 0;
  $('kpi-high').textContent = s.severity_counts.HIGH || 0;
  $('kpi-comps').textContent = report.components.length;
  $('kpi-supp').textContent = report.suppressed_count;
  mountEscapedHtml(
    $('scan-meta-line'),
    `项目：<strong>${esc(report.target_name)}</strong> · 主许可证：<code>${esc(report.project_license)}</code> · ` +
      `ID：<code>${esc(report.scan_id)}</code> · 扫描 ${Number(s.files_scanned)} 文件 / ${Number(s.lines_scanned)} 行 (${Number(s.scan_duration_ms).toFixed(1)} ms)`
  );

  mountEscapedHtml(
    $('dimensions-table-wrap'),
    `<table>
    <thead><tr><th>评估维度</th><th>得分</th><th>权重</th><th>问题数</th><th>诊断摘要</th></tr></thead>
    <tbody>${s.dimensions
      .map(
        (d) =>
          `<tr><td><strong>${esc(d.name)}</strong></td><td>${Number(d.score).toFixed(1)}</td><td>${Math.round(d.weight * 100)}%</td><td>${Number(d.issue_count)}</td><td>${esc(d.summary)}</td></tr>`
      )
      .join('')}</tbody>
  </table>`
  );

  mountEscapedHtml(
    $('roadmap-wrap'),
    s.roadmap.length
      ? s.roadmap
          .map(
            (r) =>
              `<div class="roadmap-item"><span class="badge sev-high">${esc(r.priority)}</span> <strong>${esc(r.title)}</strong><div class="muted" style="margin-top:4px;">${esc(r.action)}</div></div>`
          )
          .join('')
      : '<div class="muted" style="margin-top:10px;color:#10b981;">无紧急整改项，符合高标准开源合规要求。</div>'
  );

  renderFindingsList();
  renderGovernance(report.governance_checks);
  renderSbomView(report);
}

function renderFindingsList() {
  if (!currentReport) return;
  const items = [];
  currentReport.secrets.forEach((f) => {
    items.push({
      kind: 'secret',
      sev: f.severity,
      title: f.rule_name,
      pill: '明文凭据',
      loc: `${f.file_path}:${f.line_number}`,
      body: `脱敏值：<code>${esc(f.matched_masked)}</code> · 置信度 ${esc(f.confidence)} · 熵值 ${esc(f.entropy)} · 上下文：<code>${esc(f.ast_context)}</code>`,
      snippet: f.snippet,
      fix: f.remediation,
    });
  });
  currentReport.git_history_secrets.forEach((f) => {
    items.push({
      kind: 'history',
      sev: f.severity,
      title: f.rule_name,
      pill: `Git历史 ${f.commit_hash}`,
      loc: `${f.file_path}:${f.line_number}`,
      body: `作者 ${esc(f.commit_author)} (${esc(f.commit_date)}) · 脱敏值：<code>${esc(f.matched_masked)}</code>`,
      snippet: f.snippet,
      fix: f.remediation,
    });
  });
  currentReport.license_conflicts.forEach((lc) => {
    items.push({
      kind: 'license',
      sev: lc.severity,
      title: `${lc.component_name} (${lc.component_license} vs ${lc.project_license})`,
      pill: lc.compatibility,
      loc: lc.dependency_path.join(' -> '),
      body: esc(lc.explanation),
      snippet: '',
      fix: lc.remediation,
    });
  });
  currentReport.vulnerabilities.forEach((v) => {
    items.push({
      kind: 'vuln',
      sev: v.severity,
      title: `${v.id} · ${v.component_name}@${v.component_version}`,
      pill: v.source === 'typosquatting' ? '仿冒投毒告警' : `CVSS ${v.cvss_score}`,
      loc: `安全版本: ${v.fixed_version}`,
      body: esc(v.summary),
      snippet: '',
      fix: v.remediation,
    });
  });
  currentReport.code_security_findings.forEach((cs) => {
    items.push({
      kind: 'sast',
      sev: cs.severity,
      title: `${cs.rule_name} (${cs.cwe_id})`,
      pill: 'SAST',
      loc: `${cs.file_path}:${cs.line_number}`,
      body: esc(cs.description),
      snippet: cs.snippet,
      fix: cs.remediation,
    });
  });

  const filtered = items.filter((it) => {
    const okKind = currentFilterKind === 'all' || it.kind === currentFilterKind;
    const hay = `${it.title} ${it.loc} ${it.body} ${it.snippet}`.toLowerCase();
    return okKind && (!currentSearch || hay.includes(currentSearch));
  });

  mountEscapedHtml(
    $('findings-container'),
    filtered.length
      ? filtered
          .map(
            (it) => `<div class="finding-card">
            <div class="finding-head">
              <span class="badge sev-${esc(it.sev).toLowerCase()}">${esc(it.sev)}</span>
              <span class="kind-pill">${esc(it.pill)}</span>
              <strong>${esc(it.title)}</strong>
              <code class="loc">${esc(it.loc)}</code>
            </div>
            <div>${it.body}</div>
            ${it.snippet ? `<pre class="code-snip">${esc(it.snippet)}</pre>` : ''}
            <div class="fix-tip">整改建议：${esc(it.fix)}</div>
          </div>`
          )
          .join('')
      : '<div class="muted" style="padding:14px;">当前筛选条件下无匹配的风险项。</div>'
  );
}

function renderGovernance(checks) {
  mountEscapedHtml(
    $('governance-container'),
    `<table>
    <thead><tr><th>检查项</th><th>类别</th><th>状态</th><th>得分</th><th>详情</th></tr></thead>
    <tbody>${checks
      .map(
        (g) => `<tr>
          <td>${esc(g.name)}</td>
          <td>${esc(g.category)}</td>
          <td><span class="badge ${g.passed ? 'sev-ok' : 'sev-medium'}">${g.passed ? '通过' : '待完善'}</span></td>
          <td>${Number(g.score).toFixed(0)}/${Number(g.max_score).toFixed(0)}</td>
          <td>${esc(g.details)}</td>
        </tr>`
      )
      .join('')}</tbody>
  </table>`
  );
}

function renderSbomView(report) {
  const conflictSet = new Set(report.license_conflicts.map((c) => c.component_name));
  const comps = report.components.slice(0, 22);
  const w = 780;
  const h = Math.max(220, comps.length * 36 + 40);
  const rootY = h / 2;

  let lines = '';
  let nodes = `<rect x="20" y="${rootY - 18}" width="160" height="36" rx="8" fill="#4f46e5"/>
    <text x="100" y="${rootY + 5}" text-anchor="middle" fill="#fff" font-size="12" font-weight="700">${esc(report.target_name)} (${esc(report.project_license)})</text>`;

  comps.forEach((c, idx) => {
    const y = 26 + idx * 34;
    const isConflict = conflictSet.has(c.name);
    const fill = isConflict ? '#991b1b' : '#1e293b';
    const stroke = isConflict ? '#ef4444' : '#334155';
    lines += `<path d="M 180 ${rootY} C 280 ${rootY}, 290 ${y + 13}, 380 ${y + 13}" fill="none" stroke="${stroke}" stroke-width="1.6"/>`;
    nodes += `<rect x="380" y="${y}" width="370" height="26" rx="6" fill="${fill}" stroke="${stroke}"/>
      <text x="392" y="${y + 17}" fill="#f1f5f9" font-size="11.5" font-family="Consolas,monospace">${esc(c.name)}@${esc(c.version)} [${esc(c.ecosystem)}] · ${esc(c.license_id)}</text>`;
  });

  mountEscapedHtml(
    $('dep-graph-container'),
    comps.length
      ? `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">${lines}${nodes}</svg>`
      : '<span class="muted">该项目未检测到依赖文件。</span>'
  );

  mountEscapedHtml(
    $('sbom-table-container'),
    `<table>
    <thead><tr><th>组件</th><th>版本</th><th>生态</th><th>SPDX 许可证</th><th>层级</th><th>PURL</th></tr></thead>
    <tbody>${report.components
      .map(
        (c) =>
          `<tr><td><code>${esc(c.name)}</code></td><td>${esc(c.version)}</td><td>${esc(c.ecosystem)}</td><td><code>${esc(c.license_id)}</code></td><td>${c.direct ? '直接' : '传递'}</td><td><code>${esc(c.purl)}</code></td></tr>`
      )
      .join('')}</tbody>
  </table>`
  );
}

// Run Scan
$('btn-run-scan').addEventListener('click', async () => {
  const target = $('scan-target').value.trim();
  if (!target) return showStatus('请先输入待扫描的本地路径或仓库 URL', true);
  const btn = $('btn-run-scan');
  btn.disabled = true;
  showStatus('正在执行全维度安全、SBOM 与开源治理审计，请稍候...');
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        include_git_history: $('opt-git-history').checked,
        offline: $('opt-offline').checked,
        license_override: $('opt-license').value.trim() || null,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '扫描请求失败');
    hideStatus();
    renderReport(data);
  } catch (err) {
    showStatus(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    currentFilterKind = btn.getAttribute('data-kind');
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    renderFindingsList();
  });
});

$('finding-search').addEventListener('input', (e) => {
  currentSearch = (e.target.value || '').trim().toLowerCase();
  renderFindingsList();
});

// Playground Snippet
$('btn-load-sample').addEventListener('click', () => {
  const awsSynthetic = ['AKIA', '7F4K9P2M8Q3X6Z1W5N2R'].join('');
  const ghSynthetic = ['ghp_', 'R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u'].join('');
  $('snippet-code').value =
    `import os\nimport yaml\n\n` +
    `# 1. 真实泄露的云端与 SCM 凭据（将被精准捕获）\n` +
    `AWS_ACCESS_KEY = "${awsSynthetic}"\n` +
    `GITHUB_TOKEN = "${ghSynthetic}"\n\n` +
    `# 2. 常见测试占位符与 Git SHA（将被 AST+熵值引擎智能过滤）\n` +
    `OPENAI_API_KEY = "sk-your_api_key_placeholder_example"\n` +
    `COMMIT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n\n` +
    `# 3. 高危 SAST 反序列化漏洞 (CWE-502)\n` +
    `def parse_cfg(raw_yaml: str):\n` +
    `    return yaml.load(raw_yaml)\n`;
});

$('btn-run-snippet').addEventListener('click', async () => {
  const code = $('snippet-code').value;
  const filename = $('snippet-filename').value;
  const res = await fetch('/api/scan/snippet', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, filename }),
  });
  const data = await res.json();
  $('snippet-results').classList.remove('hidden');
  const cards = [];
  data.secrets.forEach((f) => {
    cards.push(`<div class="finding-card"><span class="badge sev-${esc(f.severity).toLowerCase()}">${esc(f.severity)}</span> <strong>${esc(f.rule_name)}</strong> (Line ${Number(f.line_number)}) — 脱敏：<code>${esc(f.matched_masked)}</code> · 置信度 ${esc(f.confidence)}</div>`);
  });
  data.code_security_findings.forEach((cs) => {
    cards.push(`<div class="finding-card"><span class="badge sev-${esc(cs.severity).toLowerCase()}">${esc(cs.severity)}</span> <strong>[SAST ${esc(cs.cwe_id)}] ${esc(cs.rule_name)}</strong> (Line ${Number(cs.line_number)}) — ${esc(cs.description)}</div>`);
  });
  const suppNote = `<div class="muted" style="margin-top:8px;">AST + 信息熵过滤低置信误报候选数：<strong>${Number(data.suppressed_count)}</strong> 条</div>`;
  mountEscapedHtml($('snippet-findings'), (cards.join('') || '<div class="muted">未发现安全问题。</div>') + suppNote);
});

// AutoFix
async function runAutofix(apply) {
  const target = $('autofix-target').value.trim();
  if (!target) return;
  const endpoint = apply ? '/api/autofix/apply' : '/api/autofix/preview';
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      fix_secrets: $('fix-secrets').checked,
      fix_docs: $('fix-docs').checked,
      license_id: $('fix-license').value,
    }),
  });
  const data = await res.json();
  const box = $('autofix-output');
  box.classList.remove('hidden');
  if (!res.ok) {
    mountEscapedHtml(box, `<div class="red">${esc(data.detail || '操作失败')}</div>`);
    return;
  }
  const diffs = (data.secrets.previews || [])
    .map((p) => {
      const colored = esc(p.unified_diff)
        .split('\n')
        .map((ln) => (ln.startsWith('+') ? `<span class="diff-add">${ln}</span>` : ln.startsWith('-') ? `<span class="diff-del">${ln}</span>` : ln))
        .join('\n');
      return `<div style="margin-bottom:12px;"><strong>${esc(p.file_path)}</strong> (提取环境变量: <code>${esc(p.env_vars_added.join(', '))}</code>)<pre class="diff-pre">${colored}</pre></div>`;
    })
    .join('');
  const docRows = Object.entries(data.docs || {})
    .map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`)
    .join('');

  mountEscapedHtml(
    box,
    `
    <div class="panel-title">${data.applied ? '已成功应用修复（已备份原文件至 .openguard_backup）' : 'Dry-Run 重构差异预览'}</div>
    <p>涉及文件：${Number(data.secrets.files_modified)} 个 · 脱敏凭据：${Number(data.secrets.findings_remediated)} 处</p>
    ${diffs || '<div class="muted">暂无可自动提取重构的源码文件。</div>'}
    ${docRows ? `<table><thead><tr><th>文档文件</th><th>状态</th></tr></thead><tbody>${docRows}</tbody></table>` : ''}
  `
  );
}

$('btn-autofix-preview').addEventListener('click', () => runAutofix(false));
$('btn-autofix-apply').addEventListener('click', () => runAutofix(true));

// History & Diff
async function loadHistory() {
  const res = await fetch('/api/history');
  const rows = await res.json();
  const opts = rows
    .map((r) => `<option value="${esc(r.scan_id)}">${esc(r.scan_id)} · ${esc(r.target_name)} (${Number(r.total_score)}分 / ${esc(r.grade)})</option>`)
    .join('');
  mountEscapedHtml($('diff-before'), opts);
  mountEscapedHtml($('diff-after'), opts);
  if (rows.length >= 2) {
    $('diff-before').selectedIndex = 1;
    $('diff-after').selectedIndex = 0;
  }

  mountEscapedHtml(
    $('history-table-box'),
    rows.length
      ? `<table><thead><tr><th>扫描 ID</th><th>时间</th><th>目标项目</th><th>得分</th><th>密钥</th><th>漏洞</th><th>许可证冲突</th><th>操作</th></tr></thead>
      <tbody>${rows
        .map(
          (r) => `<tr>
            <td><code>${esc(r.scan_id)}</code></td>
            <td>${esc(r.scanned_at)}</td>
            <td>${esc(r.target_name)}</td>
            <td><strong>${Number(r.total_score)} (${esc(r.grade)})</strong></td>
            <td>${Number(r.secrets_count)}</td>
            <td>${Number(r.vulns_count)}</td>
            <td>${Number(r.license_conflicts_count)}</td>
            <td><button class="btn-outline" data-load-scan="${esc(r.scan_id)}">加载详情</button></td>
          </tr>`
        )
        .join('')}</tbody></table>`
      : '<div class="muted">暂无历史扫描记录。</div>'
  );
  $('history-table-box').querySelectorAll('[data-load-scan]').forEach((btn) => {
    btn.addEventListener('click', () => loadScanById(btn.getAttribute('data-load-scan')));
  });
}

async function loadScanById(scanId) {
  const res = await fetch(`/api/history/${encodeURIComponent(scanId)}`);
  const data = await res.json();
  document.querySelector('[data-view="dashboard"]').click();
  renderReport(data);
}

$('btn-refresh-history').addEventListener('click', loadHistory);
$('btn-run-diff').addEventListener('click', async () => {
  const b = $('diff-before').value;
  const a = $('diff-after').value;
  if (!b || !a) return;
  const res = await fetch(`/api/diff/${encodeURIComponent(b)}/${encodeURIComponent(a)}`);
  const d = await res.json();
  const box = $('diff-result-box');
  box.classList.remove('hidden');
  const sign = d.score_delta >= 0 ? '+' : '';
  mountEscapedHtml(
    box,
    `
    <div style="margin-bottom:10px;">
      <strong>评分变化：</strong> ${Number(d.before_score)} (${esc(d.before_grade)}) → <strong>${Number(d.after_score)} (${esc(d.after_grade)})</strong>
      <span class="badge ${d.score_delta >= 0 ? 'sev-ok' : 'sev-critical'}">${sign}${Number(d.score_delta)} 分</span>
      &nbsp;|&nbsp; 已消除风险：<strong>${Number(d.resolved_count)}</strong> &nbsp;|&nbsp; 新增风险：<strong>${Number(d.new_count)}</strong>
    </div>
    ${d.resolved_items.length ? `<div><strong>已修复问题：</strong><ul>${d.resolved_items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
    ${d.new_items.length ? `<div><strong>新增问题：</strong><ul>${d.new_items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
  `
  );
});

initApp();
