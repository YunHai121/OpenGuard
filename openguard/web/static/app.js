/* OpenGuard v1.1 — Editorial Engineering Frontend Controller (Zero External CDN) */

let currentReport = null;
let unifiedIssues = [];
let selectedIssueId = null;
let currentFilterKind = 'all';
let currentSevFilter = 'ALL';
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
  // Centralized DOM sink: all interpolated variables MUST pass through esc().
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

function switchView(viewName) {
  document.querySelectorAll('.top-tab').forEach((t) => t.classList.toggle('active', t.getAttribute('data-view') === viewName));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${viewName}`));
  if (viewName === 'history') loadHistory();
}

document.querySelectorAll('.top-tab').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.getAttribute('data-view')));
});

// Theme Toggle
$('btn-theme-toggle').addEventListener('click', () => {
  const dark = document.body.classList.toggle('theme-dark');
  $('ico-moon').classList.toggle('hidden', dark);
  $('ico-sun').classList.toggle('hidden', !dark);
});

// Export Dropdown
$('btn-export-toggle').addEventListener('click', (e) => {
  e.stopPropagation();
  $('export-menu').classList.toggle('hidden');
});
document.addEventListener('click', () => $('export-menu').classList.add('hidden'));

async function initApp() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    $('health-pill').textContent = `在线 · v${data.version}`;
  } catch {
    $('health-pill').textContent = '离线';
  }

  try {
    const pRes = await fetch('/api/presets');
    const presets = await pRes.json();
    mountEscapedHtml(
      $('preset-list'),
      presets
        .map(
          (p) =>
            `<button class="preset-chip" data-path="${esc(p.path)}" title="${esc(p.description)}">${esc(p.name)}</button>`
        )
        .join('')
    );
    $('preset-list').querySelectorAll('.preset-chip').forEach((chip) => {
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
  } catch (err) {
    console.warn('Presets failed', err);
  }
}

function buildUnifiedIssues(report) {
  const list = [];
  report.secrets.forEach((f) => {
    list.push({
      id: f.id,
      kind: 'secret',
      sev: String(f.severity),
      title: f.rule_name,
      subtitle: `${f.file_path}:${f.line_number}`,
      pill: '明文凭据',
      file_path: f.file_path,
      line_number: f.line_number,
      cwe: f.cwe_id,
      summary: `检测到脱敏凭据 \`${f.matched_masked}\`（置信度 ${f.confidence}，Shannon 熵 ${f.entropy}，AST 上下文：${f.ast_context}）。`,
      snippet: f.snippet,
      runbook: f.runbook_steps && f.runbook_steps.length ? f.runbook_steps : [f.remediation],
      triageable: true,
      raw: f,
    });
  });

  report.git_history_secrets.forEach((f) => {
    list.push({
      id: f.id,
      kind: 'history',
      sev: String(f.severity),
      title: `${f.rule_name} (历史残留)`,
      subtitle: `${f.file_path}:${f.line_number} @ ${f.commit_hash}`,
      pill: 'GHOST COMMIT',
      file_path: null,
      line_number: f.line_number,
      cwe: f.cwe_id,
      summary: `作者 ${f.commit_author} 于 ${f.commit_date} 提交（${f.commit_hash}）中曾包含凭据 \`${f.matched_masked}\`，现工作区虽已删除但仍可从 Git 历史直接恢复。`,
      snippet: f.snippet,
      runbook: f.runbook_steps && f.runbook_steps.length ? f.runbook_steps : [f.remediation],
      triageable: false,
      raw: f,
    });
  });

  report.vulnerabilities.forEach((v) => {
    const isAttack = v.source === 'typosquatting' || v.source === 'install_script';
    const isUnreachable = !isAttack && (v.reachability_level === 'unreachable' || v.reachable === false);
    const kind = isAttack ? 'supply_attack' : isUnreachable ? 'vuln_unreachable' : 'vuln_reachable';
    const rLevel = v.reachability_level || (v.reachable === true ? 'import_only' : v.reachable === false ? 'unreachable' : 'unknown');
    const kevTag = v.in_cisa_kev ? ' · CISA KEV' : '';
    const epssTag = typeof v.epss_score === 'number' ? ` · EPSS ${(v.epss_score * 100).toFixed(0)}%` : '';
    const prioPrefix = v.priority_tier ? `[${v.priority_tier}] ` : '';
    const pill =
      v.source === 'install_script'
        ? '[P0] INSTALL SCRIPT'
        : v.source === 'typosquatting'
        ? '[P0] TYPOSQUAT'
        : rLevel === 'call_reachable'
        ? `${prioPrefix}CALL REACHABLE${kevTag}${epssTag}`
        : rLevel === 'import_only'
        ? `${prioPrefix}IMPORT ONLY${kevTag}${epssTag}`
        : rLevel === 'unreachable'
        ? `${prioPrefix}UNREACHABLE · VEX: not_affected`
        : `${prioPrefix}CVSS ${v.cvss_score}${kevTag}`;
    const callLocs = (v.call_locations || []).join(', ');
    const locs = callLocs || (v.import_locations || []).join(', ');
    const firstLoc = (v.call_locations && v.call_locations[0]) || (v.import_locations && v.import_locations[0]) || null;
    list.push({
      id: `${v.id}-${v.component_name}`,
      kind,
      sev: String(v.severity),
      title: `${v.id} · ${v.component_name}@${v.component_version}`,
      subtitle: `${v.ecosystem}${v.source_file ? ' · ' + v.source_file : ''}${locs ? ' · 命中: ' + locs : ''}`,
      pill,
      file_path: firstLoc ? firstLoc.split(':')[0] : v.source_file || null,
      line_number: firstLoc && firstLoc.includes(':') ? Number(firstLoc.split(':')[1]) || 1 : 1,
      cwe: v.id,
      summary:
        v.summary +
        (rLevel === 'call_reachable'
          ? ` 【函数级可达 · VEX: exploitable】已在 ${locs} 直接调用高危符号，需优先升级！`
          : rLevel === 'import_only'
          ? ` 【已导入未调用高危符号 · VEX: in_triage】已在 ${locs} 导入，但未检出已知漏洞函数直接调用。`
          : rLevel === 'unreachable'
          ? ' 【未直接引用 · VEX: not_affected (code_not_reachable)】仅在依赖清单声明，当前源码未检测到导入调用。'
          : ''),
      snippet: '',
      runbook: [
        `1. 确认组件 \`${v.component_name}@${v.component_version}\` 的升级兼容范围，目标修复版本：\`${v.fixed_version}\`。`,
        `2. ${v.remediation}`,
        '3. 升级后重新执行单元测试与 `openguard scan` 验证质量门禁状态。',
      ],
      triageable: false,
      raw: v,
    });
  });

  report.license_conflicts.forEach((lc) => {
    list.push({
      id: lc.id,
      kind: 'license',
      sev: String(lc.severity),
      title: `${lc.component_name} (${lc.component_license} vs ${lc.project_license})`,
      subtitle: lc.dependency_path.join(' -> '),
      pill: lc.compatibility,
      file_path: null,
      line_number: 1,
      cwe: lc.component_license,
      summary: lc.explanation,
      snippet: '',
      runbook: [
        `1. 核查依赖路径：\`${lc.dependency_path.join(' -> ')}\`。`,
        `2. ${lc.remediation}`,
        '3. 更新许可证或替换依赖后执行 `openguard sbom .` 重新生成合规物料清单。',
      ],
      triageable: false,
      raw: lc,
    });
  });

  report.code_security_findings.forEach((cs) => {
    const rid = String(cs.rule_id || '');
    const isSupplyCfg = rid.startsWith('OG-CI-') || rid.startsWith('OG-DOCKER-') || rid.startsWith('OG-AI-') || rid.startsWith('OG-IAC-');
    const pill = rid.startsWith('OG-CI-')
      ? 'CI/CD 供应链'
      : rid.startsWith('OG-DOCKER-')
      ? 'DOCKERFILE'
      : rid.startsWith('OG-IAC-')
      ? 'IAC 云原生'
      : rid.startsWith('OG-AI-')
      ? 'AI 安全/UNICODE'
      : 'SAST';
    list.push({
      id: cs.id,
      kind: isSupplyCfg ? 'ci_docker_ai' : 'sast',
      sev: String(cs.severity),
      title: `${cs.rule_name} (${cs.cwe_id})`,
      subtitle: `${cs.file_path}:${cs.line_number}`,
      pill,
      file_path: cs.file_path,
      line_number: cs.line_number,
      cwe: cs.cwe_id,
      summary: cs.description,
      snippet: cs.snippet,
      runbook: [
        `1. 定位 \`${cs.file_path}:${cs.line_number}\` 的高危模式（${cs.rule_id} / ${cs.cwe_id}）。`,
        `2. ${cs.remediation}`,
        '3. 若确认当前配置受控，可在行尾标记 `# openguard: ignore` 或 `// openguard: ignore`。',
      ],
      triageable: true,
      raw: cs,
    });
  });

  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  list.sort((a, b) => (sevRank[b.sev] || 0) - (sevRank[a.sev] || 0));
  return list;
}

function renderReport(report) {
  currentReport = report;
  unifiedIssues = buildUnifiedIssues(report);
  selectedIssueId = unifiedIssues.length ? unifiedIssues[0].id : null;

  $('overview-empty').classList.add('hidden');
  $('overview-content').classList.remove('hidden');
  $('export-dropdown').classList.remove('hidden');

  $('nav-issues-count').textContent = unifiedIssues.length;
  $('nav-issues-count').classList.remove('hidden');

  const sid = encodeURIComponent(report.scan_id);
  $('exp-html').href = `/api/export/${sid}/html`;
  $('exp-pdf').href = `/api/export/${sid}/pdf`;
  $('exp-sarif').href = `/api/export/${sid}/sarif`;
  $('exp-cdx').href = `/api/export/${sid}/cyclonedx`;
  $('exp-spdx').href = `/api/export/${sid}/spdx`;
  $('exp-md').href = `/api/export/${sid}/md`;
  if ($('exp-pr')) $('exp-pr').href = `/api/export/${sid}/pr-comment`;
  $('exp-badge').href = `/api/export/${sid}/badge`;

  renderOverview(report);
  renderIssueList();
  renderGovernance(report.governance_checks);
  renderSbomTab(report);
}

function renderOverview(report) {
  const s = report.summary;
  const qg = s.quality_gate || { status: s.total_score >= 80 ? 'PASSED' : 'FAILED', conditions: [] };
  const isPass = qg.status === 'PASSED';

  const condHtml = (qg.conditions || [])
    .map(
      (c) =>
        `<div class="qg-cond ${c.passed ? 'pass' : 'fail'}">
          <span>${esc(c.label)}</span>
          <strong class="mono">${Number(c.actual)} <span class="muted">(${esc(c.threshold)})</span></strong>
        </div>`
    )
    .join('');

  mountEscapedHtml(
    $('quality-gate-card'),
    `
    <div class="qg-top">
      <div class="qg-status-wrap">
        <span class="qg-pill ${isPass ? 'qg-passed' : 'qg-failed'}">
          ${isPass ? 'QUALITY GATE PASSED' : 'QUALITY GATE FAILED'}
        </span>
        <div>
          <strong>${esc(report.target_name)}</strong>
          <span class="muted"> · 主许可证 <code>${esc(report.project_license)}</code> · 扫描 ${Number(s.files_scanned)} 文件 / ${Number(s.lines_scanned)} 行</span>
        </div>
      </div>
      <div class="qg-score-box">
        <span class="qg-score-num">${Number(s.total_score).toFixed(1)}</span>
        <span class="muted">/ 100</span>
        <span class="qg-grade">等级 ${esc(s.grade)}</span>
      </div>
    </div>
    <div class="qg-conditions">${condHtml}</div>
  `
  );

  $('scan-meta-mini').textContent = `${report.scan_id} · ${Number(s.scan_duration_ms).toFixed(0)} ms`;

  // Socket.dev-style segmented dimension bars
  mountEscapedHtml(
    $('dimensions-bars'),
    s.dimensions
      .map((d) => {
        const cls = d.score >= 85 ? 'fill-ok' : d.score >= 60 ? 'fill-med' : 'fill-crit';
        return `<div>
          <div class="dim-row-head">
            <span><strong>${esc(d.name)}</strong> <span class="muted">(${Math.round(d.weight * 100)}%)</span></span>
            <span class="mono"><strong>${Number(d.score).toFixed(1)}</strong> · ${Number(d.issue_count)} 项</span>
          </div>
          <div class="dim-track"><div class="dim-fill ${cls}" style="width:${Math.max(2, Number(d.score))}%"></div></div>
          <div class="muted-xs" style="margin-top:3px;">${esc(d.summary)}</div>
        </div>`;
      })
      .join('')
  );

  // Reachability + License stacked bar
  const reachCount = report.vulnerabilities.filter((v) => v.reachable === true).length;
  const unreachCount = report.vulnerabilities.filter((v) => v.reachable === false).length;
  const unknownReach = report.vulnerabilities.length - reachCount - unreachCount;

  const totalComps = report.components.length || 1;
  const conflictMap = new Map(report.license_conflicts.map((c) => [c.component_name, String(c.compatibility)]));
  let strongCnt = 0, weakCnt = 0, unkCnt = 0, permCnt = 0;
  report.components.forEach((c) => {
    const compat = conflictMap.get(c.name);
    if (compat === 'INCOMPATIBLE') strongCnt++;
    else if (compat === 'REVIEW_REQUIRED') weakCnt++;
    else if (c.license_id === 'UNKNOWN') unkCnt++;
    else permCnt++;
  });

  const pct = (n) => ((n / totalComps) * 100).toFixed(1);

  mountEscapedHtml(
    $('reachability-license-box'),
    `
    <div class="metric-pair">
      <div class="mini-stat">
        <div class="mini-stat-val" style="color:var(--crit-fg);">${reachCount}</div>
        <div class="mini-stat-lbl">源码可达 CVE/投毒</div>
      </div>
      <div class="mini-stat">
        <div class="mini-stat-val">${unreachCount}</div>
        <div class="mini-stat-lbl">未直接导入 CVE</div>
      </div>
      <div class="mini-stat">
        <div class="mini-stat-val" style="color:var(--ok-fg);">${Number(report.suppressed_count)}</div>
        <div class="mini-stat-lbl">AST+熵值过滤误报</div>
      </div>
    </div>
    <div class="muted-xs">SBOM 许可证分布 (${report.components.length} 组件${unknownReach ? ` · 含 ${unknownReach} 项跨生态告警` : ''})</div>
    <div class="stacked-bar">
      <div style="width:${pct(permCnt)}%;background:#16a34a;" title="宽松兼容"></div>
      <div style="width:${pct(weakCnt)}%;background:#d97706;" title="弱传染需复核"></div>
      <div style="width:${pct(strongCnt)}%;background:#dc2626;" title="强传染冲突"></div>
      <div style="width:${pct(unkCnt)}%;background:#94a3b8;" title="未知"></div>
    </div>
    <div class="legend-row">
      <span><i class="dot" style="background:#16a34a;"></i>宽松兼容 (${permCnt})</span>
      <span><i class="dot" style="background:#d97706;"></i>弱传染 (${weakCnt})</span>
      <span><i class="dot" style="background:#dc2626;"></i>GPL/AGPL 冲突 (${strongCnt})</span>
      <span><i class="dot" style="background:#94a3b8;"></i>未知 (${unkCnt})</span>
    </div>
  `
  );

  mountEscapedHtml(
    $('roadmap-wrap'),
    s.roadmap.length
      ? s.roadmap
          .slice(0, 4)
          .map(
            (r) =>
              `<div class="roadmap-row"><span class="badge sev-high">${esc(r.priority)}</span> <strong>${esc(r.title)}</strong><div class="muted-xs" style="margin-top:3px;">${esc(r.action)}</div></div>`
          )
          .join('')
      : '<div class="muted">暂无紧急整改项，满足发布合规要求。</div>'
  );
}

function renderGovernance(checks) {
  const passedCount = checks.filter((g) => g.passed).length;
  $('gov-pass-summary').textContent = `通过 ${passedCount} / ${checks.length} 项`;
  mountEscapedHtml(
    $('governance-container'),
    `<table>
    <thead><tr><th>检查项</th><th>类别</th><th>状态</th><th>得分</th><th>检查详情</th></tr></thead>
    <tbody>${checks
      .map(
        (g) => `<tr>
          <td><strong>${esc(g.name)}</strong></td>
          <td class="muted">${esc(g.category)}</td>
          <td><span class="badge ${g.passed ? 'sev-ok' : 'sev-medium'}">${g.passed ? '通过' : '待完善'}</span></td>
          <td class="mono">${Number(g.score).toFixed(0)}/${Number(g.max_score).toFixed(0)}</td>
          <td>${esc(g.details)}</td>
        </tr>`
      )
      .join('')}</tbody>
  </table>`
  );
}

// Issues Master-Detail Workbench
function getFilteredIssues() {
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const minSev = currentSevFilter === 'ALL' ? 0 : sevRank[currentSevFilter] || 0;
  return unifiedIssues.filter((it) => {
    if (currentFilterKind !== 'all' && it.kind !== currentFilterKind) return false;
    if ((sevRank[it.sev] || 0) < minSev) return false;
    if (currentSearch) {
      const hay = `${it.title} ${it.subtitle} ${it.summary} ${it.pill}`.toLowerCase();
      if (!hay.includes(currentSearch)) return false;
    }
    return true;
  });
}

function renderIssueList() {
  const filtered = getFilteredIssues();
  if (!filtered.length) {
    mountEscapedHtml($('issue-list-pane'), '<div class="muted pad-lg">当前筛选条件下无匹配问题。</div>');
    mountEscapedHtml($('issue-detail-pane'), '<div class="muted pad-lg">请选择或调整筛选条件。</div>');
    return;
  }

  if (!filtered.some((x) => x.id === selectedIssueId)) {
    selectedIssueId = filtered[0].id;
  }

  mountEscapedHtml(
    $('issue-list-pane'),
    filtered
      .map(
        (it) => `<div class="issue-row ${it.id === selectedIssueId ? 'selected' : ''}" data-issue-id="${esc(it.id)}">
          <div class="issue-row-top">
            <span class="badge sev-${esc(it.sev).toLowerCase()}">${esc(it.sev)}</span>
            <span class="issue-row-title">${esc(it.title)}</span>
          </div>
          <div class="issue-row-meta">
            <span class="mono">${esc(it.subtitle)}</span>
            <span class="badge badge-neutral">${esc(it.pill)}</span>
          </div>
        </div>`
      )
      .join('')
  );

  $('issue-list-pane').querySelectorAll('.issue-row').forEach((row) => {
    row.addEventListener('click', () => {
      selectedIssueId = row.getAttribute('data-issue-id');
      renderIssueList();
    });
  });

  const activeIssue = filtered.find((x) => x.id === selectedIssueId) || filtered[0];
  renderIssueDetail(activeIssue);
}

async function renderIssueDetail(issue) {
  const runbookHtml = (issue.runbook || [])
    .map((step) => `<div class="runbook-step">${esc(step)}</div>`)
    .join('');

  const canTriage = issue.triageable && issue.file_path && currentReport && !currentReport.target_path.startsWith('http');

  mountEscapedHtml(
    $('issue-detail-pane'),
    `
    <div class="detail-header">
      <div>
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px;">
          <span class="badge sev-${esc(issue.sev).toLowerCase()}">${esc(issue.sev)}</span>
          <span class="badge badge-neutral">${esc(issue.pill)}</span>
          <code class="mono">${esc(issue.cwe)}</code>
        </div>
        <h3 class="detail-title">${esc(issue.title)}</h3>
        <div class="mono muted-xs">${esc(issue.subtitle)}</div>
      </div>
    </div>

    <div style="font-size:13px;color:var(--text-secondary);">${esc(issue.summary)}</div>

    <div id="detail-code-wrap">
      ${issue.snippet ? `<div class="code-viewer"><div class="code-line hl"><span class="line-num">${Number(issue.line_number)}</span><span>${esc(issue.snippet)}</span></div></div>` : ''}
    </div>

    <div class="runbook-box">
      <div class="sub-head">应急响应与修复 Runbook</div>
      ${runbookHtml}
    </div>

    <div class="action-strip">
      ${canTriage ? `<button id="btn-triage-inline" class="btn-secondary">标记误报并写入行内豁免</button>
      <button id="btn-triage-ignorefile" class="btn-secondary">将文件加入 .openguardignore</button>` : ''}
      <button id="btn-jump-remed" class="btn-primary">前往一键自动修复</button>
    </div>
  `
  );

  $('btn-jump-remed').addEventListener('click', () => switchView('remediation'));

  if (canTriage) {
    $('btn-triage-inline').addEventListener('click', () => applyTriage(issue, 'inline'));
    $('btn-triage-ignorefile').addEventListener('click', () => applyTriage(issue, 'ignorefile'));
  }

  // Fetch rich contextual code lines if local file path exists
  if (issue.file_path && currentReport && !currentReport.target_path.startsWith('http')) {
    try {
      const qs = new URLSearchParams({
        target: currentReport.target_path,
        file_path: issue.file_path,
        line: String(issue.line_number || 1),
        radius: '6',
      });
      const res = await fetch(`/api/file-context?${qs.toString()}`);
      if (res.ok) {
        const ctx = await res.json();
        const codeHtml = ctx.lines
          .map(
            (ln) =>
              `<div class="code-line ${ln.highlight ? 'hl' : ''}"><span class="line-num">${Number(ln.num)}</span><span>${esc(ln.text)}</span></div>`
          )
          .join('');
        mountEscapedHtml($('detail-code-wrap'), `<div class="code-viewer">${codeHtml}</div>`);
      }
    } catch {
      // Fallback to inline snippet already mounted
    }
  }
}

async function applyTriage(issue, mode) {
  if (!currentReport || !issue.file_path) return;
  const res = await fetch('/api/triage/ignore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: currentReport.target_path,
      file_path: issue.file_path,
      line_number: issue.line_number || 1,
      mode,
    }),
  });
  if (res.ok) {
    showStatus(`已写入豁免标记 (${mode})，正在刷新审计结果...`);
    $('btn-run-scan').click();
  }
}

$('issue-kind-pills').addEventListener('click', (e) => {
  const btn = e.target.closest('.filter-pill');
  if (!btn) return;
  currentFilterKind = btn.getAttribute('data-kind');
  $('issue-kind-pills').querySelectorAll('.filter-pill').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  renderIssueList();
});

$('issue-sev-filter').addEventListener('change', (e) => {
  currentSevFilter = e.target.value;
  renderIssueList();
});

$('finding-search').addEventListener('input', (e) => {
  currentSearch = (e.target.value || '').trim().toLowerCase();
  renderIssueList();
});

// SBOM Tab
let currentSbomFilter = '';
function renderSbomTab(report) {
  $('sbom-summary-tag').textContent = `共 ${report.components.length} 组件 · ${report.license_conflicts.length} 许可证风险`;
  const conflictSet = new Set(report.license_conflicts.map((c) => c.component_name));
  const comps = report.components.slice(0, 22);
  const w = 860;
  const h = Math.max(200, comps.length * 34 + 36);
  const rootY = h / 2;

  let lines = '';
  let nodes = `<rect x="16" y="${rootY - 18}" width="185" height="36" rx="6" fill="#111827"/>
    <text x="108" y="${rootY + 4}" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="600">${esc(report.target_name)} (${esc(report.project_license)})</text>`;

  comps.forEach((c, idx) => {
    const y = 22 + idx * 32;
    const isConflict = conflictSet.has(c.name);
    const fill = isConflict ? '#fef2f2' : '#ffffff';
    const stroke = isConflict ? '#dc2626' : '#d0d5dd';
    const txtColor = isConflict ? '#991b1b' : '#101828';
    const usedBadge = c.used_in_code ? ' · 已调用' : '';
    lines += `<path d="M 201 ${rootY} C 280 ${rootY}, 295 ${y + 12}, 360 ${y + 12}" fill="none" stroke="${stroke}" stroke-width="1.4"/>`;
    nodes += `<rect x="360" y="${y}" width="470" height="24" rx="5" fill="${fill}" stroke="${stroke}"/>
      <text x="372" y="${y + 16}" fill="${txtColor}" font-size="11.5" font-family="Consolas,monospace">${esc(c.name)}@${esc(c.version)} [${esc(c.ecosystem)}] · ${esc(c.license_id)}${usedBadge}</text>`;
  });

  mountEscapedHtml(
    $('dep-graph-container'),
    comps.length
      ? `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="max-width:100%;height:auto;">${lines}${nodes}</svg>`
      : '<span class="muted">未解析到外部依赖清单。</span>'
  );

  renderSbomTable(report);
}

function renderSbomTable(report) {
  const conflictMap = new Map(report.license_conflicts.map((c) => [c.component_name, c]));
  const rows = report.components.filter((c) => {
    if (!currentSbomFilter) return true;
    return `${c.name} ${c.ecosystem} ${c.license_id} ${c.purl}`.toLowerCase().includes(currentSbomFilter);
  });

  mountEscapedHtml(
    $('sbom-table-container'),
    `<table>
    <thead><tr><th>组件</th><th>版本</th><th>生态</th><th>代码引用状态</th><th>SPDX 许可证</th><th>兼容性</th><th>PURL</th></tr></thead>
    <tbody>${rows
      .map((c) => {
        const conf = conflictMap.get(c.name);
        const compatHtml = conf
          ? `<span class="badge ${conf.compatibility === 'INCOMPATIBLE' ? 'sev-critical' : 'sev-medium'}">${esc(conf.compatibility)}</span>`
          : `<span class="badge sev-ok">COMPATIBLE</span>`;
        const usageHtml = c.used_in_code
          ? `<span class="badge sev-low" title="${esc((c.import_locations || []).join(', '))}">已导入 (${esc((c.import_locations || [])[0] || '')})</span>`
          : `<span class="badge badge-neutral">未直接导入</span>`;
        return `<tr>
          <td><code class="mono">${esc(c.name)}</code></td>
          <td class="mono">${esc(c.version)}</td>
          <td>${esc(c.ecosystem)}</td>
          <td>${usageHtml}</td>
          <td><code class="mono">${esc(c.license_id)}</code></td>
          <td>${compatHtml}</td>
          <td class="mono muted-xs">${esc(c.purl)}</td>
        </tr>`;
      })
      .join('')}</tbody>
  </table>`
  );
}

$('sbom-search').addEventListener('input', (e) => {
  currentSbomFilter = (e.target.value || '').trim().toLowerCase();
  if (currentReport) renderSbomTable(currentReport);
});

// Run Scan
$('btn-run-scan').addEventListener('click', async () => {
  const target = $('scan-target').value.trim();
  if (!target) return showStatus('请先输入待扫描的本地路径或远程仓库 URL。', true);
  const btn = $('btn-run-scan');
  btn.disabled = true;
  showStatus('正在执行全维度安全、可达性与许可证审计...');
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

// Live Playground
$('snippet-code').addEventListener('input', () => {
  const lines = $('snippet-code').value ? $('snippet-code').value.split('\n').length : 0;
  $('snippet-line-count').textContent = `${lines} 行`;
});

$('btn-load-sample').addEventListener('click', () => {
  const awsSynthetic = ['AKIA', '7F4K9P2M8Q3X6Z1W'].join('');
  const ghSynthetic = ['ghp_', 'R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u'].join('');
  $('snippet-code').value =
    `import os\nimport yaml\n\n` +
    `# 1. 真实泄露的云端与 SCM 凭据（将被精准捕获）\n` +
    `AWS_ACCESS_KEY = "${awsSynthetic}"\n` +
    `GITHUB_TOKEN = "${ghSynthetic}"\n\n` +
    `# 2. 常见测试占位符与 Git SHA（将被 AST+熵值引擎智能过滤）\n` +
    `API_KEY = "sk-your_api_key_placeholder_example"\n` +
    `COMMIT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n\n` +
    `# 3. 高危 SAST 反序列化漏洞 (CWE-502)\n` +
    `def parse_cfg(raw_yaml: str):\n` +
    `    return yaml.load(raw_yaml)\n`;
  $('snippet-line-count').textContent = `${$('snippet-code').value.split('\n').length} 行`;
});

$('btn-run-snippet').addEventListener('click', async () => {
  const res = await fetch('/api/scan/snippet', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: $('snippet-code').value, filename: $('snippet-filename').value }),
  });
  const data = await res.json();
  $('snippet-suppressed-badge').textContent = `已自动过滤 ${Number(data.suppressed_count)} 条低置信误报`;
  const cards = [];
  data.secrets.forEach((f) => {
    cards.push(`<div class="roadmap-row"><span class="badge sev-${esc(f.severity).toLowerCase()}">${esc(f.severity)}</span> <strong>${esc(f.rule_name)}</strong> <code class="mono">L${Number(f.line_number)}</code> · 脱敏：<code>${esc(f.matched_masked)}</code> · AST上下文：<code>${esc(f.ast_context)}</code></div>`);
  });
  data.code_security_findings.forEach((cs) => {
    cards.push(`<div class="roadmap-row"><span class="badge sev-${esc(cs.severity).toLowerCase()}">${esc(cs.severity)}</span> <strong>[${esc(cs.cwe_id)}] ${esc(cs.rule_name)}</strong> <code class="mono">L${Number(cs.line_number)}</code> · ${esc(cs.description)}</div>`);
  });
  const suppLog = (data.suppressed_samples || []).length
    ? `<div class="divider"></div><div class="sub-head">AST + Shannon 熵降噪抑制详情</div>` +
      data.suppressed_samples
        .map(
          (s) => `<div class="muted-xs" style="padding:3px 0;">• L${Number(s.line_number)} <code>${esc(s.masked)}</code> — 抑制原因：<code>${esc(s.reason)}</code></div>`
        )
        .join('')
    : '';
  mountEscapedHtml($('snippet-findings'), (cards.join('') || '<div class="muted">未发现安全问题。</div>') + suppLog);
});

// AutoFix
async function runAutofix(apply) {
  const target = $('autofix-target').value.trim();
  if (!target) return;
  const res = await fetch(apply ? '/api/autofix/apply' : '/api/autofix/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      fix_secrets: $('fix-secrets').checked,
      fix_deps: $('fix-deps') ? $('fix-deps').checked : false,
      fix_docs: $('fix-docs').checked,
      license_id: $('fix-license').value,
    }),
  });
  const data = await res.json();
  const box = $('autofix-output');
  box.classList.remove('hidden');
  if (!res.ok) {
    mountEscapedHtml(box, `<div style="color:var(--crit-fg);">${esc(data.detail || '操作失败')}</div>`);
    return;
  }
  const colorDiff = (raw) =>
    esc(raw)
      .split('\n')
      .map((ln) => (ln.startsWith('+') ? `<span class="diff-add">${ln}</span>` : ln.startsWith('-') ? `<span class="diff-del">${ln}</span>` : `<span>${ln}</span>`))
      .join('\n');

  const diffs = (data.secrets.previews || [])
    .map(
      (p) =>
        `<div style="margin-bottom:12px;"><strong>${esc(p.file_path)}</strong> <span class="muted-xs">→ 提取环境变量：<code>${esc(p.env_vars_added.join(', '))}</code></span><pre class="diff-pre">${colorDiff(p.unified_diff)}</pre></div>`
    )
    .join('');
  const depDiffs = ((data.deps && data.deps.previews) || [])
    .map(
      (p) =>
        `<div style="margin-bottom:12px;"><strong>${esc(p.file_path)}</strong> <span class="muted-xs">→ 安全升级依赖：<code>${esc((p.upgraded_packages || []).join(', '))}</code></span><pre class="diff-pre">${colorDiff(p.unified_diff)}</pre></div>`
    )
    .join('');
  const docRows = Object.entries(data.docs || {})
    .map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`)
    .join('');

  const depCount = (data.deps && Number(data.deps.packages_upgraded)) || 0;
  mountEscapedHtml(
    box,
    `<div class="card-head"><h3 class="card-title">${data.applied ? '已写入修复（原文件已备份至 .openguard_backup/）' : 'Dry-Run 自动修复 Diff 预览'}</h3>
      <span class="mono muted-xs">密钥 ${Number(data.secrets.findings_remediated)} 处 · 漏洞依赖升级 ${depCount} 项</span></div>
      ${diffs || '<div class="muted">暂无需要脱敏重构的源码文件。</div>'}
      ${depDiffs ? `<div class="divider"></div><div class="sub-head">漏洞依赖最小安全升级 Diff</div>${depDiffs}` : ''}
      ${docRows ? `<table><thead><tr><th>开源治理文档</th><th>执行状态</th></tr></thead><tbody>${docRows}</tbody></table>` : ''}`
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
      ? `<table><thead><tr><th>扫描 ID</th><th>时间</th><th>目标</th><th>得分</th><th>密钥</th><th>漏洞</th><th>许可证冲突</th><th>操作</th></tr></thead>
      <tbody>${rows
        .map(
          (r) => `<tr>
            <td class="mono">${esc(r.scan_id)}</td>
            <td class="muted-xs">${esc(r.scanned_at)}</td>
            <td>${esc(r.target_name)}</td>
            <td><strong>${Number(r.total_score)} (${esc(r.grade)})</strong></td>
            <td>${Number(r.secrets_count)}</td>
            <td>${Number(r.vulns_count)}</td>
            <td>${Number(r.license_conflicts_count)}</td>
            <td><button class="btn-secondary" data-load-scan="${esc(r.scan_id)}">载入查看</button></td>
          </tr>`
        )
        .join('')}</tbody></table>`
      : '<div class="muted pad-lg">暂无历史扫描记录。</div>'
  );
  $('history-table-box').querySelectorAll('[data-load-scan]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const resItem = await fetch(`/api/history/${encodeURIComponent(btn.getAttribute('data-load-scan'))}`);
      renderReport(await resItem.json());
      switchView('overview');
    });
  });
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
    `<div style="margin-bottom:10px;">
      <strong>评分变化：</strong> ${Number(d.before_score)} (${esc(d.before_grade)}) → <strong>${Number(d.after_score)} (${esc(d.after_grade)})</strong>
      <span class="badge ${d.score_delta >= 0 ? 'sev-ok' : 'sev-critical'}">${sign}${Number(d.score_delta)} 分</span>
      &nbsp;|&nbsp; 已修复：<strong>${Number(d.resolved_count)}</strong> &nbsp;|&nbsp; 新增：<strong>${Number(d.new_count)}</strong>
    </div>
    ${d.resolved_items.length ? `<div><strong>已消除问题：</strong><ul>${d.resolved_items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
    ${d.new_items.length ? `<div><strong>新增问题：</strong><ul>${d.new_items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}`
  );
});

// Global Ctrl+K Command Palette
function openCmdk() {
  $('cmdk-backdrop').classList.remove('hidden');
  $('cmdk-input').value = '';
  renderCmdk('');
  $('cmdk-input').focus();
}

function closeCmdk() {
  $('cmdk-backdrop').classList.add('hidden');
}

function renderCmdk(query) {
  const q = query.trim().toLowerCase();
  const commands = [
    { label: '跳转：概览与质量门禁 (Overview)', tag: '视图', action: () => switchView('overview') },
    { label: '跳转：问题溯源工作台 (Issues Split-Pane)', tag: '视图', action: () => switchView('issues') },
    { label: '跳转：供应链 SBOM 与可达性矩阵', tag: '视图', action: () => switchView('sbom') },
    { label: '跳转：实时代码检测台 (Playground)', tag: '视图', action: () => switchView('playground') },
    { label: '跳转：一键脱敏修复中心', tag: '视图', action: () => switchView('remediation') },
    { label: '操作：切换浅色 / 深色主题', tag: '外观', action: () => $('btn-theme-toggle').click() },
    { label: '操作：重新运行当前仓库深度审计', tag: '扫描', action: () => $('btn-run-scan').click() },
  ];

  unifiedIssues.slice(0, 20).forEach((it) => {
    commands.push({
      label: `${it.title} (${it.subtitle})`,
      tag: it.sev,
      action: () => {
        selectedIssueId = it.id;
        switchView('issues');
        renderIssueList();
      },
    });
  });

  const matched = commands.filter((c) => !q || `${c.label} ${c.tag}`.toLowerCase().includes(q)).slice(0, 10);
  mountEscapedHtml(
    $('cmdk-results'),
    matched.length
      ? matched
          .map((c, idx) => `<div class="cmdk-item" data-cmd-idx="${idx}"><span>${esc(c.label)}</span><span class="badge badge-neutral">${esc(c.tag)}</span></div>`)
          .join('')
      : '<div class="muted pad-lg">未找到匹配指令或问题项。</div>'
  );
  $('cmdk-results').querySelectorAll('.cmdk-item').forEach((el) => {
    el.addEventListener('click', () => {
      const item = matched[Number(el.getAttribute('data-cmd-idx'))];
      closeCmdk();
      if (item) item.action();
    });
  });
}

$('btn-cmdk').addEventListener('click', openCmdk);
$('cmdk-input').addEventListener('input', (e) => renderCmdk(e.target.value));
$('cmdk-backdrop').addEventListener('click', (e) => {
  if (e.target === $('cmdk-backdrop')) closeCmdk();
});

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if ($('cmdk-backdrop').classList.contains('hidden')) openCmdk();
    else closeCmdk();
  } else if (e.key === 'Escape') {
    closeCmdk();
  }
});

initApp();
