const scenarioInput = document.getElementById('scenario-input');
const targetInput = document.getElementById('target-input');
const runButton = document.getElementById('run-button');
const statusNode = document.getElementById('status');
const stepsNode = document.getElementById('steps');
const errorsNode = document.getElementById('errors');
const reportNode = document.getElementById('report');
const findingsNode = document.getElementById('findings');
const rawNode = document.getElementById('raw');
const labsNode = document.getElementById('labs');
const runListNode = document.getElementById('run-list');
const kbResults = document.getElementById('kb-results');
const egOut = document.getElementById('eg-out');

const cockpitTarget = document.getElementById('cockpit-target');
const cockpitRunId = document.getElementById('cockpit-run-id');
const runCountBadge = document.getElementById('run-count-badge');
const findingsCountBadge = document.getElementById('findings-count-badge');
const reportRenderedContent = document.getElementById('report-rendered-content');
const copyRunIdBtn = document.getElementById('copy-run-id-btn');
const copyReportBtn = document.getElementById('copy-report-btn');
const openReportLink = document.getElementById('open-report-link');
const copyRawBtn = document.getElementById('copy-raw-btn');
const refreshRunsBtn = document.getElementById('refresh-runs-btn');

let pollTimer = null;
let activeRunId = null;
let currentReportMarkdown = '';

const labels = {operator:'协调者', recon:'侦察', code_audit:'代码审计', env_repro:'环境复现', vuln:'漏洞分析', exploit:'验证', post_exploit:'横向移动', report:'报告'};
const statuses = {queued:'排队', pending:'等待', running:'执行中', success:'完成', skipped:'跳过', failed:'失败', completed:'已完成', verified:'已差分验证'};

/* Tab Switching (App Header) */
document.querySelectorAll('.nav-tab').forEach(tabBtn => {
  tabBtn.addEventListener('click', () => {
    const targetId = tabBtn.getAttribute('data-tab');
    document.querySelectorAll('.nav-tab').forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tabBtn.classList.add('active');
    tabBtn.setAttribute('aria-selected', 'true');
    const targetPanel = document.getElementById(targetId);
    if (targetPanel) targetPanel.classList.add('active');

    if (targetId === 'tab-labs' && (!labsNode.children.length || labsNode.textContent.includes('正在诊断'))) {
      refreshLabs().catch(console.error);
    }
  });
});

/* Results Sub-View Switching (Findings / Report / Raw) */
document.querySelectorAll('.view-tab').forEach(viewBtn => {
  viewBtn.addEventListener('click', () => {
    const targetView = viewBtn.getAttribute('data-view');
    document.querySelectorAll('.view-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    viewBtn.classList.add('active');
    const targetPanel = document.getElementById(targetView);
    if (targetPanel) targetPanel.classList.add('active');
  });
});

/* Quick Target Chips */
document.querySelectorAll('.chip-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const scenario = btn.getAttribute('data-scenario');
    const target = btn.getAttribute('data-target');
    if (scenario) scenarioInput.value = scenario;
    if (target) targetInput.value = target;
    scenarioInput.dispatchEvent(new Event('change'));
  });
});

/* Quick Knowledge Keywords */
document.querySelectorAll('.tag-chip').forEach(btn => {
  btn.addEventListener('click', () => {
    const q = btn.getAttribute('data-query');
    if (q) {
      document.getElementById('kb-input').value = q;
      searchKnowledge().catch(err => {
        kbResults.innerHTML = `<div class="empty-state">错误：${err.message}</div>`;
      });
    }
  });
});

scenarioInput.addEventListener('change', () => {
  const label = runButton.querySelector('span');
  const setLabel = (value) => { if (label) label.textContent = value; else runButton.textContent = value; };
  if (scenarioInput.value === 'local-web') {
    if (targetInput.value === 'demo.local' || targetInput.value.includes('18089') || !targetInput.value) {
      targetInput.value = 'http://127.0.0.1:18088';
    }
    setLabel('Run local-web');
  } else if (scenarioInput.value === 'complex-web') {
    if (targetInput.value === 'demo.local' || targetInput.value.includes('18088') || !targetInput.value) {
      targetInput.value = 'http://127.0.0.1:18089';
    }
    setLabel('Run complex-web');
  } else {
    if (targetInput.value.includes('18088') || targetInput.value.includes('18089') || !targetInput.value) {
      targetInput.value = 'demo.local';
    }
    setLabel('Run Demo');
  }
});

/* Copy Helper with Button Feedback */
function copyText(text, btnElement, successMsg = '已复制 ✓') {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (!btnElement) return;
    const orig = btnElement.textContent;
    btnElement.textContent = successMsg;
    setTimeout(() => { btnElement.textContent = orig; }, 1800);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    if (!btnElement) return;
    const orig = btnElement.textContent;
    btnElement.textContent = successMsg;
    setTimeout(() => { btnElement.textContent = orig; }, 1800);
  });
}

if (copyRunIdBtn) {
  copyRunIdBtn.addEventListener('click', () => copyText(cockpitRunId.textContent, copyRunIdBtn));
}
if (copyReportBtn) {
  copyReportBtn.addEventListener('click', () => copyText(currentReportMarkdown, copyReportBtn));
}
if (copyRawBtn) {
  copyRawBtn.addEventListener('click', () => copyText(rawNode.textContent, copyRawBtn));
}
if (refreshRunsBtn) {
  refreshRunsBtn.addEventListener('click', () => refreshRuns().catch(console.error));
}

function badge(status) {
  const span = document.createElement('span');
  const normalized = String(status || '');
  span.className = 'badge';
  if (['ready','catalog_ready','completed','success','verified'].includes(normalized)) span.classList.add('ok');
  else if (['not_ready','blocked','running','queued'].includes(normalized)) span.classList.add('warn');
  else if (['failed','danger'].includes(normalized)) span.classList.add('danger');
  else span.classList.add('info');
  span.textContent = statuses[normalized] || normalized;
  return span;
}

/* Simple Offline Markdown-to-HTML Parser */
function renderMarkdown(md) {
  if (!md) return '<div class="empty-state">暂无报告内容</div>';
  const lines = md.split('\n');
  let html = '';
  let inCodeBlock = false;
  let codeBuffer = '';
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('```')) {
      if (!inCodeBlock) {
        inCodeBlock = true;
        codeBuffer = '';
      } else {
        inCodeBlock = false;
        html += `<pre><code>${escapeHtml(codeBuffer.trim())}</code></pre>`;
      }
      continue;
    }
    if (inCodeBlock) {
      codeBuffer += line + '\n';
      continue;
    }

    if (line.startsWith('# ')) {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<h1>${formatInline(line.slice(2))}</h1>`;
    } else if (line.startsWith('## ')) {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<h2>${formatInline(line.slice(3))}</h2>`;
    } else if (line.startsWith('### ')) {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<h3>${formatInline(line.slice(4))}</h3>`;
    } else if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += `<li>${formatInline(line.trim().slice(2))}</li>`;
    } else if (line.trim().length === 0) {
      if (inList) { html += '</ul>'; inList = false; }
    } else {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<p>${formatInline(line)}</p>`;
    }
  }
  if (inList) html += '</ul>';
  return html;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}

function formatInline(str) {
  let res = escapeHtml(str);
  res = res.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  res = res.replace(/`([^`]+)`/g, '<code>$1</code>');
  res = res.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  return res;
}

function renderCapabilities(catalog) {
  const cards = document.getElementById('capability-cards');
  if (!cards) return;
  cards.replaceChildren();
  (catalog.capabilities || []).forEach(item => {
    const card = document.createElement('article');
    card.className = 'spec-card';
    const title = document.createElement('div');
    title.className = 'spec-card-title';
    title.textContent = item.title;
    const statusTag = document.createElement('span');
    statusTag.className = 'badge ok';
    statusTag.textContent = item.status;
    title.appendChild(statusTag);
    const body = document.createElement('div');
    body.className = 'spec-card-desc';
    body.textContent = item.summary;
    card.append(title, body);
    cards.appendChild(card);
  });

  const agents = document.getElementById('agent-cards');
  if (!agents) return;
  agents.replaceChildren();
  (catalog.agents || []).forEach(item => {
    const card = document.createElement('article');
    card.className = 'agent-card';
    const name = document.createElement('div');
    name.className = 'agent-card-name';
    name.textContent = `@${item.name}`;
    const title = document.createElement('div');
    title.className = 'agent-card-label';
    title.textContent = item.label;
    const body = document.createElement('div');
    body.className = 'agent-card-summary';
    body.textContent = item.summary;
    card.append(name, title, body);
    agents.appendChild(card);
  });

  const safety = document.getElementById('safety-list');
  if (!safety) return;
  safety.replaceChildren();
  (catalog.safety || []).forEach(text => {
    const li = document.createElement('li');
    li.textContent = text;
    safety.appendChild(li);
  });
}

function renderLabs(items) {
  if (!labsNode) return;
  labsNode.replaceChildren();
  if (!items.length) {
    labsNode.innerHTML = '<div class="empty-state">未检测到靶场信息</div>';
    return;
  }
  items.forEach(item => {
    const card = document.createElement('article');
    card.className = 'lab-card ' + (item.status || '');

    const header = document.createElement('div');
    header.className = 'lab-header';
    const title = document.createElement('span');
    title.className = 'lab-title';
    title.textContent = item.lab_id;
    header.append(title, badge(item.status));

    const req = document.createElement('div');
    req.className = 'lab-req';
    req.textContent = '环境要求：' + item.requirement;

    const evidence = document.createElement('div');
    evidence.className = 'lab-evidence';
    evidence.textContent = item.evidence ? `状态证据：${item.evidence}` : '无异常证据';

    card.append(header, req, evidence);

    if (item.next_action) {
      const actionRow = document.createElement('div');
      actionRow.className = 'lab-action';
      actionRow.innerHTML = `<span>建议处理：</span><code class="action-cmd">${escapeHtml(item.next_action)}</code>`;
      card.appendChild(actionRow);
    }

    labsNode.appendChild(card);
  });
}

function renderRunList(items) {
  if (!runListNode) return;
  if (runCountBadge) runCountBadge.textContent = items.length;
  runListNode.replaceChildren();
  if (!items.length) {
    runListNode.innerHTML = '<div class="empty-state">暂无历史运行</div>';
    return;
  }
  items.slice().reverse().forEach(item => {
    const node = document.createElement('article');
    node.className = 'run-item' + (item.run_id === activeRunId ? ' active' : '');

    const topRow = document.createElement('div');
    topRow.className = 'run-item-top';
    const title = document.createElement('span');
    title.className = 'run-id-tag';
    title.textContent = item.run_id;
    topRow.append(title, badge(item.status));

    const metaRow = document.createElement('div');
    metaRow.className = 'run-meta-row';
    const target = document.createElement('span');
    target.className = 'run-target-tag';
    target.textContent = `${item.scenario} · ${item.target}`;

    const findingTag = document.createElement('span');
    findingTag.className = 'run-findings-tag';
    findingTag.textContent = `${item.finding_count || 0} 发现`;

    metaRow.append(target, findingTag);
    node.append(topRow, metaRow);

    node.addEventListener('click', () => {
      activeRunId = item.run_id;
      poll(item.run_id);
      refreshRuns();
    });
    runListNode.appendChild(node);
  });
}

function render(state) {
  activeRunId = state.run_id || activeRunId;

  let targetDisplay = 'demo.local';
  if (typeof state.target === 'string') {
    targetDisplay = state.target;
  } else if (state.target && typeof state.target === 'object') {
    if (state.target.address) {
      targetDisplay = state.target.address;
    } else if (state.target.host) {
      const portSuffix = state.target.port && state.target.port !== 80 && state.target.port !== 443 ? `:${state.target.port}` : '';
      targetDisplay = `${state.target.scheme || 'http'}://${state.target.host}${portSuffix}`;
    }
  }
  if (cockpitTarget) cockpitTarget.textContent = targetDisplay;
  if (cockpitRunId) cockpitRunId.textContent = state.run_id || 'none';

  const statusKey = state.status || 'unknown';
  statusNode.textContent = statuses[statusKey] || statusKey;
  statusNode.className = 'badge-status ' + (['completed', 'success'].includes(statusKey) ? 'ok' : ['running', 'queued'].includes(statusKey) ? 'warn' : ['failed'].includes(statusKey) ? 'danger' : 'info');

  // Pipeline Stepper
  stepsNode.replaceChildren();
  const stepsData = (state.progress && state.progress.steps) || [
    {name: 'recon', agent: 'recon', status: 'queued'},
    {name: 'code_audit', agent: 'code_audit', status: 'queued'},
    {name: 'env_repro', agent: 'env_repro', status: 'queued'},
    {name: 'vuln', agent: 'vuln', status: 'queued'},
    {name: 'exploit', agent: 'exploit', status: 'queued'},
    {name: 'post_exploit', agent: 'post_exploit', status: 'queued'},
    {name: 'report', agent: 'report', status: 'queued'}
  ];

  stepsData.forEach((step, idx) => {
    const card = document.createElement('div');
    const status = step.status || 'queued';
    card.className = `step-card ${status}`;

    const header = document.createElement('div');
    header.className = 'step-header';
    const name = document.createElement('span');
    name.className = 'step-agent-name';
    name.textContent = `${idx + 1}. ${labels[step.agent] || step.agent || step.name}`;

    const statusTag = document.createElement('span');
    statusTag.className = 'step-state-tag';
    statusTag.textContent = statuses[status] || status;
    header.append(name, statusTag);

    const summary = document.createElement('div');
    summary.className = 'step-summary';
    const summaries = {
      operator: '接收汇报并分配任务',
      recon: '探测目标训练路径',
      code_audit: '扫描实验源码 sink',
      env_repro: '输出启动/重置/清理步骤',
      vuln: '识别差分特征与 CWE',
      exploit: '执行确定性差分验证',
      post_exploit: '模拟横向移动，不实执行',
      report: '生成可审计完整报告'
    };
    summary.textContent = summaries[step.agent] || step.name || step.agent;

    card.append(header, summary);
    stepsNode.appendChild(card);
  });

  // Errors
  const errors = state.errors || [];
  if (errors.length) {
    errorsNode.style.display = 'block';
    errorsNode.textContent = '错误：' + errors.join('；');
  } else {
    errorsNode.style.display = 'none';
    errorsNode.textContent = '';
  }

  // Findings
  findingsNode.replaceChildren();
  const findings = state.findings || [];
  if (findingsCountBadge) findingsCountBadge.textContent = findings.length;

  if (!findings.length) {
    findingsNode.innerHTML = '<div class="empty-state">尚未检出风险漏洞</div>';
  } else {
    findings.forEach(f => {
      const card = document.createElement('article');
      const sev = (f.severity || 'info').toLowerCase();
      card.className = `finding-card ${sev}`;

      const header = document.createElement('div');
      header.className = 'finding-header';

      const titleGroup = document.createElement('div');
      titleGroup.className = 'finding-title-group';
      const idTag = document.createElement('span');
      idTag.className = 'finding-id';
      idTag.textContent = f.finding_id || 'FINDING';
      const title = document.createElement('span');
      title.className = 'finding-title';
      title.textContent = f.title || '';
      titleGroup.append(idTag, title);

      const sevPill = document.createElement('span');
      sevPill.className = `severity-pill ${sev}`;
      sevPill.textContent = f.severity || 'INFO';
      header.append(titleGroup, sevPill);

      const metaRow = document.createElement('div');
      metaRow.className = 'finding-meta-row';
      metaRow.innerHTML = `
        <span class="meta-item"><span class="meta-label">端点:</span> <code class="meta-val">${escapeHtml(f.endpoint || 'n/a')}</code></span>
        <span class="meta-item"><span class="meta-label">CWE:</span> <code class="meta-val">${escapeHtml(f.cwe || 'n/a')}</code></span>
        <span class="meta-item"><span class="meta-label">置信度:</span> <span class="meta-val">${Math.round((f.confidence || 0) * 100)}%</span></span>
        <span class="meta-item"><span class="meta-label">来源:</span> <span class="meta-val">${escapeHtml(f.source || 'n/a')}</span></span>
      `;

      const desc = document.createElement('div');
      desc.className = 'finding-desc';
      desc.textContent = f.description || '';

      card.append(header, metaRow, desc);

      if (f.evidence) {
        const evBox = document.createElement('div');
        evBox.className = 'finding-evidence-box';
        evBox.textContent = 'Evidence: ' + f.evidence;
        card.appendChild(evBox);
      }

      if (f.remediation) {
        const remBox = document.createElement('div');
        remBox.className = 'finding-remediation';
        remBox.innerHTML = `<strong>修复建议:</strong> <span>${escapeHtml(f.remediation)}</span>`;
        card.appendChild(remBox);
      }

      findingsNode.appendChild(card);
    });
  }

  // Report action button
  reportNode.replaceChildren();
  if (state.report_url) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-secondary btn-sm';
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> <span>预览审计报告</span>`;
    btn.addEventListener('click', () => {
      const reportTabBtn = document.querySelector('.view-tab[data-view="view-report"]');
      if (reportTabBtn) reportTabBtn.click();
    });
    reportNode.appendChild(btn);

    if (openReportLink) {
      openReportLink.href = state.report_url;
      openReportLink.style.display = 'inline-flex';
    }

    // Fetch and render report markdown inside report tab
    fetch(state.report_url)
      .then(res => res.ok ? res.text() : '')
      .then(md => {
        if (md && reportRenderedContent) {
          currentReportMarkdown = md;
          reportRenderedContent.innerHTML = renderMarkdown(md);
        }
      })
      .catch(console.error);
  }

  rawNode.textContent = JSON.stringify(state, null, 2);
}

async function poll(runId) {
  try {
    const response = await fetch('/api/runs/' + encodeURIComponent(runId));
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || ('HTTP ' + response.status));
    render(state);
    if (!['completed', 'failed'].includes(state.status)) {
      pollTimer = setTimeout(() => poll(runId), 300);
    } else {
      refreshRuns();
    }
  } catch (error) {
    errorsNode.style.display = 'block';
    errorsNode.textContent = '错误：' + error.message;
  }
}

async function refreshCatalog() {
  const response = await fetch('/api/catalog');
  const catalog = await response.json();
  if (!response.ok) throw new Error(catalog.error || 'catalog failed');
  renderCapabilities(catalog);
}

async function refreshLabs() {
  labsNode.innerHTML = '<div class="empty-state">正在诊断靶场就绪状态...</div>';
  const response = await fetch('/api/labs');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'labs failed');
  renderLabs(payload.labs || []);
}

async function refreshRuns() {
  const response = await fetch('/api/runs');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'runs failed');
  const runs = payload.runs || [];
  renderRunList(runs);
  if (runs.length && !activeRunId) {
    const latest = runs[runs.length - 1];
    activeRunId = latest.run_id;
    poll(latest.run_id);
  }
}

async function searchKnowledge() {
  const q = document.getElementById('kb-input').value.trim();
  if (!q) {
    kbResults.innerHTML = '<div class="empty-state">请输入检索词</div>';
    return;
  }
  kbResults.innerHTML = '<div class="empty-state">检索中...</div>';
  const response = await fetch('/api/knowledge?q=' + encodeURIComponent(q) + '&limit=6');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'knowledge failed');
  kbResults.replaceChildren();
  const items = payload.results || [];
  if (!items.length) {
    kbResults.innerHTML = '<div class="empty-state">没有足够相关的条目</div>';
    return;
  }
  items.forEach(item => {
    const card = document.createElement('article');
    card.className = 'kb-card';

    const header = document.createElement('div');
    header.className = 'kb-card-header';
    const title = document.createElement('span');
    title.className = 'kb-card-title';
    title.textContent = item.title;
    const score = document.createElement('span');
    score.className = 'kb-score-pill';
    score.textContent = `Match ${(Number(item.score || 0) * 100).toFixed(1)}%`;
    header.append(title, score);

    const meta = document.createElement('div');
    meta.className = 'kb-meta';
    meta.textContent = `${item.entry_id} · ${item.category || 'cve'} · ${item.cwe || ''}`;

    const text = document.createElement('div');
    text.className = 'kb-text';
    text.textContent = item.text || '';

    card.append(header, meta, text);

    if (item.remediation) {
      const fix = document.createElement('div');
      fix.className = 'kb-remediation';
      fix.innerHTML = `<strong>防护建议：</strong> <span>${escapeHtml(item.remediation)}</span>`;
      card.appendChild(fix);
    }

    kbResults.appendChild(card);
  });
}

async function checkExploitGym() {
  const task = document.getElementById('eg-input').value.trim() || 'v8:sbxbrk/398773898';
  egOut.textContent = '检查中...';
  const response = await fetch('/api/exploitgym?task_id=' + encodeURIComponent(task));
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'exploitgym failed');
  egOut.textContent = JSON.stringify(payload, null, 2);
}

document.getElementById('run-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (pollTimer) clearTimeout(pollTimer);
  runButton.disabled = true;
  statusNode.textContent = '提交中...';
  errorsNode.style.display = 'none';
  errorsNode.textContent = '';
  reportNode.replaceChildren();
  try {
    const response = await fetch('/api/runs', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({target: targetInput.value, scenario: scenarioInput.value})
    });
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || ('HTTP ' + response.status));
    render(state);
    await refreshRuns();
    poll(state.run_id);
  } catch (error) {
    statusNode.textContent = '提交失败';
    errorsNode.style.display = 'block';
    errorsNode.textContent = '错误：' + error.message;
  } finally {
    runButton.disabled = false;
  }
});

document.getElementById('labs-button').addEventListener('click', () => refreshLabs().catch(err => {
  labsNode.innerHTML = `<div class="empty-state">错误：${err.message}</div>`;
}));
document.getElementById('catalog-refresh').addEventListener('click', () => refreshCatalog().catch(err => {
  errorsNode.style.display = 'block';
  errorsNode.textContent = '错误：' + err.message;
}));
document.getElementById('kb-button').addEventListener('click', () => searchKnowledge().catch(err => {
  kbResults.innerHTML = `<div class="empty-state">错误：${err.message}</div>`;
}));
document.getElementById('eg-button').addEventListener('click', () => checkExploitGym().catch(err => {
  egOut.textContent = '错误：' + err.message;
}));

Promise.all([refreshCatalog(), refreshRuns()]).catch(err => {
  if (errorsNode) {
    errorsNode.style.display = 'block';
    errorsNode.textContent = '错误：' + err.message;
  }
});

/* Initialize Default Pipeline Stepper UI */
function renderDefaultSteps() {
  if (stepsNode && stepsNode.children.length === 0) {
    const defaultSteps = [
      {agent: 'recon', desc: '探测目标训练路径'},
      {agent: 'code_audit', desc: '扫描实验源码 sink'},
      {agent: 'env_repro', desc: '输出启动/重置/清理步骤'},
      {agent: 'vuln', desc: '识别差分特征与 CWE'},
      {agent: 'exploit', desc: '执行确定性差分验证'},
      {agent: 'post_exploit', desc: '模拟横向移动，不实执行'},
      {agent: 'report', desc: '生成可审计完整报告'}
    ];
    defaultSteps.forEach((step, idx) => {
      const card = document.createElement('div');
      card.className = 'step-card queued';
      const header = document.createElement('div');
      header.className = 'step-header';
      const name = document.createElement('span');
      name.className = 'step-agent-name';
      name.textContent = `${idx + 1}. ${labels[step.agent] || step.agent}`;
      const statusTag = document.createElement('span');
      statusTag.className = 'step-state-tag';
      statusTag.textContent = '就绪';
      header.append(name, statusTag);
      const summary = document.createElement('div');
      summary.className = 'step-summary';
      summary.textContent = step.desc;
      card.append(header, summary);
      stepsNode.appendChild(card);
    });
  }
}
renderDefaultSteps();
