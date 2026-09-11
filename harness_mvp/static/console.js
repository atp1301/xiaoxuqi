const scenarioInput = document.getElementById('scenario-input');
const modeInput = document.getElementById('mode-input');
const modeNote = document.getElementById('mode-note');
const targetInput = document.getElementById('target-input');
const runButton = document.getElementById('run-button');
const statusNode = document.getElementById('status');
const stepsNode = document.getElementById('steps');
const errorsNode = document.getElementById('errors');
const modeNoticeNode = document.getElementById('mode-notice');
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
  const isExploitGym = scenarioInput.value === 'exploitgym';
  const isExploitGymTask = /^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(targetInput.value.trim());
  modeInput.disabled = isExploitGym;
  if (isExploitGym) {
    if (!targetInput.value || targetInput.value === 'demo.local' || targetInput.value.includes('18088') || targetInput.value.includes('18089') || targetInput.value.startsWith('http')) {
      targetInput.value = 'v8:sbxbrk/398773898';
    }
    targetInput.placeholder = '输入 ExploitGym Task ID，如 v8:sbxbrk/398773898';
    setLabel('检查 ExploitGym');
    if (modeNote) modeNote.textContent = 'ExploitGym 当前仅做只读任务清单检查，不启动 benchmark、不执行 payload，也不会创建普通运行记录。';
  } else if (scenarioInput.value === 'local-web') {
    if (isExploitGymTask || targetInput.value === 'demo.local' || targetInput.value.includes('18089') || !targetInput.value) {
      targetInput.value = 'http://127.0.0.1:18088';
    }
    targetInput.placeholder = '请输入合规白名单目标';
    setLabel('Run local-web');
  } else if (scenarioInput.value === 'complex-web') {
    if (isExploitGymTask || targetInput.value === 'demo.local' || targetInput.value.includes('18088') || !targetInput.value) {
      targetInput.value = 'http://127.0.0.1:18089';
    }
    targetInput.placeholder = '请输入合规白名单目标';
    setLabel('Run complex-web');
  } else {
    if (isExploitGymTask || targetInput.value.includes('18088') || targetInput.value.includes('18089') || !targetInput.value) {
      targetInput.value = 'demo.local';
    }
    targetInput.placeholder = '请输入合规白名单目标';
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
  // Only http(s) targets become links. Model-authored text reaches this
  // function, so a bare `$2` would turn `[click](javascript:...)` into a live
  // link. Anything else keeps the literal label and drops the URL.
  res = res.replace(/\[([^\]]+)\]\(([^)]*)\)/g, (match, label, url) => {
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed)) return label;
    return `<a href="${trimmed}" target="_blank" rel="noopener">${label}</a>`;
  });
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
  if (safety) {
    safety.replaceChildren();
    (catalog.safety || []).forEach(text => {
      const li = document.createElement('li');
      li.textContent = text;
      safety.appendChild(li);
    });
  }
  renderModeNote(catalog.llm);
}

function renderModeNote(llm) {
  if (!modeNote) return;
  if (!llm) {
    modeNote.textContent = '决策模式：未获取到服务端 LLM 配置（catalog.llm 缺失）';
    return;
  }
  const sites = (llm.call_sites || []).join(' / ');
  const where = llm.base_url_host ? `${llm.base_url_host}` : '未配置端点';
  modeNote.textContent = llm.configured
    ? `决策模式：模型已配置（${llm.model} @ ${where}，约 ${llm.timeout_seconds ?? '?'}s/次），调用点 ${sites}；LLM 模式下模型只做定级与叙述，实测差分仍是唯一证据来源。`
    : '决策模式：未检测到 HARNESS_LLM_*，auto 会回退为确定性模式，LLM 模式将直接被拒绝（400）。';
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
    target.textContent = `${item.scenario} · ${item.target} · ${item.mode || 'deterministic'}`;

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

  // Model participation notice — a degraded model call must never be silent.
  if (modeNoticeNode) {
    const interpretation = (state.facts && state.facts.llm_findings_interpretation) || null;
    if (state.mode === 'llm' && interpretation && interpretation.available === false) {
      modeNoticeNode.style.display = 'block';
      modeNoticeNode.textContent = `模型判读不可用，已回退确定性定级：${interpretation.error || '未知原因'}`;
    } else {
      modeNoticeNode.style.display = 'none';
      modeNoticeNode.textContent = '';
    }
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

function renderExploitGymCheck(payload, taskId) {
  activeRunId = null;
  if (cockpitTarget) cockpitTarget.textContent = taskId;
  if (cockpitRunId) cockpitRunId.textContent = 'read-only';
  if (statusNode) {
    statusNode.textContent = '只读检查完成';
    statusNode.className = 'badge-status info';
  }
  if (stepsNode) {
    stepsNode.replaceChildren();
    const card = document.createElement('div');
    card.className = 'step-card success';
    card.innerHTML = '<div class="step-header"><span class="step-agent-name">1. ExploitGym 清单检查</span><span class="step-state-tag">完成</span></div><div class="step-summary">读取任务 ID、checkout 文件和官方 scorer 状态；未启动 benchmark。</div>';
    stepsNode.appendChild(card);
  }
  if (errorsNode) {
    errorsNode.style.display = 'none';
    errorsNode.textContent = '';
  }
  if (modeNoticeNode) {
    modeNoticeNode.style.display = 'block';
    modeNoticeNode.textContent = '这是只读检查结果，不是 ExploitGym 官方 benchmark 执行结果。';
  }
  if (findingsCountBadge) findingsCountBadge.textContent = '0';
  if (findingsNode) {
    findingsNode.replaceChildren();
    const card = document.createElement('article');
    card.className = 'finding-card info';
    const title = document.createElement('div');
    title.className = 'finding-title';
    title.textContent = 'ExploitGym 只读检查结果';
    const meta = document.createElement('div');
    meta.className = 'finding-meta-row';
    meta.innerHTML = `<span class="meta-item"><span class="meta-label">任务:</span> <code class="meta-val">${escapeHtml(taskId)}</code></span><span class="meta-item"><span class="meta-label">清单:</span> <span class="meta-val">${escapeHtml(payload.status || 'unknown')}</span></span><span class="meta-item"><span class="meta-label">官方评分:</span> <span class="meta-val">${escapeHtml(payload.benchmark_status || 'unknown')}</span></span>`;
    const body = document.createElement('div');
    body.className = 'finding-desc';
    body.textContent = payload.next_action || payload.readiness_meaning || '已完成只读检查。';
    card.append(title, meta, body);
    findingsNode.appendChild(card);
  }
  if (reportNode) reportNode.replaceChildren();
  if (openReportLink) openReportLink.style.display = 'none';
  if (reportRenderedContent) reportRenderedContent.innerHTML = '<div class="empty-state">ExploitGym 只读检查不生成普通审计报告。</div>';
  if (rawNode) rawNode.textContent = JSON.stringify(payload, null, 2);
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
    if (scenarioInput.value === 'exploitgym') {
      const taskId = targetInput.value.trim();
      if (!taskId) throw new Error('请填写 ExploitGym Task ID');
      const response = await fetch('/api/exploitgym?task_id=' + encodeURIComponent(taskId));
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || ('HTTP ' + response.status));
      renderExploitGymCheck(payload, taskId);
      return;
    }
    const response = await fetch('/api/runs', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        target: targetInput.value,
        scenario: scenarioInput.value,
        mode: modeInput.value
      })
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

const egBtnV8 = document.getElementById('eg-btn-v8');
if (egBtnV8) {
  egBtnV8.addEventListener('click', () => {
    const egInput = document.getElementById('eg-input');
    if (egInput) egInput.value = 'v8:sbxbrk/398773898';
    checkExploitGym().catch(err => { egOut.textContent = '错误：' + err.message; });
  });
}
const egBtnArvo = document.getElementById('eg-btn-arvo');
if (egBtnArvo) {
  egBtnArvo.addEventListener('click', () => {
    const egInput = document.getElementById('eg-input');
    if (egInput) egInput.value = 'user:cybergym/arvo_18224';
    checkExploitGym().catch(err => { egOut.textContent = '错误：' + err.message; });
  });
}

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

/* ==========================================================================
   Health Diagnostics, Service Management & Course Requirements Handlers
   ========================================================================== */
let lastReqTestData = null;

function showModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'flex';
}

function hideModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}

['health-modal-close', 'start-modal-close', 'start-cancel-btn', 'req-modal-close', 'req-modal-confirm-btn'].forEach(id => {
  const btn = document.getElementById(id);
  if (btn) {
    btn.addEventListener('click', () => {
      hideModal('modal-health');
      hideModal('modal-start');
      hideModal('modal-req-test');
    });
  }
});

['modal-health', 'modal-start', 'modal-req-test'].forEach(id => {
  const modal = document.getElementById(id);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) hideModal(id);
    });
  }
});

const copyReqBtn = document.getElementById('req-modal-copy-btn');
if (copyReqBtn) {
  copyReqBtn.addEventListener('click', async () => {
    if (lastReqTestData) {
      await navigator.clipboard.writeText(JSON.stringify(lastReqTestData, null, 2));
      copyReqBtn.textContent = '已复制！';
      setTimeout(() => { copyReqBtn.textContent = '复制测试证据 JSON'; }, 1800);
    }
  });
}

async function fetchAndRenderHealth() {
  const summaryText = document.getElementById('health-summary-text');
  const verdictBadge = document.getElementById('health-verdict-badge');
  const verdictText = document.getElementById('health-verdict-text');
  const servicesList = document.getElementById('health-services-list');
  const tsText = document.getElementById('health-timestamp');
  const hostText = document.getElementById('health-hostname');
  const dockerVer = document.getElementById('health-docker-ver');
  const dockerChips = document.getElementById('health-docker-containers');
  const distributedList = document.getElementById('health-distributed-list');

  if (summaryText) summaryText.textContent = '正在检测全系统服务与靶场端口...';

  try {
    const res = await fetch('/api/services/health');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    if (tsText) tsText.textContent = `检测时间：${data.timestamp}`;
    if (hostText) hostText.textContent = `${data.local_node.host} (${data.local_node.role})`;
    if (summaryText) summaryText.textContent = data.summary;

    if (verdictBadge && verdictText) {
      verdictBadge.className = `health-badge-large ${data.verdict.toLowerCase()}`;
      verdictText.textContent = data.verdict;
    }

    if (servicesList) {
      servicesList.innerHTML = '';
      (data.local_node.services || []).forEach(svc => {
        const card = document.createElement('div');
        card.className = 'health-item-card';
        card.innerHTML = `
          <div class="item-header">
            <span class="item-name">${svc.name}</span>
            <span class="item-status ${svc.status === 'ready' ? 'ready' : 'offline'}">
              ● ${svc.status === 'ready' ? '就绪' : '离线'}
            </span>
          </div>
          <div class="item-meta">${svc.endpoint}</div>
          <div class="item-meta">${svc.latency_ms ? svc.latency_ms + 'ms' : '-'}</div>
        `;
        servicesList.appendChild(card);
      });
    }

    if (dockerVer) {
      dockerVer.textContent = data.local_node.docker.message || '未运行';
    }
    if (dockerChips) {
      dockerChips.innerHTML = '';
      const containers = data.local_node.docker.containers || [];
      if (containers.length === 0) {
        dockerChips.innerHTML = '<span class="container-chip">无运行中的 harness 专属容器</span>';
      } else {
        containers.forEach(c => {
          const chip = document.createElement('span');
          chip.className = 'container-chip';
          chip.textContent = `${c.name}: ${c.status}`;
          dockerChips.appendChild(chip);
        });
      }
    }

    if (distributedList) {
      distributedList.innerHTML = '';
      (data.distributed_nodes || []).forEach(node => {
        const card = document.createElement('div');
        card.className = 'distributed-node-card';
        card.innerHTML = `
          <div class="node-title">
            <span>${node.course_requirement}</span>
            <span class="req-status-pill pill-blue">${node.assigned_role}</span>
          </div>
          <div class="node-sub">${node.detail}</div>
        `;
        distributedList.appendChild(card);
      });
    }
  } catch (err) {
    if (summaryText) summaryText.textContent = '健康检测失败：' + err.message;
  }
}

const btnQuickHealth = document.getElementById('btn-quick-health');
if (btnQuickHealth) {
  btnQuickHealth.addEventListener('click', () => {
    showModal('modal-health');
    fetchAndRenderHealth();
  });
}

const btnHealthRecheck = document.getElementById('health-recheck-btn');
if (btnHealthRecheck) {
  btnHealthRecheck.addEventListener('click', () => {
    fetchAndRenderHealth();
  });
}

const btnHealthQuickStart = document.getElementById('health-quick-start-btn');
if (btnHealthQuickStart) {
  btnHealthQuickStart.addEventListener('click', () => {
    hideModal('modal-health');
    showModal('modal-start');
  });
}

const btnQuickStart = document.getElementById('btn-quick-start');
if (btnQuickStart) {
  btnQuickStart.addEventListener('click', () => {
    showModal('modal-start');
  });
}

const btnStartExecute = document.getElementById('start-execute-btn');
if (btnStartExecute) {
  btnStartExecute.addEventListener('click', async () => {
    const roleSelect = document.getElementById('start-role-select');
    const logOutput = document.getElementById('start-log-output');
    const role = roleSelect ? roleSelect.value : 'all';

    btnStartExecute.disabled = true;
    btnStartExecute.textContent = '正在启动中...';
    if (logOutput) logOutput.textContent = `[${new Date().toLocaleTimeString()}] 正在下发启动指令 (role=${role})...\n`;

    try {
      const res = await fetch('/api/services/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      });
      const data = await res.json();
      let log = `[${new Date().toLocaleTimeString()}] 启动执行完毕。\n`;
      if (data.started && data.started.length > 0) {
        log += `✓ 已启动服务:\n  - ${data.started.join('\n  - ')}\n`;
      }
      if (data.already_running && data.already_running.length > 0) {
        log += `ℹ 已经在运行中:\n  - ${data.already_running.join('\n  - ')}\n`;
      }
      if (data.docker_note) {
        log += `🐳 Docker 诊断: ${data.docker_note}\n`;
      }
      if (data.errors && data.errors.length > 0) {
        log += `⚠ 错误或警告:\n  - ${data.errors.join('\n  - ')}\n`;
      }
      if (logOutput) logOutput.textContent = log;
    } catch (err) {
      if (logOutput) logOutput.textContent += `[错误] 启动请求失败: ${err.message}\n`;
    } finally {
      btnStartExecute.disabled = false;
      btnStartExecute.textContent = '立即执行启动';
    }
  });
}

const reqBtnGoad = document.getElementById('req-btn-goad');
if (reqBtnGoad) {
  reqBtnGoad.addEventListener('click', async () => {
    const title = document.getElementById('req-modal-title');
    const sub = document.getElementById('req-modal-sub');
    const body = document.getElementById('req-modal-body');

    if (title) title.textContent = '课程设计要求一：Windows 域环境 (GOAD) 渗透测试';
    if (sub) sub.textContent = '多节点域环境架构、攻击链验证与组员分布式协作状态';
    if (body) body.innerHTML = '<div class="loading-state">正在拉取 Windows 域渗透验证与拓扑数据...</div>';
    showModal('modal-req-test');

    try {
      const res = await fetch('/api/tests/goad', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      lastReqTestData = data;

      let topRows = (data.domain_topology || []).map(node => `
        <tr>
          <td><strong>${node.role}</strong></td>
          <td><code>${node.hostname}</code></td>
          <td>${node.ip}</td>
          <td>${node.os}</td>
          <td>${node.services}</td>
        </tr>
      `).join('');

      let attackItems = (data.attack_path || []).map(p => `<li>${p}</li>`).join('');

      if (body) {
        body.innerHTML = `
          <div class="req-test-section">
            <h4>1. Windows 域靶场三节点拓扑 (预设漏洞与域控架构)</h4>
            <table class="topology-table">
              <thead>
                <tr><th>节点角色</th><th>主机名</th><th>IP 地址</th><th>操作系统</th><th>运行服务</th></tr>
              </thead>
              <tbody>${topRows}</tbody>
            </table>
          </div>
          <div class="req-test-section">
            <h4>2. 预设攻击路径与域管理员提权验证链</h4>
            <ol class="attack-path-list">${attackItems}</ol>
          </div>
          <div class="req-test-section">
            <h4>3. 课程团队分工与执行状态</h4>
            <p style="margin:0 0 6px 0; font-size:11px; color:#93c5fd;"><strong>状态判定：</strong>${data.verdict}</p>
            <p style="margin:0; font-size:11px; color:var(--ink-secondary); line-height:1.5;">${data.host_distribution_note}</p>
            <p style="margin:4px 0 0 0; font-size:11px; color:#34d399;"><strong>安全合规：</strong>${data.safety_baseline}</p>
          </div>
        `;
      }
    } catch (err) {
      if (body) body.innerHTML = `<div class="error-banner">加载失败：${err.message}</div>`;
    }
  });
}

const reqBtnEg = document.getElementById('req-btn-exploitgym');
if (reqBtnEg) {
  reqBtnEg.addEventListener('click', async () => {
    const title = document.getElementById('req-modal-title');
    const sub = document.getElementById('req-modal-sub');
    const body = document.getElementById('req-modal-body');

    if (title) title.textContent = '课程设计要求二：ExploitGym 两项典型靶场测试';
    if (sub) sub.textContent = '官方 Scorer 真实评测数据、沙箱隔离与代码利用执行轨迹';
    if (body) body.innerHTML = '<div class="loading-state">正在核验 ExploitGym 任务清单与评测结果...</div>';
    showModal('modal-req-test');

    try {
      const res = await fetch('/api/tests/exploitgym', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      lastReqTestData = data;

      const t1 = data.task_1_specified;
      const t2 = data.task_2_custom;

      if (body) {
        body.innerHTML = `
          <div class="req-test-section">
            <h4>任务一（指定任务）：${t1.task_id}</h4>
            <p style="margin:0 0 4px 0; font-size:11px; color:var(--ink);"><strong>漏洞类型：</strong>${t1.type}</p>
            <p style="margin:0 0 4px 0; font-size:11px; color:var(--ink-secondary);"><strong>成功目标：</strong>${t1.course_goal}</p>
            <p style="margin:0 0 4px 0; font-size:11px; color:#fbbf24;"><strong>官方 Scorer 判定：</strong><code>${t1.scorer_result}</code></p>
            <p style="margin:0; font-size:11px; color:var(--ink-secondary);"><strong>真实轨迹统计：</strong>${t1.turns} 轮对话，${t1.tool_calls} 次工具调用，Agent 退出码 ${t1.agent_exit_code}</p>
          </div>

          <div class="req-test-section">
            <h4>任务二（自选任务）：${t2.task_id}</h4>
            <p style="margin:0 0 4px 0; font-size:11px; color:var(--ink);"><strong>漏洞类型：</strong>${t2.type}</p>
            <p style="margin:0 0 4px 0; font-size:11px; color:var(--ink-secondary);"><strong>成功目标：</strong>${t2.course_goal}</p>
            <p style="margin:0 0 4px 0; font-size:11px; color:#fbbf24;"><strong>官方 Scorer 判定：</strong><code>${t2.scorer_result}</code></p>
            <p style="margin:0; font-size:11px; color:var(--ink-secondary);"><strong>真实轨迹统计：</strong>${t2.turns} 次工具调用，${t2.model_requests} 次模型交互，Agent 退出码 ${t2.agent_exit_code}</p>
          </div>

          <div class="req-test-section">
            <h4>学术诚信与官方验证机制</h4>
            <p style="margin:0; font-size:11px; color:#34d399; line-height:1.5;">${data.academic_honesty}</p>
          </div>
        `;
      }
    } catch (err) {
      if (body) body.innerHTML = `<div class="error-banner">加载失败：${err.message}</div>`;
    }
  });
}

const reqBtnComplexWeb = document.getElementById('req-btn-complex-web');
if (reqBtnComplexWeb) {
  reqBtnComplexWeb.addEventListener('click', () => {
    const scenarioSelect = document.getElementById('scenario-input');
    const targetInput = document.getElementById('target-input');
    const runBtn = document.getElementById('run-button');

    if (scenarioSelect) scenarioSelect.value = 'complex-web';
    if (targetInput) targetInput.value = 'http://127.0.0.1:18089';

    document.querySelectorAll('.chip-btn').forEach(c => c.classList.remove('active'));
    const chip = document.querySelector('.chip-btn[data-scenario="complex-web"]');
    if (chip) chip.classList.add('active');

    if (runBtn) runBtn.click();

    const cockpit = document.querySelector('.run-cockpit');
    if (cockpit) cockpit.scrollIntoView({ behavior: 'smooth' });
  });
}
