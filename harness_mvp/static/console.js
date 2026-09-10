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
let pollTimer = null;
let activeRunId = null;
const labels = {recon:'侦察', vuln:'漏洞分析', exploit:'验证', report:'报告'};
const statuses = {queued:'排队', pending:'等待', running:'执行中', success:'完成', skipped:'跳过', failed:'失败', completed:'完成'};

scenarioInput.addEventListener('change', () => {
  targetInput.value = scenarioInput.value === 'local-web' ? 'http://127.0.0.1:18088' : 'demo.local';
  runButton.textContent = scenarioInput.value === 'local-web' ? '运行本机靶场' : '运行 Demo';
});

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

function renderCapabilities(catalog) {
  const cards = document.getElementById('capability-cards');
  cards.replaceChildren();
  (catalog.capabilities || []).forEach(item => {
    const card = document.createElement('article');
    card.className = 'card';
    const title = document.createElement('strong');
    title.textContent = item.title;
    const body = document.createElement('div');
    body.className = 'muted';
    body.textContent = item.summary;
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = item.status;
    card.append(title, body, tag);
    cards.appendChild(card);
  });
  const agents = document.getElementById('agent-cards');
  agents.replaceChildren();
  (catalog.agents || []).forEach(item => {
    const card = document.createElement('article');
    card.className = 'card';
    const title = document.createElement('strong');
    title.textContent = item.label;
    const body = document.createElement('div');
    body.className = 'muted';
    body.textContent = item.summary;
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = item.name;
    card.append(title, body, tag);
    agents.appendChild(card);
  });
  const safety = document.getElementById('safety-list');
  safety.replaceChildren();
  (catalog.safety || []).forEach(text => {
    const li = document.createElement('li');
    li.textContent = text;
    safety.appendChild(li);
  });
}

function renderLabs(items) {
  labsNode.replaceChildren();
  if (!items.length) {
    labsNode.innerHTML = '<span class="muted">无结果</span>';
    return;
  }
  items.forEach(item => {
    const node = document.createElement('article');
    node.className = 'lab ' + (item.status || '');
    const title = document.createElement('strong');
    title.textContent = item.lab_id;
    node.append(title, document.createTextNode(' '), badge(item.status));
    const req = document.createElement('div');
    req.className = 'muted';
    req.textContent = item.requirement;
    const evidence = document.createElement('div');
    evidence.textContent = item.evidence || '';
    const next = document.createElement('div');
    next.className = 'muted';
    next.textContent = item.next_action ? ('下一步：' + item.next_action) : '';
    node.append(req, evidence, next);
    labsNode.appendChild(node);
  });
}

function renderRunList(items) {
  runListNode.replaceChildren();
  if (!items.length) {
    runListNode.innerHTML = '<span class="muted">还没有运行</span>';
    return;
  }
  items.slice().reverse().forEach(item => {
    const node = document.createElement('article');
    node.className = 'run-item' + (item.run_id === activeRunId ? ' active' : '');
    const title = document.createElement('strong');
    title.textContent = item.run_id;
    node.append(title, document.createTextNode(` · ${item.scenario} · ${item.target} `), badge(item.status));
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
  statusNode.textContent = '状态：' + (statuses[state.status] || state.status || '未知') + (state.run_id ? ` · ${state.run_id}` : '');
  stepsNode.replaceChildren();
  ((state.progress && state.progress.steps) || []).forEach(step => {
    const node = document.createElement('span');
    const status = step.status || 'queued';
    node.className = 'step ' + status;
    node.textContent = (labels[step.agent] || step.agent || step.name) + ' · ' + (statuses[status] || status);
    stepsNode.appendChild(node);
  });
  const errors = state.errors || [];
  errorsNode.textContent = errors.length ? ('错误：' + errors.join('；')) : '';
  findingsNode.replaceChildren();
  const findings = state.findings || [];
  if (!findings.length) {
    findingsNode.innerHTML = '<span class="muted">暂无发现</span>';
  } else {
    findings.forEach(f => {
      const card = document.createElement('article');
      card.className = 'finding ' + (f.severity || '');
      const title = document.createElement('strong');
      title.textContent = `${f.finding_id || ''} ${f.title || ''}`;
      const meta = document.createElement('div');
      meta.textContent = `严重性：${f.severity || 'n/a'}；来源：${f.source || 'n/a'}；端点：${f.endpoint || 'n/a'}`;
      const evidence = document.createElement('div');
      evidence.className = 'muted';
      evidence.textContent = f.evidence || '';
      card.append(title, meta, evidence);
      findingsNode.appendChild(card);
    });
  }
  reportNode.replaceChildren();
  if (state.report_url) {
    const link = document.createElement('a');
    link.href = state.report_url;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = '查看 Markdown 报告';
    reportNode.appendChild(link);
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
  labsNode.innerHTML = '<span class="muted">检查中...</span>';
  const response = await fetch('/api/labs');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'labs failed');
  renderLabs(payload.labs || []);
}

async function refreshRuns() {
  const response = await fetch('/api/runs');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'runs failed');
  renderRunList(payload.runs || []);
}

async function searchKnowledge() {
  const q = document.getElementById('kb-input').value.trim();
  if (!q) {
    kbResults.innerHTML = '<span class="muted">请输入检索词</span>';
    return;
  }
  kbResults.innerHTML = '<span class="muted">检索中...</span>';
  const response = await fetch('/api/knowledge?q=' + encodeURIComponent(q) + '&limit=5');
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'knowledge failed');
  kbResults.replaceChildren();
  const items = payload.results || [];
  if (!items.length) {
    kbResults.innerHTML = '<span class="muted">没有足够相关的条目</span>';
    return;
  }
  items.forEach(item => {
    const node = document.createElement('article');
    node.className = 'kb';
    const title = document.createElement('strong');
    title.textContent = `${item.entry_id} · ${item.title}`;
    const meta = document.createElement('div');
    meta.className = 'muted';
    meta.textContent = `分数 ${Number(item.score || 0).toFixed(3)} · ${item.cwe || ''}`;
    const text = document.createElement('div');
    text.textContent = item.text || '';
    const fix = document.createElement('div');
    fix.className = 'muted';
    fix.textContent = '修复：' + (item.remediation || '');
    node.append(title, meta, text, fix);
    kbResults.appendChild(node);
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
  statusNode.textContent = '状态：提交中...';
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
    statusNode.textContent = '状态：提交失败';
    errorsNode.textContent = '错误：' + error.message;
  } finally {
    runButton.disabled = false;
  }
});

document.getElementById('labs-button').addEventListener('click', () => refreshLabs().catch(err => {
  labsNode.textContent = '错误：' + err.message;
}));
document.getElementById('catalog-refresh').addEventListener('click', () => refreshCatalog().catch(err => {
  errorsNode.textContent = '错误：' + err.message;
}));
document.getElementById('kb-button').addEventListener('click', () => searchKnowledge().catch(err => {
  kbResults.textContent = '错误：' + err.message;
}));
document.getElementById('eg-button').addEventListener('click', () => checkExploitGym().catch(err => {
  egOut.textContent = '错误：' + err.message;
}));

Promise.all([refreshCatalog(), refreshRuns()]).catch(err => {
  errorsNode.textContent = '错误：' + err.message;
});
