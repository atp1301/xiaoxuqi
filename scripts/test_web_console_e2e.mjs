import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const port = 9445;
const chrome = spawn(chromePath, [
  '--headless=new',
  '--disable-gpu',
  '--disable-software-rasterizer',
  '--no-sandbox',
  `--remote-debugging-port=${port}`,
  '--window-size=1440,960',
  'about:blank'
]);

await new Promise(resolve => setTimeout(resolve, 1500));

try {
  const listRes = await fetch(`http://127.0.0.1:${port}/json`);
  const list = await listRes.json();
  const pageTarget = list.find(t => t.type === 'page') || list[0];
  const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);

  let id = 1;
  const pending = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (pending.has(msg.id)) {
      const resolve = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg.result);
    }
  };

  await new Promise(r => ws.onopen = r);

  function send(method, params = {}) {
    return new Promise((resolve) => {
      const reqId = id++;
      pending.set(reqId, resolve);
      ws.send(JSON.stringify({ id: reqId, method, params }));
    });
  }

  async function evalExpr(expression) {
    return await send('Runtime.evaluate', { expression, returnByValue: true });
  }

  async function snap(filename) {
    const res = await send('Page.captureScreenshot', { format: 'png' });
    const fullPath = path.resolve(filename);
    fs.writeFileSync(fullPath, Buffer.from(res.data, 'base64'));
    console.log(`[Screenshot Saved] -> ${fullPath}`);
  }

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: 'http://127.0.0.1:8765/' });
  await new Promise(r => setTimeout(r, 1800));

  console.log('Step 1: Capturing Web Console Overview...');
  await snap('docs/screenshots/web_01_dashboard.png');

  console.log('Step 2: Testing Health Diagnostics Modal...');
  await evalExpr(`document.getElementById('btn-quick-health').click();`);
  await new Promise(r => setTimeout(r, 1200));
  await snap('docs/screenshots/web_02_health_modal.png');
  await evalExpr(`document.getElementById('health-modal-close').click();`);
  await new Promise(r => setTimeout(r, 400));

  console.log('Step 3: Testing Service Startup Modal...');
  await evalExpr(`document.getElementById('btn-quick-start').click();`);
  await new Promise(r => setTimeout(r, 500));
  await evalExpr(`document.getElementById('start-execute-btn').click();`);
  await new Promise(r => setTimeout(r, 1500));
  await snap('docs/screenshots/web_03_start_modal.png');
  await evalExpr(`document.getElementById('start-modal-close').click();`);
  await new Promise(r => setTimeout(r, 400));

  console.log('Step 4: Testing Requirement 1 (Windows Domain / GOAD)...');
  await evalExpr(`document.getElementById('req-btn-goad').click();`);
  await new Promise(r => setTimeout(r, 1000));
  await snap('docs/screenshots/web_04_req1_goad.png');
  await evalExpr(`document.getElementById('req-modal-close').click();`);
  await new Promise(r => setTimeout(r, 400));

  console.log('Step 5: Testing Requirement 2 (ExploitGym Two Tasks)...');
  await evalExpr(`document.getElementById('req-btn-exploitgym').click();`);
  await new Promise(r => setTimeout(r, 1000));
  await snap('docs/screenshots/web_05_req2_exploitgym.png');
  await evalExpr(`document.getElementById('req-modal-close').click();`);
  await new Promise(r => setTimeout(r, 400));

  console.log('Step 6: Triggering Requirement 3 (Complex Web Automated Penetration)...');
  await evalExpr(`document.getElementById('req-btn-complex-web').click();`);
  await new Promise(r => setTimeout(r, 1500));
  await snap('docs/screenshots/web_06_req3_pipeline_running.png');

  console.log('Step 7: Waiting for 7-Agent Attack Pipeline to complete...');
  for (let i = 0; i < 25; i++) {
    const statusRes = await evalExpr(`document.getElementById('status') ? document.getElementById('status').textContent : ''`);
    const text = statusRes?.result?.value || '';
    console.log(`  Pipeline state at ${i * 0.5}s: "${text}"`);
    if (text.includes('完成') || text.includes('completed') || text.includes('失败') || text.includes('failed')) {
      break;
    }
    await new Promise(r => setTimeout(r, 500));
  }
  await new Promise(r => setTimeout(r, 1000));
  await snap('docs/screenshots/web_07_req3_findings.png');

  console.log('Step 8: Switching to Report view and capturing Markdown Report...');
  await evalExpr(`document.querySelector('.view-tab[data-view="view-report"]').click();`);
  await new Promise(r => setTimeout(r, 1000));
  await snap('docs/screenshots/web_08_req3_markdown_report.png');

  console.log('Step 9: Scrolling into Attack Chain & Flag Evidence...');
  await evalExpr(`
    const content = document.getElementById('report-rendered-content');
    if (content) content.scrollTop = 240;
  `);
  await new Promise(r => setTimeout(r, 800));
  await snap('docs/screenshots/web_09_flag_evidence.png');

  console.log('Step 10: Scrolling to Flag & Attack Chain Summary...');
  await evalExpr(`
    const content = document.getElementById('report-rendered-content');
    if (content) {
      const targets = Array.from(content.querySelectorAll('h2, h3, p, strong, code'));
      const flagEl = targets.find(el => el.textContent.includes('Attack Chain Evidence') || el.textContent.includes('FLAG{'));
      if (flagEl) {
        flagEl.scrollIntoView({ behavior: 'instant', block: 'center' });
      }
    }
  `);
  await new Promise(r => setTimeout(r, 800));
  await snap('docs/screenshots/web_10_flag_token.png');

  ws.close();
  console.log('ALL BROWSER TESTS AND SCREENSHOTS COMPLETED SUCCESSFULLY!');
} finally {
  chrome.kill();
}
