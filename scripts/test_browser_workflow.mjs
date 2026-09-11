import { spawn } from 'node:child_process';
import fs from 'node:fs';

const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const port = 9444;
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

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: 'http://127.0.0.1:8765/' });
  await new Promise(r => setTimeout(r, 1500));

  async function snap(filename) {
    const res = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(filename, Buffer.from(res.data, 'base64'));
    console.log(`Saved ${filename}`);
  }

  // Step 1: Click the chip button for Complex-Web (18089)
  console.log('1. Selecting complex-web scenario...');
  await send('Runtime.evaluate', { expression: `
    const chip = document.querySelector('.chip-btn[data-scenario="complex-web"]');
    if (chip) chip.click();
  ` });
  await new Promise(r => setTimeout(r, 500));

  // Step 2: Click "启动评估" (Start Assessment)
  console.log('2. Clicking Start Assessment button in Web UI...');
  await send('Runtime.evaluate', { expression: `
    document.getElementById('run-button').click();
  ` });

  // Wait for run to finish (poll in page)
  console.log('3. Waiting for run to complete in UI...');
  await new Promise(r => setTimeout(r, 3000));
  await snap('browser_test_complex_web.png');

  // Step 3: Switch to Report view in Console
  console.log('4. Switching to Report tab...');
  await send('Runtime.evaluate', { expression: `
    document.querySelector('.view-tab[data-view="view-report"]').click();
  ` });
  await new Promise(r => setTimeout(r, 800));
  await snap('browser_test_report.png');

  // Step 4: Switch to Labs Diagnostic tab
  console.log('5. Navigating to Labs tab and checking labs...');
  await send('Runtime.evaluate', { expression: `
    document.querySelector('.nav-tab[data-tab="tab-labs"]').click();
  ` });
  await new Promise(r => setTimeout(r, 2500));

  // Click ExploitGym Task 1 (v8:sbxbrk/398773898)
  console.log('6. Checking ExploitGym Task 1 (v8)...');
  await send('Runtime.evaluate', { expression: `
    const btn = document.getElementById('eg-btn-v8');
    if (btn) btn.click();
  ` });
  await new Promise(r => setTimeout(r, 1000));
  await snap('browser_test_labs_v8.png');

  ws.close();
  console.log('Browser automated test finished successfully!');
} finally {
  chrome.kill();
}
