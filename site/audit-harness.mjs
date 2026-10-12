#!/usr/bin/env node
// Shared harness for the site audits.
//
//   node site/audit-layout.mjs     layout, overflow, SVG text, ids
//   node site/audit-contrast.mjs   WCAG AA text contrast + band visibility
//
// Each audit script owns a headless Chrome and a static server for the site, so
// they run identically from a shell and from CI with no setup.

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DOCS = path.join(SITE, 'docs');

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.xml': 'application/xml', '.txt': 'text/plain' };

/** Serve docs/ on an ephemeral port. */
export async function serve() {
  const files = new Set(await readdir(DOCS));
  const server = createServer(async (req, res) => {
    const url = decodeURIComponent((req.url || '/').split('?')[0]);
    const rel = url === '/' ? '/index.html' : url;
    const file = path.join(DOCS, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
    if (!files.has(path.basename(file)) || !existsSync(file)) {
      res.writeHead(404).end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(await readFile(file));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

/** Locate a Chrome/Chromium binary. GitHub runners ship google-chrome. */
function chromeBinary() {
  const candidates = [process.env.CHROME_BIN, 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'];
  for (const bin of candidates) {
    if (!bin) continue;
    if (bin.includes('/') && existsSync(bin)) return bin;
    const found = spawnSync('which', [bin], { encoding: 'utf8' });
    if (found.status === 0 && found.stdout.trim()) return found.stdout.trim();
  }
  throw new Error('no Chrome or Chromium binary found; set CHROME_BIN');
}

/** Launch headless Chrome with a debugging port, and wait until it answers. */
export async function chrome() {
  const profile = path.join('/tmp', `fasp-audit-${process.pid}`);
  const child = spawn(
    chromeBinary(),
    [
      '--headless=new', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
      '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  );

  // Chrome writes the chosen port to <profile>/DevToolsActivePort. Reading the
  // file is reliable; parsing stderr is not, because the format of the
  // "DevTools listening" line varies by version and host binding.
  const portFile = path.join(profile, 'DevToolsActivePort');
  const deadline = Date.now() + 30000;
  let port = null;
  while (Date.now() < deadline && port === null) {
    try {
      const first = (await readFile(portFile, 'utf8')).split('\n')[0].trim();
      if (first) port = Number(first);
    } catch {
      /* not written yet */
    }
    if (port === null) await sleep(150);
  }
  if (!port) {
    child.kill();
    throw new Error('chrome did not report a debugging port within 30s');
  }

  let version = {};
  try {
    version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  } catch {
    /* version string is cosmetic */
  }
  return { port, browser: version.Browser || 'Chrome', close: () => child.kill() };
}

/** Minimal CDP client over the browser WebSocket. */
export async function cdp(port) {
  const res = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' });
  const tab = await res.json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  const send = (method, params = {}) =>
    new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
  };
  await new Promise((r) => (ws.onopen = r));
  await send('Page.enable');
  await send('Runtime.enable');

  /** Navigate and wait until the document is actually parsed and complete. */
  const goto = async (url) => {
    for (let attempt = 0; attempt < 30; attempt++) {
      await send('Page.navigate', { url });
      for (let i = 0; i < 15; i++) {
        await sleep(70);
        const r = await send('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
        if (r.result?.value === 'complete') { await sleep(250); return true; }
      }
    }
    return false;
  };

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true });
    if (r.exceptionDetails) {
      throw new Error('probe threw: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    }
    return r.result?.value;
  };

  return { send, goto, evaluate, close: () => ws.close() };
}


/** Every page plus the viewports and themes to check them at. */
export const VIEWPORTS = [360, 390, 480, 768, 1024, 1280, 1440, 1920];
export const THEMES = ['light', 'dark'];

export async function pages() {
  return (await readdir(DOCS)).filter((f) => f.endsWith('.html')).sort();
}