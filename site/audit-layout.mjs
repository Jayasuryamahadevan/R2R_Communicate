#!/usr/bin/env node
// Layout audit: overflow, SVG text escaping its shape, clipped words, ids.
//   node site/audit-layout.mjs
import { serve, chrome, cdp, pages, VIEWPORTS, THEMES } from './audit-harness.mjs';

const AUDIT = String.raw`(() => {
  const out = [];
  const vw = document.documentElement.clientWidth;

  if (document.documentElement.scrollWidth > vw + 1) {
    out.push({ kind: 'page-overflow-x', detail: 'scrollWidth ' + document.documentElement.scrollWidth + ' > ' + vw });
  }

  for (const el of document.querySelectorAll('body *')) {
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || s.position === 'fixed') continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (r.right > vw + 1.5 || r.left < -1.5) {
      if (el.closest('.figure-scroll') || el.closest('.table-wrap') || el.closest('pre')) continue;
      if (s.overflowX === 'auto' || s.overflowX === 'scroll') continue;
      const tag = el.tagName.toLowerCase() + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '');
      out.push({ kind: 'element-overflow-x', detail: tag + ' right=' + r.right.toFixed(0) + ' vw=' + vw });
    }
  }

  // SVG text must stay inside the rectangle it labels.
  for (const svg of document.querySelectorAll('svg.diag, svg.viz')) {
    const box0 = svg.getBoundingClientRect();
    const vb = svg.viewBox.baseVal;
    const scale = vb && vb.width ? box0.width / vb.width : 1;
    if (!scale) continue;
    for (const t of svg.querySelectorAll('text')) {
      const b = t.getBoundingClientRect();
      if (!b.width) continue;
      const rect = t.parentElement && t.parentElement.tagName === 'g' ? null : t.closest('rect');
      if (!rect) continue;
      const b0 = rect.getBoundingClientRect();
      if (b0.width === 0) continue;
      const pad = 1.5;
      if (b.left < b0.left - pad || b.right > b0.right + pad || b.top < b0.top - pad || b.bottom > b0.bottom + pad) {
        out.push({ kind: 'svg-text-overflow', detail: '"' + t.textContent.trim().slice(0, 28) + '"' });
      }
    }
  }

  // Text clipped by its own box.
  for (const el of document.querySelectorAll('h1,h2,h3,p,td,th,dd,dt,.card-kicker,.layer-verb b,.stat dd,.pager-title,.card h3,.path h3')) {
    if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0) {
      const s = getComputedStyle(el);
      if (s.textOverflow === 'ellipsis' || s.whiteSpace === 'nowrap' || s.overflow === 'auto') continue;
      out.push({ kind: 'text-overflow', detail: el.tagName.toLowerCase() + ' "' + el.textContent.trim().slice(0, 30) + '" ' + el.scrollWidth + '>' + el.clientWidth });
    }
  }

  // Text overlapping other text. Overflow and clipping checks cannot see this:
  // two elements drawn on top of each other are each perfectly "in bounds".
  // Inline elements are compared per line box (getClientRects), not by their
  // union box, or a wrapped <code> would appear to overlap whatever sits beside
  // its first and last lines.
  const textNodes = 'h1,h2,h3,h4,p,li,td,th,dd,dt,code,strong,em';
  const items = [];
  for (const el of document.querySelectorAll(textNodes)) {
    if (!el.textContent.trim()) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || +cs.opacity === 0) continue;
    for (const r of el.getClientRects()) {
      if (r.width > 2 && r.height > 2) items.push({ el, r });
    }
  }
  for (let i = 0; i < items.length; i++) {
    for (let j = i + 1; j < items.length; j++) {
      const a = items[i], b = items[j];
      if (a.el === b.el || a.el.contains(b.el) || b.el.contains(a.el)) continue;
      const ox = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left);
      const oy = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top);
      if (ox > 4 && oy > 4) {
        const name = (e) => e.tagName.toLowerCase() + '.' + String(e.className).split(' ')[0];
        out.push({ kind: 'text-overlap', detail: name(a.el) + ' "' + a.el.textContent.trim().slice(0, 18) + '" over ' + name(b.el) + ' "' + b.el.textContent.trim().slice(0, 18) + '"' });
      }
    }
  }

  // A component must not inherit page-level prose spacing. Catch it here rather
  // than by eye: a card heading sitting far below its kicker is this bug.
  for (const el of document.querySelectorAll('.card-kicker, .path-for, .form-number')) {
    const title = el.parentElement && el.parentElement.querySelector('h3');
    if (!title) continue;
    const gap = title.getBoundingClientRect().top - el.getBoundingClientRect().bottom;
    if (gap > 28) {
      out.push({ kind: 'component-spacing', detail: el.className + ' -> h3 gap ' + Math.round(gap) + 'px' });
    }
  }

  // Sibling card headings must sit at the same offset within their own card.
  // Comparing absolute tops would flag every multi-row grid, because cards in
  // the second row are legitimately further down the page.
  for (const grid of document.querySelectorAll('.card-grid, .form-grid, .paths')) {
    const offsets = [...grid.children]
      .filter((c) => c.querySelector('h3'))
      .map((c) => Math.round(c.querySelector('h3').getBoundingClientRect().top - c.getBoundingClientRect().top));
    const uniq = [...new Set(offsets)];
    if (uniq.length > 1) {
      out.push({ kind: 'card-heading-misaligned', detail: 'heading offsets ' + uniq.join(' vs ') });
    }
  }

  const seen = new Set(); const dupes = new Set();
  for (const el of document.querySelectorAll('[id]')) {
    if (seen.has(el.id)) dupes.add(el.id); else seen.add(el.id);
  }
  for (const d of dupes) out.push({ kind: 'duplicate-id', detail: d });

  return out;
})()`;

const site = await serve();
const ch = await chrome();
const client = await cdp(ch.port);
const PAGES = await pages();
const findings = [];

for (const theme of THEMES) {
  for (const width of VIEWPORTS) {
    await client.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 768 });
    for (const page of PAGES) {
      await client.goto(`${site.origin}/${page}`);
      await client.evaluate(`document.documentElement.setAttribute('data-theme','${theme}')`);
      for (const f of (await client.evaluate(AUDIT)) ?? []) findings.push({ page, width, theme, ...f });
    }
  }
}
client.close();
ch.close();
await site.close();

const key = (f) => `${f.page}|${f.width}|${f.kind}|${f.detail.replace(/\d+/g, '#')}`;
const seen = new Map();
for (const f of findings) {
  if (!seen.has(key(f))) seen.set(key(f), { ...f, count: 0, themes: new Set() });
  const e = seen.get(key(f));
  e.count++;
  e.themes.add(f.theme);
}

const scope = `${PAGES.length} pages x ${VIEWPORTS.length} widths x ${THEMES.length} themes`;
if (!seen.size) {
  process.stdout.write(`Layout OK: no defects across ${scope} (${ch.browser}).\n`);
} else {
  process.stdout.write(`${seen.size} distinct layout defects across ${scope}:\n\n`);
  for (const f of [...seen.values()].sort((a, b) => b.width - a.width || a.kind.localeCompare(b.kind))) {
    process.stdout.write(`  [${f.kind}] ${f.page} @${f.width}px (${[...f.themes].join('+')}, ${f.count}x)\n      ${f.detail}\n\n`);
  }
  process.exit(1);
}