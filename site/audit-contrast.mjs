#!/usr/bin/env node
// Contrast audit: WCAG AA text contrast, plus the requirement that an
// alternating section band stays visibly distinct from the page background.
//   node site/audit-contrast.mjs
import { serve, chrome, cdp, pages, sleep, THEMES } from './audit-harness.mjs';

// Chrome resolves color-mix() to color(srgb r g b / a) with 0..1 channels.
// Reading those as 0..255, or ignoring alpha, invents failures that do not
// exist -- so parse properly and composite over the real backdrop.
const PROBE = String.raw`(() => {
  const parse = (v) => { v = v.trim();
    if (v.charAt(0) === '#') { const h = v.length === 4 ? v.slice(1).split('').map(c=>c+c).join('') : v.slice(1);
      return [[parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16), 1]]; }
    const m = v.match(/-?[\d.]+(?:e-?\d+)?/gi); if (!m) return [[0,0,0,1]];
    let n = m.map(Number);
    // Colour channels scale from 0..1; alpha is already 0..1 and must not.
    if (v.slice(0, 6).toLowerCase() === 'color(') n = [n[0]*255, n[1]*255, n[2]*255, n[3]];
    while (n.length < 4) n.push(n.length === 3 ? 1 : 0);
    return [[n[0], n[1], n[2], n[3]]];
  };
  const px = (v) => parse(v)[0].slice(0, 3);
  const over = (fg, a, bg) => fg.map((c, i) => c * a + bg[i] * (1 - a));
  const lum = (c) => { const f = (x) => { x/=255; return x <= .03928 ? x/12.92 : Math.pow((x+.055)/1.055, 2.4); };
    return .2126*f(c[0]) + .7152*f(c[1]) + .0722*f(c[2]); };
  const ratio = (a,b) => { const l = [lum(a), lum(b)].sort((m,n)=>n-m); return (l[0]+.05)/(l[1]+.05); };
  const rgb = (c) => 'rgb(' + c.map((x) => Math.round(x)).join(',') + ')';
  const bgOf = (el) => { const stack = []; let n = el;
    while (n && n !== document.documentElement) {
      const col = parse(getComputedStyle(n).backgroundColor)[0];
      if (col[3] > 0) { stack.push([col.slice(0,3), col[3]]); if (col[3] >= 1) break; }
      n = n.parentElement;
    }
    let out = px(getComputedStyle(document.body).backgroundColor);
    for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i][0], stack[i][1], out);
    return out; };

  const out = { bands: [], contrast: [] };

  for (const b of document.querySelectorAll('.band-dark')) {
    const page = px(getComputedStyle(document.body).backgroundColor);
    const band = px(getComputedStyle(b).backgroundColor);
    out.bands.push({ bandBg: rgb(band), pageBg: rgb(page), ratio: +ratio(band, page).toFixed(3) });
  }

  const sel = 'h1,h2,h3,p,li,td,th,dt,dd,code,strong,.card-kicker,.sec-num,.toc a,.layer-verb b,.layer-verb,.pager-title,.source-note a,.source-note,.callout p,.callout-title,.stat dd,.stat small,.eyebrow,.hero-meta,.crumb,.crumb a,.footer-label,.footer-note p,.footer-cols a,.code-head,.code-block .copy-button,.visual-label,.card-foot,.gate span,.gate-num,.toc-num,.path-for,.form-number,.layer-id .l,.path-links a';
  const seen = {};
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    if (!el.textContent.trim()) continue;
    const fg = px(cs.color); const bg = bgOf(el);
    const size = parseFloat(cs.fontSize); const weight = parseInt(cs.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3 : 4.5;
    const got = +ratio(fg, bg).toFixed(2);
    const key = el.tagName + '.' + String(el.className).split(' ')[0] + '|' + got;
    if (seen[key]) continue; seen[key] = 1;
    if (got < need) {
      out.contrast.push({ el: el.tagName.toLowerCase() + '.' + String(el.className).split(' ')[0],
        size, ratio: got, need, fg: cs.color, bg: rgb(bg), sample: el.textContent.trim().slice(0, 34) });
    }
  }
  return out;
})()`;

const MIN_BAND_RATIO = 1.08; // below this the band is invisible to the eye

const site = await serve();
const ch = await chrome();
const client = await cdp(ch.port);
const PAGES = await pages();
const problems = [];

await client.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });

for (const page of PAGES) {
  for (const theme of THEMES) {
    await client.goto(`${site.origin}/${page}`);
    await client.evaluate(`document.documentElement.setAttribute('data-theme','${theme}')`);
    // Let the style recalc settle. light-dark() resolves against color-scheme,
    // and probing in the same tick can read the previous theme's values.
    await sleep(250);
    const v = (await client.evaluate(PROBE)) ?? { bands: [], contrast: [] };

    // Sanity check: the tokens must actually be in the requested theme,
    // otherwise every result below is measuring the wrong thing.
    const scheme = await client.evaluate('getComputedStyle(document.documentElement).colorScheme');
    if (scheme !== theme) problems.push(`[theme-not-applied] ${page} requested ${theme}, color-scheme is ${scheme}`);

    for (const b of v.bands) {
      if (b.ratio < MIN_BAND_RATIO) {
        problems.push(`[band-indistinct] ${page} [${theme}] band ${b.bandBg} vs page ${b.pageBg}, ratio ${b.ratio} < ${MIN_BAND_RATIO}`);
      }
    }
    for (const c of v.contrast) {
      problems.push(`[contrast] ${page} [${theme}] ${c.el} ${c.size}px  ${c.ratio} < ${c.need}  ${c.fg} on ${c.bg}  "${c.sample}"`);
    }
  }
}
client.close();
ch.close();
await site.close();

if (!problems.length) {
  process.stdout.write(`Contrast OK: WCAG AA met on ${PAGES.length} pages in both themes (${ch.browser}).\n`);
} else {
  process.stdout.write(`${problems.length} contrast problem(s):\n  ${problems.join('\n  ')}\n`);
  process.exit(1);
}