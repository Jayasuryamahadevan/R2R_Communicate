#!/usr/bin/env node
// Zero-dependency static site generator for the FASP reference site.
//
//   node site/build.mjs
//
// Reads   site/pages/*.html   (front matter + body, plain HTML, no escaping games)
// Writes  docs/*.html         (GitHub Pages serves this directory directly)
//
// Everything shared - head, header, sidebar, pager, footer, search dialog -
// lives in site/layout.mjs, so the navigation cannot drift between pages.

import { readFile, writeFile, readdir, mkdir, copyFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { renderPage } from './layout.mjs';
import { SITE, NAV } from './nav.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const pagesDir = path.join(here, 'pages');
const assetsDir = path.join(here, 'assets');
const staticDir = path.join(here, 'static');
const outDir = path.join(repoRoot, 'docs');

// ---------------------------------------------------------------- front matter

function parseFrontMatter(raw, file) {
  if (!raw.startsWith('---')) throw new Error(`${file}: missing front matter block`);
  const end = raw.indexOf('\n---', 3);
  if (end === -1) throw new Error(`${file}: unterminated front matter block`);

  const meta = {};
  let listKey = null;
  for (const rawLine of raw.slice(4, end).split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    // "  - [Label, Value]" continues the previous key as a list item.
    const item = line.match(/^-\s*\[(.+?),\s*(.+)\]$/);
    if (item && listKey) {
      (meta[listKey] ||= []).push([item[1].trim(), item[2].trim()]);
      continue;
    }

    const at = line.indexOf(':');
    if (at === -1) continue;
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    meta[key] = value;
    listKey = key;
  }
  return { meta, body: raw.slice(end + 4).replace(/^\n+/, '') };
}

// A page's own table of contents is derived from its markup, never duplicated.
//   <section id="gates" data-nav="Request gates" data-num="03">
function extractToc(body) {
  const toc = [];
  const re = /<section\b([^>]*)>/g;
  let m;
  while ((m = re.exec(body))) {
    const attrs = m[1];
    if (!/\bdata-nav=/.test(attrs)) continue;
    const id = (attrs.match(/\bid="([^"]+)"/) || [])[1];
    const label = (attrs.match(/\bdata-nav="([^"]+)"/) || [])[1];
    const num = (attrs.match(/\bdata-num="([^"]+)"/) || [])[1];
    if (!id || !label) throw new Error(`section needs both id and data-nav: ${m[0]}`);
    toc.push({ id, label, num });
  }
  return toc;
}

// Each section's eyebrow number is authored once (data-num) and injected here,
// so the sidebar, the body, and the search index can never disagree. The label
// belongs inside the section's .shell wrapper, not beside it.
function injectSectionNumbers(body) {
  return body.replace(
    /<section\b([^>]*?)\s*data-num="([^"]+)"([^>]*)>(\s*)<div class="shell">/g,
    (_all, before, num, after, gap) =>
      `<section${before} data-num="${num}"${after}>${gap}<div class="shell"><p class="sec-num">${num}</p>`,
  );
}

// Cheap structural guard. Browsers silently ignore a stray close tag, so an
// unbalanced <div> or <figure> would quietly swallow the rest of the page
// instead of failing. Catch it here instead.
function checkBalance(body, file) {
  for (const tag of ['div', 'figure', 'section', 'table', 'svg']) {
    const open = (body.match(new RegExp(`<${tag}[\\s>]`, 'gi')) || []).length;
    const close = (body.match(new RegExp(`</${tag}>`, 'gi')) || []).length;
    if (open !== close) {
      throw new Error(`${file}: unbalanced <${tag}> — ${open} open, ${close} close`);
    }
  }
  // Every numbered section must actually receive its label, or the page silently
  // ships without the section numbering the sidebar promises.
  const numbered = (body.match(/data-num="/g) || []).length;
  const injected = (injectSectionNumbers(body).match(/class="sec-num"/g) || []).length;
  if (numbered !== injected) {
    throw new Error(
      `${file}: ${numbered} sections declare data-num but ${injected} received a label — ` +
        'each must be followed by <div class="shell">',
    );
  }
}

// Text used by the client-side search index.
function plainText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// ---------------------------------------------------------------------- build

async function main() {
  const files = (await readdir(pagesDir)).filter((f) => f.endsWith('.html')).sort();
  if (!files.length) throw new Error('no pages found');

  const pages = [];
  for (const file of files) {
    const raw = await readFile(path.join(pagesDir, file), 'utf8');
    const { meta, body } = parseFrontMatter(raw, file);
    checkBalance(body, file);
    if (!meta.slug) throw new Error(`${file}: front matter needs a slug`);
    if (!NAV.some((n) => n.slug === meta.slug)) throw new Error(`${file}: slug "${meta.slug}" is not in nav.mjs`);
    pages.push({ ...meta, file, body: injectSectionNumbers(body), toc: extractToc(body) });
  }

  const order = new Map(NAV.map((n, i) => [n.slug, i]));
  pages.sort((a, b) => (order.get(a.slug) ?? 99) - (order.get(b.slug) ?? 99));

  // docs/ is entirely generated, so it is rebuilt from empty. That is what
  // stops a renamed or deleted page from lingering in the published artifact.
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  const searchIndex = [];
  for (const page of pages) {
    const html = renderPage(page, page.body, page.toc);
    const outName = `${page.slug === 'index' ? 'index' : page.slug}.html`;
    await writeFile(path.join(outDir, outName), html, 'utf8');

    // One search entry per section. Sections are siblings in the markup, so the
    // slice for entry N runs to the start of entry N+1.
    const offsets = page.toc.map((t) => page.body.indexOf(`id="${t.id}"`));
    page.toc.forEach((t, i) => {
      const start = offsets[i];
      const end = i + 1 < offsets.length ? offsets[i + 1] : page.body.length;
      searchIndex.push({
        t: `${page.nav || page.title} › ${t.label}`,
        u: `${outName}#${t.id}`,
        d: plainText(page.body.slice(start, Math.max(start, end))).slice(0, 240),
      });
    });
    process.stdout.write(`  ${outName.padEnd(20)} ${page.toc.length} sections\n`);
  }

  // Client-side search corpus. One small request, cached by Pages.
  await writeFile(path.join(outDir, 'search-index.json'), JSON.stringify(searchIndex), 'utf8');

  // ------------------------------------------------------------ static assets

  // Static assets (stylesheet, script, icons) and pass-through files such as
  // .nojekyll are copied verbatim. Diagrams are authored inline in the page
  // markup so they inherit the active colour theme.
  for (const asset of await readdir(assetsDir)) {
    await copyFile(path.join(assetsDir, asset), path.join(outDir, asset));
  }
  for (const pass of await readdir(staticDir)) {
    await copyFile(path.join(staticDir, pass), path.join(outDir, pass));
  }

  // ------------------------------------------------------------ site plumbing

  const urls = pages.map(
    (p) => `  <url><loc>${SITE.url}${p.slug === 'index' ? '' : `${p.slug}/`}</loc><priority>${
      p.slug === 'index' ? '1.0' : '0.8'
    }</priority></url>`,
  );
  await writeFile(
    path.join(outDir, 'sitemap.xml'),
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`,
    'utf8',
  );

  await writeFile(path.join(outDir, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${SITE.url}sitemap.xml\n`, 'utf8');

  // GitHub Pages serves 404.html for unknown paths; keep it on-brand and useful.
  await writeFile(
    path.join(outDir, '404.html'),
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Page not found — ${SITE.name}</title><link rel="icon" type="image/svg+xml" href="favicon.svg"><link rel="stylesheet" href="styles.css"></head>
<body class="error-page"><main class="error-shell">
<p class="eyebrow">HTTP 404</p><h1>This path is not on the node.</h1>
<p class="page-lede">The page you asked for does not exist on this site. Everything published is listed below.</p>
<ul class="error-links">${NAV.map(
      (n) => `<li><a href="${n.slug === 'index' ? 'index.html' : `${n.slug}.html`}">${n.label}</a></li>`,
    ).join('')}<li><a href="${SITE.repo}">Source repository</a></li></ul>
</main></body></html>\n`,
    'utf8',
  );

  process.stdout.write(`\nBuilt ${pages.length} pages · ${searchIndex.length} search entries → docs/\n`);
}

main().catch((err) => {
  process.stderr.write(`build failed: ${err.message}\n`);
  process.exit(1);
});