import { SITE, NAV, SHORT } from './nav.mjs';

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const brandMark = (cls = 'brand-mark') =>
  `<span class="${cls}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>`;

function head(meta) {
  const title = meta.slug === 'index' ? `${SITE.name} — ${SITE.tagline}` : `${meta.title} — ${SITE.name}`;
  const url = `${SITE.url}${meta.slug === 'index' ? '' : `${meta.slug}/`}`;
  return `<!doctype html>
<html lang="en" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(meta.description)}">
  <link rel="canonical" href="${url}">
  <meta name="theme-color" content="#0d1519" media="(prefers-color-scheme: dark)">
  <meta name="theme-color" content="#f3f5f1" media="(prefers-color-scheme: light)">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="${SITE.name} reference harness">
  <meta property="og:title" content="${esc(title)}">
  <meta property="og:description" content="${esc(meta.description)}">
  <meta property="og:url" content="${url}">
  <meta property="og:image" content="${SITE.url}og.png">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="icon" type="image/svg+xml" href="favicon.svg">
  <link rel="stylesheet" href="styles.css">
  <script>
    (function(){try{var t=localStorage.getItem('fasp-theme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}})();
  </script>
  <script src="script.js" defer></script>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>`;
}

function header(activeSlug) {
  const links = NAV.map(
    (n) =>
      `<a href="${n.slug === 'index' ? 'index.html' : `${n.slug}.html`}"${
        n.slug === activeSlug ? ' aria-current="page"' : ''
      }>${n.label}</a>`,
  ).join('\n        ');

  return `<header class="site-header">
    <div class="shell nav-row">
      <a class="brand" href="index.html" aria-label="${SITE.name} home">${brandMark()}<span>${SITE.name}<span class="brand-soft"> / harness</span></span></a>
      <nav id="site-nav" class="site-nav" aria-label="Primary">
        ${links}
      </nav>
      <div class="nav-tools">
        <button class="search-toggle" type="button" data-search-open aria-label="Search the site">
          <svg viewBox="0 0 16 16" aria-hidden="true" width="14" height="14"><circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 10.5 14 14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
          <span>Search</span><kbd>/</kbd>
        </button>
        <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch colour theme">
          <svg viewBox="0 0 16 16" aria-hidden="true" width="15" height="15" data-theme-icon><circle cx="8" cy="8" r="3.4" fill="currentColor"/></svg>
        </button>
        <button class="menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav" aria-label="Toggle navigation"><span aria-hidden="true">☰</span></button>
      </div>
    </div>
  </header>`;
}

function sidebar(toc, activeSlug) {
  if (!toc.length) return '';
  const items = toc
    .map((t) => {
      const num = t.num ? `<span class="toc-num">${esc(t.num)}</span>` : '';
      return `<li><a href="#${t.id}">${num}<span>${esc(t.label)}</span></a></li>`;
    })
    .join('\n          ');
  return `<aside class="toc" aria-label="On this page">
        <p class="toc-label">On this page</p>
        <ol>
          ${items}
        </ol>
      </aside>`;
}

function pager(activeSlug) {
  const i = NAV.findIndex((n) => n.slug === activeSlug);
  const prev = i > 0 ? NAV[i - 1] : null;
  const next = i >= 0 && i < NAV.length - 1 ? NAV[i + 1] : null;
  const link = (n, dir) =>
    n
      ? `<a class="pager-link pager-${dir}" href="${n.slug === 'index' ? 'index.html' : `${n.slug}.html`}">
          <span class="pager-dir">${dir === 'prev' ? 'Previous' : 'Next'}</span>
          <span class="pager-title">${SHORT[n.slug]}</span>
        </a>`
      : '<span></span>';
  return `<nav class="pager" aria-label="Page navigation">${link(prev, 'prev')}${link(next, 'next')}</nav>`;
}

function footer() {
  const year = new Date().getFullYear();
  const repo = NAV.length;
  void repo;
  return `<footer class="site-footer">
    <div class="shell footer-grid">
      <div class="footer-brand">
        <a class="brand" href="index.html">${brandMark()}<span>${SITE.name}<span class="brand-soft"> / harness</span></span></a>
        <p>${esc(SITE.tagline)}</p>
      </div>
      <div class="footer-cols">
        <div><p class="footer-label">Documentation</p>
          ${NAV.slice(1)
            .map((n) => `<a href="${n.slug}.html">${n.label}</a>`)
            .join('\n          ')}
        </div>
        <div><p class="footer-label">Repository</p>
          <a href="${SITE.repo}">Source code</a>
          <a href="${SITE.blob}/README.md">README</a>
          <a href="${SITE.blob}/FASP_PROTOCOL.md">Protocol spec</a>
          <a href="${SITE.blob}/ARCHITECTURE.md">Architecture</a>
          <a href="${SITE.blob}/LICENSE">Apache 2.0</a>
        </div>
      </div>
      <div class="footer-note">
        <p class="footer-label">Status</p>
        <p>Reference implementation and research harness. <strong>Not</strong> safety-certified software, not hard real-time, not independently validated. Physical deployment requires site-specific safety and security review.</p>
        <p class="footer-copy">© ${year} ${esc(SITE.author)}</p>
      </div>
    </div>
  </footer>
  <div class="search-modal" data-search-modal hidden>
    <div class="search-backdrop" data-search-close></div>
    <div class="search-panel" role="dialog" aria-modal="true" aria-label="Search the site">
      <div class="search-field">
        <svg viewBox="0 0 16 16" aria-hidden="true" width="15" height="15"><circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 10.5 14 14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
        <input type="search" data-search-input placeholder="Search pages and sections…" aria-label="Search pages and sections" autocomplete="off" spellcheck="false">
        <kbd>Esc</kbd>
      </div>
      <ul class="search-results" data-search-results></ul>
      <p class="search-hint">Type to filter. <kbd>↑</kbd><kbd>↓</kbd> to move, <kbd>Enter</kbd> to open.</p>
    </div>
  </div>`;
}

export function renderPage(meta, body, toc) {
  const isHome = meta.slug === 'index';
  const hero = isHome
    ? ''
    : `<section class="page-hero">
        <div class="shell">
          <nav class="crumbs" aria-label="Breadcrumb"><a href="index.html">${SITE.name}</a><span aria-hidden="true">/</span><span>${esc(meta.nav || meta.title)}</span></nav>
          <p class="eyebrow">${esc(meta.eyebrow || meta.title)}</p>
          <h1>${meta.heading || esc(meta.title)}</h1>
          ${meta.lede ? `<p class="page-lede">${meta.lede}</p>` : ''}
          ${meta.facts ? `<dl class="hero-facts">${meta.facts
            .map((f) => `<div><dt>${esc(f[0])}</dt><dd>${esc(f[1])}</dd></div>`)
            .join('')}</dl>` : ''}
        </div>
      </section>`;

  const main = isHome
    ? `<main id="main" class="home">${body}</main>`
    : `<main id="main" class="docs"><div class="shell docs-layout">${sidebar(toc, meta.slug)}<article class="doc-body">${body}${pager(meta.slug)}</article></div></main>`;

  return `${head(meta)}
${header(meta.slug)}
${hero}
${main}
${footer()}
</body>
</html>
`;
}