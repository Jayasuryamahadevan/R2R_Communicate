#!/usr/bin/env node
// Link checker for the generated site. Run after `node site/build.mjs`.
//
//   node site/check-links.mjs
//
// Catches the two mistakes a static site actually makes: a link to a page that
// does not exist, and a fragment that points at an id that was renamed.

import { readFile, readdir, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const docs = path.join(repoRoot, 'docs');

// Links into the repository break silently when a document is renamed, which is
// the one external-link class worth verifying without network access.
async function existsInRepo(relPath) {
  try {
    await access(path.join(repoRoot, relPath));
    return true;
  } catch {
    return false;
  }
}

const pages = (await readdir(docs)).filter((f) => f.endsWith('.html'));
const markup = new Map();
for (const page of pages) markup.set(page, await readFile(path.join(docs, page), 'utf8'));

const repoPaths = new Set();
const assetTargets = new Set();

const existsInDocs = async (rel) => {
  try {
    await access(path.join(docs, rel));
    return true;
  } catch {
    return false;
  }
};

const problems = [];
const ids = (page) => new Set([...markup.get(page).matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
const idCache = new Map();
const idsOf = (page) => {
  if (!idCache.has(page)) idCache.set(page, ids(page));
  return idCache.get(page);
};

for (const page of pages) {
  const html = markup.get(page);
  const refs = [...html.matchAll(/(?:href|src)="([^"]+)"/g)].map((m) => m[1]);

  for (const ref of refs) {
    if (/^(https?:|mailto:|data:|javascript:)/.test(ref)) {
      // External links cannot be checked here. Repository links are checked for
      // the one thing that silently rots: a path that no longer exists.
      const m = ref.match(/github\.com\/[^/]+\/[^/]+\/blob\/[^/]+\/(.+)$/);
      if (m) {
        repoPaths.add(decodeURIComponent(m[1].split('#')[0]));
      }
      continue;
    }

    const [target, fragment] = ref.split('#');

    if (target && !markup.has(target)) {
      // Anything that is not a page is an asset; it still has to exist.
      if (!target.endsWith('.html')) assetTargets.add(target);
      else problems.push(`${page}: missing page — ${ref}`);
      continue;
    }

    if (fragment && !idsOf(target || page).has(fragment)) {
      problems.push(`${page}: dangling anchor — ${ref}`);
    }
  }

  // Every page should carry exactly one canonical, and one h1.
  const canonical = [...html.matchAll(/<link rel="canonical"/g)].length;
  const h1 = [...html.matchAll(/<h1[\s>]/g)].length;
  if (canonical !== 1 && page !== '404.html') problems.push(`${page}: expected 1 canonical link, found ${canonical}`);
  if (h1 !== 1) problems.push(`${page}: expected 1 h1, found ${h1}`);
}

// Repository paths and site assets are resolved after the page walk so the
// check is one batch rather than one syscall per link.
for (const rel of repoPaths) {
  if (!(await existsInRepo(rel))) problems.push(`repository path missing — ${rel}`);
}
for (const rel of assetTargets) {
  if (!(await existsInDocs(rel))) problems.push(`site asset missing — ${rel}`);
}
if (problems.length) {
  process.stderr.write(`\n${problems.length} link problem(s):\n  ${problems.join('\n  ')}\n`);
  process.exit(1);
}

const links = [...markup.values()].flatMap((h) => [...h.matchAll(/(?:href|src)="([^"]+)"/g)]).length;
process.stdout.write(`${pages.length} pages, ${links} references, all resolve.\n`);