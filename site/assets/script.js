/* FASP reference site — progressive enhancement only.
   Every page works with this file blocked: navigation is real links, search is a
   shortcut over content that already exists in the markup, and the tables of
   contents are server-rendered. */

(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  /* ------------------------------------------------------------ mobile nav */

  const menuButton = $('.menu-toggle');
  const siteNav = $('#site-nav');

  const setMenu = (open) => {
    menuButton?.setAttribute('aria-expanded', String(open));
    siteNav?.classList.toggle('open', open);
  };

  menuButton?.addEventListener('click', () =>
    setMenu(menuButton.getAttribute('aria-expanded') !== 'true'),
  );
  siteNav?.addEventListener('click', (e) => {
    if (e.target.closest('a')) setMenu(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && siteNav?.classList.contains('open')) setMenu(false);
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 900) setMenu(false);
  });

  /* ----------------------------------------------------------------- theme */

  const SUN = '<circle cx="8" cy="8" r="3.3" fill="currentColor"/><g stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M8 .8v1.9M8 13.3v1.9M15.2 8h-1.9M2.7 8H.8M13.1 13.1l-1.35-1.35M4.25 4.25 2.9 2.9M13.1 2.9l-1.35 1.35M4.25 11.75 2.9 13.1"/></g>';
  const MOON = '<path d="M13.4 9.6A5.8 5.8 0 0 1 6.4 2.6a5.8 5.8 0 1 0 7 7Z" fill="currentColor"/>';

  const themeButton = $('[data-theme-toggle]');
  const themeIcon = $('[data-theme-icon]');
  const paintThemeIcon = () => {
    if (!themeIcon) return;
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    themeIcon.innerHTML = dark ? MOON : SUN;
  };

  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
  const isDark = () => {
    const set = document.documentElement.getAttribute('data-theme');
    return set === 'dark' || (set !== 'light' && prefersDark.matches);
  };

  themeButton?.addEventListener('click', () => {
    const next = isDark() ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try {
      localStorage.setItem('fasp-theme', next);
    } catch {
      /* private mode: the toggle still works for this page view */
    }
    paintThemeIcon();
  });

  prefersDark.addEventListener('change', paintThemeIcon);
  paintThemeIcon();

  /* ------------------------------------------------------ copy code blocks */

  $$('.copy-button').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = button.dataset.copy ? document.getElementById(button.dataset.copy) : null;
      const text = target ? target.innerText : button.closest('.code-block')?.querySelector('code')?.innerText;
      if (!text) return;
      const label = button.textContent;
      try {
        await navigator.clipboard.writeText(text.trim());
        button.textContent = 'Copied';
        button.classList.add('is-done');
      } catch {
        button.textContent = 'Press ⌘C';
      }
      setTimeout(() => {
        button.textContent = label;
        button.classList.remove('is-done');
      }, 1800);
    });
  });

  /* ------------------------------------------------------- scroll spy (TOC) */

  const tocLinks = $$('.toc a[href^="#"]');
  if (tocLinks.length) {
    const byId = new Map(tocLinks.map((a) => [a.getAttribute('href').slice(1), a]));
    const sections = tocLinks.map((a) => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
    const rootMargin = '-20% 0px -70% 0px';

    const sync = () => {
      let active = sections[0];
      for (const section of sections) {
        if (section.getBoundingClientRect().top <= window.innerHeight * 0.28) active = section;
        else break;
      }
      // Near the very bottom the last section can never reach the trigger line.
      if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 4) {
        active = sections[sections.length - 1];
      }
      for (const a of tocLinks) a.classList.remove('is-active');
      const link = active && byId.get(active.id);
      link?.classList.add('is-active');
      link?.setAttribute('aria-current', 'true');
    };

    let queued = false;
    window.addEventListener(
      'scroll',
      () => {
        if (queued) return;
        queued = true;
        requestAnimationFrame(() => {
          queued = false;
          sync();
        });
      },
      { passive: true },
    );
    sync();
    void rootMargin;
  }

  /* ---------------------------------------------------------------- search */

  const modal = $('[data-search-modal]');
  const input = $('[data-search-input]');
  const results = $('[data-search-results]');
  if (!modal || !input || !results) return;

  let corpus = null;
  let loading = false;
  let cursor = 0;
  let current = [];

  const normalise = (s) => s.toLowerCase();

  const load = async () => {
    if (corpus || loading) return;
    loading = true;
    try {
      const res = await fetch('search-index.json', { credentials: 'same-origin' });
      corpus = await res.json();
    } catch {
      corpus = [];
      results.innerHTML = '<li class="search-empty">Search index unavailable.</li>';
    }
    loading = false;
  };

  // Rank by where the match lands: a title hit beats a body hit, and earlier
  // hits beat later ones. Good enough for a 30-entry corpus, no dependency.
  const search = (query) => {
    const q = normalise(query.trim());
    if (!q || !corpus) return [];
    const terms = q.split(/\s+/);
    return corpus
      .map((entry) => {
        const title = normalise(entry.t);
        const desc = normalise(entry.d);
        let score = 0;
        let matchedAll = true;
        for (const term of terms) {
          const inTitle = title.indexOf(term);
          const inDesc = desc.indexOf(term);
          if (inTitle === -1 && inDesc === -1) {
            matchedAll = false;
            break;
          }
          if (inTitle !== -1) score += inTitle === 0 ? 120 : 40;
          if (inDesc !== -1) score += 12;
        }
        return matchedAll ? { entry, score: score - title.length / 200 } : null;
      })
      .filter(Boolean)
      .sort((a, b) => b.score - a.score)
      .slice(0, 9)
      .map((r) => r.entry);
  };

  const paint = () => {
    if (!current.length) {
      const q = input.value.trim();
      results.innerHTML = q
        ? `<li class="search-empty">Nothing matches “${q.replace(/[<>&]/g, '')}”.</li>`
        : '';
      return;
    }
    results.innerHTML = current
      .map(
        (r, i) =>
          `<li><a href="${r.u}"${i === cursor ? ' class="is-cursor"' : ''}><span class="r-title">${r.t}</span><span class="r-desc">${r.d.slice(0, 110)}${r.d.length > 110 ? '…' : ''}</span></a></li>`,
      )
      .join('');
    results.querySelector('.is-cursor')?.scrollIntoView({ block: 'nearest' });
  };

  const openSearch = async () => {
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    await load();
    if (corpus?.length) {
      current = corpus.slice(0, 9);
      cursor = 0;
      paint();
    }
    input.focus();
    input.select();
  };

  const closeSearch = () => {
    modal.hidden = true;
    document.body.style.overflow = '';
    input.value = '';
    current = [];
  };

  $$('[data-search-open]').forEach((b) => b.addEventListener('click', openSearch));
  $$('[data-search-close]').forEach((b) => b.addEventListener('click', closeSearch));

  input.addEventListener('input', () => {
    cursor = 0;
    current = search(input.value);
    paint();
  });

  document.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '');

    if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
      e.preventDefault();
      modal.hidden ? openSearch() : closeSearch();
      return;
    }

    if (modal.hidden) return;

    if (e.key === 'Escape') return closeSearch();
    if (!current.length) return;

    if (e.key === 'ArrowDown' || (e.key === 'Tab' && !e.shiftKey)) {
      e.preventDefault();
      cursor = (cursor + 1) % current.length;
      paint();
    } else if (e.key === 'ArrowUp' || (e.key === 'Tab' && e.shiftKey)) {
      e.preventDefault();
      cursor = (cursor - 1 + current.length) % current.length;
      paint();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const href = results.querySelector('.is-cursor a')?.getAttribute('href');
      if (href) window.location.href = href;
    }
  });
})();