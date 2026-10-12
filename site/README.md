# Project website

Source for **[jayasuryamahadevan.github.io/R2R_Communicate](https://jayasuryamahadevan.github.io/R2R_Communicate/)**.

Plain static HTML with a small, dependency-free generator. There is no
`npm install`, no bundler and no framework — `node` and this repository are the
entire toolchain.

```bash
node site/build.mjs        # site/pages -> docs/
node site/check-links.mjs  # dead page, anchor, asset or repo path
node site/audit-layout.mjs # overflow, overlap, clipped text, misaligned cards
node site/audit-contrast.mjs # WCAG AA, and band visibility per theme
```

The two audits drive a real headless Chrome over the built site at eight
viewport widths in both themes. They start their own server and browser, so
they need no setup. Set `CHROME_BIN` if Chrome is not on `PATH`.

To preview locally:

```bash
python3 -m http.server 8811 --directory docs
```

## Why it is built this way

A protocol reference has to stay readable in five years and be correct today.
Generated HTML from a single layout means the navigation, the sidebars, the
pager and the footer cannot drift apart between seven pages, and that adding a
page is one file rather than seven edits.

## Layout

| Path | Purpose |
|---|---|
| `site/build.mjs` | Builds `docs/`. Also the only place page chrome is assembled. |
| `site/layout.mjs` | The HTML shell: head, header, sidebar, pager, footer, search dialog. |
| `site/nav.mjs` | Site constants and the primary navigation order. |
| `site/check-links.mjs` | Link and anchor checker, run in CI and before deploy. |
| `site/audit-harness.mjs` | Shared server + headless browser harness for the audits. |
| `site/audit-layout.mjs` | Overflow, overlap, clipping and card-alignment checks. |
| `site/audit-contrast.mjs` | WCAG AA contrast and section-band visibility. |
| `site/pages/*.html` | **All content lives here.** One file per page. |
| `site/assets/` | `styles.css`, `script.js`, icons. Copied verbatim. |
| `site/static/` | Pass-through files such as `.nojekyll`. |
| `site/og-source.html` | Design source for `assets/og.png`. |
| `docs/` | Generated output. Committed so Pages has something to serve. |

## Page format

A page is front matter plus plain HTML. No templating, no escaping to worry
about, so the content files stay readable and diffable.

```html
---
slug: protocol          # must match an entry in nav.mjs
nav: Protocol           # label in the sidebar and the pager
title: Protocol reference
description: One sentence, used for search results and social cards.
heading: The wire contract
lede: One paragraph that stands on its own.
facts:
  - [Protocol, fasp/1.0]
  - [Signature, Ed25519 over RFC 8785]
---

<section id="envelope" data-nav="Envelope" data-num="01">
  <div class="shell">
    ...
  </div>
</section>
```

- `id` is the anchor. `data-nav` puts the section in the sidebar, in the pager
  and in the search index. `data-num` is the eyebrow number, injected into the
  body so the sidebar and the page can never disagree about it.
- Every section wraps its content in one `<div class="shell">`.
- The table of contents is **derived from the markup**, never written twice.

## Conventions worth keeping

- **Numbers must be verifiable.** Every count on the site — 23 envelope kinds,
  19 endpoints, 19 tables, 11 migrations, 605 tests — is checkable against the
  source. Re-check them when the code changes.
- **Claims are attributed to files.** `source-note` at the end of a section
  links the module or specification it came from.
- **Limits are stated, not implied.** The site carries the same refusals the
  README does: no hard real-time, no safety certification, no independent
  validation, signed-but-not-encrypted.
- **Diagrams are inline SVG** using the CSS custom properties in `styles.css`,
  so they follow the light and dark themes automatically. Do not paste in SVG
  with hard-coded colours.
- **The site works without JavaScript.** Search, scroll-spy and the theme toggle
  are enhancements; navigation and content do not depend on them.
- **Components must not inherit page-level prose spacing.** Headings inside a
  component are reset by the component, never by a later page-level rule. The
  page-level defaults use `:where()` so their specificity is zero; otherwise
  `.home h3` silently wins over `.card h3` and a row of cards falls apart.
- **The band is an override layer, defined last.** `.band-dark` recolours a
  whole region, so it sits at the end of the stylesheet rather than relying on
  selector specificity. Add an entry there for any component colour.
- **Both themes live in one token block** using `light-dark()`. The theme toggle
  only sets `color-scheme`. Do not add a second dark palette block — that is
  how the two themes drift apart.

## Regenerating the social card

`site/assets/og.png` is rendered from `site/og-source.html` at 1200×630. After
editing the source:

```bash
google-chrome --headless=new --disable-gpu --window-size=1200,630 \
  --screenshot=site/assets/og.png "file://$PWD/site/og-source.html"
```