// Site-wide constants. Everything a page needs to know about *other* pages
// lives here so the navigation can never drift between pages.

export const SITE = {
  name: 'FASP',
  suffix: 'reference harness',
  tagline: 'A coordination protocol that structurally refuses to become a control system.',
  description:
    'FASP is a signed-envelope coordination layer for autonomous systems. Local identity, local authority, and an enforced boundary above hard real-time safety.',
  url: 'https://jayasuryamahadevan.github.io/R2R_Communicate/',
  repo: 'https://github.com/Jayasuryamahadevan/R2R_Communicate',
  blob: 'https://github.com/Jayasuryamahadevan/R2R_Communicate/blob/main',
  license: 'Apache-2.0',
  author: 'Jayasurya Mahadevan',
};

// Primary navigation order. `slug` matches the page front matter.
export const NAV = [
  { slug: 'index', label: 'Overview' },
  { slug: 'architecture', label: 'Architecture' },
  { slug: 'protocol', label: 'Protocol' },
  { slug: 'spatial', label: 'Spatial' },
  { slug: 'connectivity', label: 'Connectivity' },
  { slug: 'operations', label: 'Operations' },
  { slug: 'guide', label: 'Guide' },
];

// Short label used in the "next/previous" pager.
export const SHORT = {
  index: 'Overview',
  architecture: 'Architecture',
  protocol: 'Protocol',
  spatial: 'Spatial',
  connectivity: 'Connectivity',
  operations: 'Operations',
  guide: 'Guide',
};