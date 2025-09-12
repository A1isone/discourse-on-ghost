/**
 * README validation tests
 *
 * Testing library/framework: Jest (describe/it/expect). If your project uses Vitest,
 * these tests are compatible with minimal changes (import { describe, it, expect } from 'vitest').
 *
 * Focus: Validate the README sections and links introduced/changed in the PR diff.
 * These tests avoid external HTTP calls to keep the suite hermetic.
 */

const fs = require('fs');
const path = require('path');

// Resolve README path at repo root by default
const README_CANDIDATES = [
  'README.md',
  'Readme.md',
  'readme.md',
  'README.MD',
];

function readReadme() {
  for (const rel of README_CANDIDATES) {
    const p = path.resolve(process.cwd(), rel);
    if (fs.existsSync(p)) {
      return fs.readFileSync(p, 'utf8');
    }
  }
  throw new Error('README file not found at repository root. Checked: ' + README_CANDIDATES.join(', '));
}

function extractLinks(markdown) {
  // Matches [text](url) and bare https?://... links
  const mdLinks = Array.from(markdown.matchAll(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g)).map(m => ({ text: m[1], url: m[2] }));
  const bareLinks = Array.from(markdown.matchAll(/(^|\s)(https?:\/\/[^\s)]+)(?=$|\s|\))/gm)).map(m => ({ text: null, url: m[2] || m[1] }));
  // De-duplicate by URL
  const seen = new Set();
  const all = [];
  mdLinks.concat(bareLinks).forEach((l) => {
    if (!seen.has(l.url)) {
      seen.add(l.url);
      all.push(l);
    }
  });
  return all;
}

describe('README content (PR diff focus)', () => {
  let md;
  beforeAll(() => {
    md = readReadme();
  });

  it('contains the top-level title "Discourse on Ghost"', () => {
    expect(md).toMatch(/#\s+Discourse on Ghost/i);
  });

  it('contains the tagline about Ghost-based SSO for Discourse', () => {
    expect(md).toMatch(/Add Ghost-based SSO to Discourse/i);
  });

  it('explains integration between Discourse and Ghost platforms', () => {
    expect(md).toMatch(/Discourse is a powerful forum.*Ghost is a powerful publishing platform/i);
  });

  it('includes the "🐶 Discourse on Ghost (DoG)" section header', () => {
    // Emoji can vary, match by text with optional emoji
    expect(md).toMatch(/#\s*[\u{1F436}]?\s*Discourse on Ghost\s*\(DoG\)/u);
  });

  it('lists the Live Routes table with expected endpoints', () => {
    // Ensure the routes table header exists
    expect(md).toMatch(/##\s*🌐\s*Live Routes/i);
    // Validate specific routes
    const requiredRoutes = [
      '/health',
      '/discourse/sso',
      '/ghost/api/external_discourse_on_ghost/hook/:token',
    ];
    for (const route of requiredRoutes) {
      expect(md).toContain(route);
    }
  });

  it('documents the Tech Stack with Node.js, TypeScript, Express.js, ESM Modules, and Render', () => {
    expect(md).toMatch(/##\s*🧰\s*Tech Stack/i);
    const expectations = [
      /Node\.js\s*\(v?18\+\)/i,
      /TypeScript/i,
      /Express\.js/i,
      /ESM Modules/i,
      /Render/i,
    ];
    expectations.forEach((re) => expect(md).toMatch(re));
  });

  it('includes developer setup steps with npm install/build/start', () => {
    expect(md).toMatch(/##\s*🛠\s*Setup\s*\(Dev\)/i);
    // Look for fenced block including the three commands in order
    const hasBlock = /```bash[\s\S]*?npm install[\s\S]*?npm run build[\s\S]*?npm start[\s\S]*?```/i.test(md)
      || /```[\s\S]*?npm install[\s\S]*?npm run build[\s\S]*?npm start[\s\S]*?```/i.test(md);
    expect(hasBlock).toBe(true);
  });

  it('advertises the hosted live URL and documentation link', () => {
    expect(md).toMatch(/Hosted live at:/i);
    expect(md).toMatch(/\(https?:\/\/dogffg\.onrender\.com\)/i);
    // Docs link can be bare or markdown; assert presence of the URL string
    expect(md).toMatch(/https?:\/\/github\.vikaspotluri\.me\/discourse-on-ghost\/?/i);
  });

  it('formats critical external links as valid URLs', () => {
    const links = extractLinks(md).map(l => l.url);
    const required = [
      'https://discourse.org',
      'https://ghost.org',
      'https://dogffg.onrender.com',
      'https://github.vikaspotluri.me/discourse-on-ghost/',
    ];
    for (const url of required) {
      const found = links.some(l => l.replace(/\/+$/, '') === url.replace(/\/+$/, ''));
      expect(found).toBe(true);
    }
  });

  it('does not contain obvious placeholder markers like TODO/FIXME in the presented sections', () => {
    const focusSections = [
      /#\s+Discourse on Ghost[\s\S]*?(?=##|$)/i,
      /##\s*🌐\s*Live Routes[\s\S]*?(?=##|$)/i,
      /##\s*🧰\s*Tech Stack[\s\S]*?(?=##|$)/i,
      /##\s*🛠\s*Setup\s*\(Dev\)[\s\S]*?(?=##|$)/i,
    ];
    for (const re of focusSections) {
      const section = (md.match(re) || [''])[0];
      expect(section).not.toMatch(/\b(TODO|FIXME|TBD)\b/);
    }
  });
});

describe('README link hygiene (static checks)', () => {
  let md;
  beforeAll(() => {
    md = readReadme();
  });

  it('does not contain mailto: or javascript: links in the diff sections', () => {
    // Keep README safe from unsafe link schemes
    expect(md).not.toMatch(/\b(?:mailto|javascript):/i);
  });

  it('contains only https:// links for external URLs in the diff sections', () => {
    const links = extractLinks(md).map(l => l.url);
    // Ignore local anchors and relative links (if any)
    const externals = links.filter(u => /^https?:\/\//i.test(u));
    expect(externals.every(u => u.startsWith('https://'))).toBe(true);
  });
});