#!/usr/bin/env node
/**
 * Add the merged DocFX pages under /docs to the sitemap.
 *
 * Astro generates the sitemap during its own build, which happens BEFORE the DocFX output is merged
 * into dist/docs. So Astro only ever sees the landing page, and the published sitemap listed exactly
 * one URL while the entire API reference and the guides were absent from it. They were reachable by
 * following links, but never announced, and IndexNow submitted a single URL per deploy.
 *
 * Rather than teach Astro about files that do not exist yet at its build time, this runs after the
 * merge: it walks dist/docs for .html files, writes sitemap-docs.xml, and adds that to the existing
 * sitemap index.
 *
 * Usage: node scripts/add-docs-to-sitemap.mjs <dist-dir> <site-origin>
 */
import { readdir, readFile, writeFile, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

const dist = process.argv[2];
const origin = (process.argv[3] || '').replace(/\/$/, '');

if (!dist || !origin) {
  console.error('usage: add-docs-to-sitemap.mjs <dist-dir> <site-origin>');
  process.exit(1);
}

/** DocFX emits navigation partials alongside real pages; those are not content and must not be listed. */
const SKIP = new Set(['toc.html']);

/**
 * The generated API reference is not LISTED, while staying live, linked and crawlable.
 *
 * A sitemap is a request to crawl. 67 of the 69 pages here were generated type documentation: one
 * page per class, titled after the class, carrying prose nobody wrote for a reader. They answer a
 * question somebody already inside the library has, they are reached from the table of contents, and
 * they will not earn a search visit. Listing them spends crawl budget on them and buries the two
 * pages that were actually written.
 *
 * Not listed is not hidden, and that distinction is the whole point: these pages carry no robots
 * directive and remain linked, so an engine that wants them can still have them.
 */
const UNLISTED_PREFIX = 'docs/api/';

async function walk(dir) {
  let out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out; // no docs directory: nothing to add, and that is not an error worth failing on
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out = out.concat(await walk(full));
    else if (e.name.endsWith('.html') && !SKIP.has(e.name)) out.push(full);
  }
  return out;
}

const docsDir = join(dist, 'docs');
const files = await walk(docsDir);

if (files.length === 0) {
  console.warn('[sitemap] no pages found under dist/docs; leaving the sitemap alone.');
  process.exit(0);
}

// lastmod from the file's own mtime, which for a generated site is its build time. An engine uses it
// to decide whether a recrawl is worth it, and a sitemap without one tells it nothing, so every URL
// looks equally stale and equally fresh.
const entries = (
  await Promise.all(
    files.map(async (f) => {
      // index.html is served as the directory itself, which is the URL people and links actually use.
      const rel = relative(dist, f).split(sep).join('/');
      if (rel.startsWith(UNLISTED_PREFIX)) return null;
      const { mtime } = await stat(f);
      return { loc: `${origin}/${rel.replace(/index\.html$/, '')}`, lastmod: mtime.toISOString() };
    }),
  )
)
  .filter(Boolean)
  .sort((a, b) => a.loc.localeCompare(b.loc));

const unlisted = files.length - entries.length;
if (unlisted > 0) {
  // Said out loud, because a silent drop reads as "the sitemap covers everything" when it does not.
  console.log(`[sitemap] ${unlisted} generated API reference pages left unlisted, and still crawlable`);
}

if (entries.length === 0) {
  console.warn('[sitemap] every page under dist/docs is unlisted; leaving the sitemap alone.');
  process.exit(0);
}

const urls = entries.map((e) => e.loc);
const body = entries
  .map((e) => `  <url><loc>${e.loc}</loc><lastmod>${e.lastmod}</lastmod></url>`)
  .join('\n');
await writeFile(
  join(dist, 'sitemap-docs.xml'),
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${body}\n</urlset>\n`,
);

// Add it to the index Astro already wrote, so one sitemap URL still covers the whole site.
const indexPath = join(dist, 'sitemap-index.xml');
let index;
try {
  index = await readFile(indexPath, 'utf8');
} catch {
  console.warn('[sitemap] no sitemap-index.xml from Astro; wrote sitemap-docs.xml only.');
  process.exit(0);
}

if (!index.includes('sitemap-docs.xml')) {
  index = index.replace(
    '</sitemapindex>',
    `<sitemap><loc>${origin}/sitemap-docs.xml</loc></sitemap></sitemapindex>`,
  );
  await writeFile(indexPath, index);
}

console.log(`[sitemap] added ${urls.length} DocFX pages to the sitemap index`);
