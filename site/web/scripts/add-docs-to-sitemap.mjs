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

const urls = files
  .map((f) => {
    // index.html is served as the directory itself, which is the URL people and links actually use.
    const rel = relative(dist, f).split(sep).join('/');
    return `${origin}/${rel.replace(/index\.html$/, '')}`;
  })
  .sort();

const body = urls.map((u) => `  <url><loc>${u}</loc></url>`).join('\n');
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
