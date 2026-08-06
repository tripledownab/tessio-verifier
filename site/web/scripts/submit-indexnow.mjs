#!/usr/bin/env node
/**
 * Submit this site's sitemap URLs to IndexNow, which feeds Bing, Yandex, Seznam and Naver.
 * Google does not use IndexNow: it is covered by Search Console and the sitemap in robots.txt.
 *
 * Runs after a successful Pages deploy, not as a postbuild step, because it reads the LIVE
 * sitemap. Submitting before the deploy lands would announce the previous build's URLs.
 *
 * Never fails the caller. A search-engine ping is not worth breaking a deploy over, so every
 * failure is a warning and the exit code stays 0.
 */
const KEY = process.env.INDEXNOW_KEY;
const HOST = process.env.INDEXNOW_HOST;

if (!KEY || !HOST) {
  console.warn('[indexnow] INDEXNOW_KEY and INDEXNOW_HOST must both be set; skipping.');
  process.exit(0);
}

const SITEMAP_URL = `https://${HOST}/sitemap-index.xml`;
const ENDPOINT = 'https://api.indexnow.org/indexnow';

/** Astro emits a sitemap index pointing at sitemap-0.xml, so follow one level down. */
async function collectUrls(url, depth = 0) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  const xml = await res.text();
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim());

  if (xml.includes('<sitemapindex') && depth < 2) {
    const nested = await Promise.all(locs.map((l) => collectUrls(l, depth + 1).catch(() => [])));
    return nested.flat();
  }
  return locs;
}

try {
  const urlList = (await collectUrls(SITEMAP_URL)).filter((u) => u.startsWith(`https://${HOST}`));
  if (urlList.length === 0) {
    console.warn('[indexnow] no URLs found in the sitemap; skipping.');
    process.exit(0);
  }

  console.log(`[indexnow] submitting ${urlList.length} URLs for ${HOST}`);
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      host: HOST,
      key: KEY,
      keyLocation: `https://${HOST}/${KEY}.txt`,
      urlList,
    }),
  });
  // 200 accepted, 202 accepted but key still being validated. Both are fine.
  console.log(`[indexnow] ${res.ok ? 'OK' : 'failed'} (status ${res.status})`);
  if (!res.ok) console.warn(`[indexnow] body: ${(await res.text().catch(() => '')).slice(0, 200)}`);
} catch (err) {
  console.warn(`[indexnow] ${err.message}`);
}
