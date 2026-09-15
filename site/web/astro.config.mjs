import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

// Custom domain (verifier.tessio.eu) serves at apex, so no subpath. Override via env if needed.
const SITE_BASE = process.env.SITE_BASE ?? '/';
const SITE_URL = process.env.SITE_URL ?? 'https://verifier.tessio.eu';

export default defineConfig({
  site: SITE_URL,
  base: SITE_BASE,
  trailingSlash: 'never',
  // lastmod on every entry. An engine reads it to decide whether a recrawl is worth its time, and a
  // sitemap without one says nothing, so every URL looks equally fresh and equally stale. Build time
  // is the honest value for a statically generated page: it is when this copy came into existence,
  // and there is no per-page source date to draw on for one hand-written landing page.
  //
  // The DocFX pages under /docs are appended afterwards by scripts/add-docs-to-sitemap.mjs, which
  // Astro never sees; that script stamps its own lastmod from each file's mtime.
  integrations: [
    sitemap({
      serialize: (item) => ({ ...item, lastmod: new Date().toISOString() }),
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
