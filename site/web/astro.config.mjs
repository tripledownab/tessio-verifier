import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

// Custom domain (verifier.tessio.eu) serves at apex — no subpath. Override via env if needed.
const SITE_BASE = process.env.SITE_BASE ?? '/';
const SITE_URL = process.env.SITE_URL ?? 'https://verifier.tessio.eu';

export default defineConfig({
  site: SITE_URL,
  base: SITE_BASE,
  trailingSlash: 'never',
  integrations: [sitemap()],
  vite: {
    plugins: [tailwindcss()],
  },
});
