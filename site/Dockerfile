# What belongs here: packaging the already-built site into an image that serves it on :80.
# The site is built by .github/workflows/site.yml (DocFX reference plus the Astro landing page) into
# site/web/dist; this file only copies that output next to the server configuration. TLS and the host
# name are the job of whatever proxy fronts the container. Build context is site/.
FROM caddy:2.11.8-alpine@sha256:f6228111e5fafa1a5238258d0858e103f10599b8d1659a146e7726681a002bb9
COPY Caddyfile.web /etc/caddy/Caddyfile
COPY web/dist /srv
