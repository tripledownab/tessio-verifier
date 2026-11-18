# What belongs here: packaging the already-built site into an image that serves it on :80.
# The site is built by .github/workflows/site.yml (DocFX reference plus the Astro landing page) into
# site/web/dist; this file only copies that output next to the server configuration. TLS and the host
# name are the job of whatever proxy fronts the container. Build context is site/.
# web/public/6859f82b21abec5c7b846a95f86d0d1a.txt is the site's IndexNow key, served as is: search
# engines fetch it to verify the pings sent when the site changes. Keep it, though nothing here reads it.
FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
COPY Caddyfile.web /etc/caddy/Caddyfile
COPY web/dist /srv
