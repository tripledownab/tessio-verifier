#!/usr/bin/env bash
#
# preview.sh — build the marketing site and the DocFX API reference, merge them,
# and serve the combined output locally. Mirrors what the CI workflow deploys.
#
# Usage:
#   site/preview.sh          # full build + serve at http://localhost:4321
#   site/preview.sh --skip-build   # just serve the existing dist/
#
# Faster iteration on just the landing page:
#   cd site/web && npm run dev     # hot reload at http://localhost:4321
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/web"
DOCS_DIR="$SCRIPT_DIR/api-docs"
DIST_DIR="$WEB_DIR/dist"
PORT="${PORT:-4321}"

if [[ "${1:-}" != "--skip-build" ]]; then
  echo "▶ Building DocFX (API reference)…"
  (cd "$DOCS_DIR" && docfx metadata docfx.json && docfx build docfx.json)

  echo "▶ Building Astro (landing)…"
  (cd "$WEB_DIR" && npm run build)

  echo "▶ Merging DocFX output into dist/docs/…"
  rm -rf "$DIST_DIR/docs"
  cp -r "$DOCS_DIR/_site" "$DIST_DIR/docs"
fi

echo
echo "▶ Serving combined site at http://localhost:$PORT"
echo "  • landing       → http://localhost:$PORT/"
echo "  • docs (API)   → http://localhost:$PORT/docs/"
echo
echo "  Press Ctrl+C to stop."
echo

cd "$DIST_DIR"
exec python3 -m http.server "$PORT"
