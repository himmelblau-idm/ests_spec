#!/bin/sh
set -eu

# Use one selection rule for the PDF and Mermaid renderers.
requested=${1:-${CHROME:-${PUPPETEER_EXECUTABLE_PATH:-}}}
if [ -n "$requested" ]; then
    if command -v "$requested"; then
        exit 0
    fi
    echo "Browser not found: $requested. Set CHROME to an installed Chrome or Chromium executable." >&2
    exit 1
fi

for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "$candidate" 2>/dev/null; then
        exit 0
    fi
done

echo "Chrome or Chromium is required. Install a browser (Fedora: sudo dnf install chromium), or set CHROME=/path/to/browser." >&2
exit 1
