#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MMDC=${MMDC:-mmdc}

if ! command -v "$MMDC" >/dev/null 2>&1; then
    echo "Mermaid CLI not found: $MMDC. Install it with: npm install --global @mermaid-js/mermaid-cli" >&2
    exit 1
fi

PUPPETEER_EXECUTABLE_PATH=$(sh "$script_dir/browser.sh" "${CHROME:-}")
export PUPPETEER_EXECUTABLE_PATH

render() {
    mkdir -p "$(dirname -- "$2")"
    "$MMDC" -p "$script_dir/puppeteer.json" \
        -c "$script_dir/mermaid-config.json" \
        -i "$1" -o "$2" -s 2 -b white
}

case $# in
    0)
        "${PYTHON:-python3}" "$script_dir/mkfigs.py"
        for source in "$script_dir"/src/*.mmd; do
            name=$(basename -- "$source" .mmd)
            render "$source" "$script_dir/../images/$name.png"
        done
        ;;
    2) render "$1" "$2" ;;
    *) echo "Usage: $0 [input.mmd output.png]" >&2; exit 2 ;;
esac
