#!/usr/bin/env bash
# Shared by the production bundle and Xcode gallery.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: build-icon.sh OUTPUT.icns' >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/seccy-icon.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
iconset="$temporary/Seccy.iconset"
mkdir -p "$iconset" "$(dirname "$1")"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$root/assets/icon-macos.png" \
        --out "$iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$root/assets/icon-macos.png" \
        --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$1"
