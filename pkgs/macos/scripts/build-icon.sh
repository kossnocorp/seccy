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

# Notification Center can resolve the app through the asset catalog rather than
# the loose Finder/Dock .icns. Ship both from the same source before codesigning.
catalog="$temporary/Assets.xcassets"
appicon="$catalog/Seccy.appiconset"
mkdir -p "$appicon" "$temporary/compiled"
cp "$iconset/"*.png "$appicon/"
python3 - "$appicon" <<'PY'
import json
import pathlib
import sys

appicon = pathlib.Path(sys.argv[1])
images = [
    {
        "idiom": "mac",
        "size": f"{size}x{size}",
        "scale": f"{scale}x",
        "filename": f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png",
    }
    for size in (16, 32, 128, 256, 512)
    for scale in (1, 2)
]
info = {"version": 1, "author": "xcode"}
(appicon / "Contents.json").write_text(json.dumps({"images": images, "info": info}))
(appicon.parent / "Contents.json").write_text(json.dumps({"info": info}))
PY
xcrun actool "$catalog" --compile "$temporary/compiled" \
    --platform macosx --minimum-deployment-target 12.0 --app-icon Seccy \
    --output-partial-info-plist "$temporary/icon-info.plist" >/dev/null
test -s "$temporary/compiled/Assets.car"
cp "$temporary/compiled/Assets.car" "$(dirname "$1")/Assets.car"
