#!/bin/bash
# Create Apple's app-like wrapper for a CLI with keychain entitlements.
set -euo pipefail

: "${SECCY_SIGNING_IDENTITY:?SECCY_SIGNING_IDENTITY must be set}"
: "${SECCY_PROFILE:?SECCY_PROFILE must be set}"

profile_path=$SECCY_PROFILE
if [[ $profile_path == '~/'* ]]; then
    profile_path="$HOME/${profile_path:2}"
fi
bundle_id=${SECCY_BUNDLE_ID-fyi.seccy.cli}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)

temporary=$(mktemp -d "${TMPDIR:-/tmp}/seccy-package.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
profile="$temporary/profile.plist"
security cms -D -i "$profile_path" > "$profile"

read_profile() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$profile"
}

team=$(read_profile 'Entitlements:com.apple.developer.team-identifier')
# The app identifier prefix can differ from the team identifier.
prefix=$(read_profile 'ApplicationIdentifierPrefix:0')
: "${team:?Profile is missing its team identifier}"
: "${prefix:?Profile is missing its app identifier prefix}"
app_id="$prefix.$bundle_id"
permitted=$(read_profile 'Entitlements:com.apple.application-identifier')

# Unquoted right-hand operands intentionally match profile wildcard patterns.
if [[ $app_id != $permitted ]]; then
    printf 'Profile does not authorize %s\n' "$app_id" >&2
    exit 1
fi

authorized=false
index=0
while group=$(read_profile "Entitlements:keychain-access-groups:$index" 2>/dev/null); do
    if [[ $app_id == $group ]]; then
        authorized=true
        break
    fi
    index=$((index + 1))
done
if [[ $authorized != true ]]; then
    printf 'Profile does not authorize keychain group %s\n' "$app_id" >&2
    exit 1
fi

bundle="$root/target/Seccy.app"
rm -rf "$bundle"
contents="$bundle/Contents"
binaries="$contents/MacOS"
plugin="$contents/Resources/fnox"
mkdir -p "$binaries" "$plugin"
cp "$root/pkgs/fnox/provider.lua" "$plugin/provider.lua"
cp "$root/target/release/seccy" "$binaries/seccy"
cp "$profile_path" "$contents/embedded.provisionprofile"

# Build the standard macOS icon sizes from the source artwork.
iconset="$temporary/Seccy.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$root/assets/icon-macos.png" \
        --out "$iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$root/assets/icon-macos.png" \
        --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$contents/Resources/Seccy.icns"

# plutil handles XML escaping; values are arguments rather than generated XML.
info="$contents/Info.plist"
plutil -create xml1 "$info"
plutil -insert CFBundleIdentifier -string "$bundle_id" "$info"
plutil -insert CFBundleName -string Seccy "$info"
plutil -insert CFBundleExecutable -string seccy "$info"
plutil -insert CFBundleIconFile -string Seccy.icns "$info"
plutil -insert CFBundlePackageType -string APPL "$info"
version=$(cd "$root" && cargo metadata --no-deps --format-version 1 --locked | jaq -r '.packages[] | select(.name == "seccy_cli") | .version')
plutil -insert CFBundleVersion -string "$version" "$info"
plutil -insert CFBundleShortVersionString -string "$version" "$info"
plutil -insert LSMinimumSystemVersion -string 11.0 "$info"
plutil -insert LSBackgroundOnly -bool YES "$info"

entitlements="$root/target/seccy.entitlements.plist"
plutil -create xml1 "$entitlements"
plutil -insert 'com\.apple\.application-identifier' -string "$app_id" "$entitlements"
plutil -insert 'com\.apple\.developer\.team-identifier' -string "$team" "$entitlements"
plutil -insert keychain-access-groups -xml '<array/>' "$entitlements"
plutil -insert keychain-access-groups.0 -string "$app_id" "$entitlements"

codesign --force --sign "$SECCY_SIGNING_IDENTITY" \
    --timestamp --options runtime --entitlements "$entitlements" "$bundle"
codesign --verify --strict "$bundle"
printf '%s\n' "$binaries/seccy"
