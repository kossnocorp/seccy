#!/usr/bin/env bash
# Ephemeral signing keychain; cleanup also runs as an always() workflow step.
set -euo pipefail
: "${RUNNER_TEMP:?This script is for GitHub-hosted macOS runners}"
keychain="$RUNNER_TEMP/seccy-signing.keychain-db"
if [[ ${1:-} == cleanup ]]; then
    security default-keychain -d user -s login.keychain-db
    security delete-keychain "$keychain" || true
    rm -f "$RUNNER_TEMP/seccy.p12" "$RUNNER_TEMP/seccy.provisionprofile"
    exit
fi
: "${SECCY_CERTIFICATE_BASE64:?}"
: "${SECCY_CERTIFICATE_PASSWORD:?}"
: "${SECCY_PROFILE_BASE64:?}"
umask 077
printf '%s' "$SECCY_CERTIFICATE_BASE64" | base64 --decode > "$RUNNER_TEMP/seccy.p12"
printf '%s' "$SECCY_PROFILE_BASE64" | base64 --decode > "$RUNNER_TEMP/seccy.provisionprofile"
password=$(openssl rand -hex 32)
echo "::add-mask::$password"
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$RUNNER_TEMP/seccy.p12" -k "$keychain" -P "$SECCY_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain"
security list-keychains -d user -s "$keychain" login.keychain-db
security default-keychain -d user -s "$keychain"
echo "SECCY_PROFILE=$RUNNER_TEMP/seccy.provisionprofile" >> "$GITHUB_ENV"
echo 'SECCY_NOTARY_PROFILE=seccy-ci' >> "$GITHUB_ENV"
SECCY_NOTARY_PROFILE=seccy-ci bash pkgs/macos/scripts/notarize-setup.sh
