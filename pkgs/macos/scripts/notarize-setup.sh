#!/bin/bash
# Store notarization credentials in Keychain; prompt if no password was supplied.
set -euo pipefail

: "${SECCY_APPLE_ID:?Set SECCY_APPLE_ID to your Apple Developer account email}"
: "${SECCY_TEAM_ID:?Set SECCY_TEAM_ID to your Apple Developer team ID}"
: "${SECCY_NOTARY_PROFILE:?Set SECCY_NOTARY_PROFILE to a Keychain credential name}"

args=(
    notarytool store-credentials "$SECCY_NOTARY_PROFILE"
    --apple-id "$SECCY_APPLE_ID"
    --team-id "$SECCY_TEAM_ID"
)
if [[ -n ${SECCY_APPLE_PASSWORD:-} ]]; then
    args+=(--password "$SECCY_APPLE_PASSWORD")
fi
xcrun "${args[@]}"
