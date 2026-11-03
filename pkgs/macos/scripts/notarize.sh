#!/bin/bash
# Submit a signed bundle and produce a stapled archive for distribution.
set -euo pipefail

: "${SECCY_NOTARY_PROFILE:?Run mise run notarize:setup to configure notarization credentials}"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
target="$root/target"
result="$target/notarization-result.json"
log="$target/notarization-log.json"
archive="$target/Seccy-notarized.zip"

# Submit and staple the same snapshot, even if another build changes the original.
temporary=$(mktemp -d "$target/notarize.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
bundle="$temporary/Seccy.app"
ditto "$target/Seccy.app" "$bundle"
codesign --verify --strict "$bundle"
ditto -c -k --keepParent "$bundle" "$temporary/Seccy.zip"

printf 'Submitting to Apple; this may take several minutes.\n'
submit_exit=0
xcrun notarytool submit "$temporary/Seccy.zip" \
    --keychain-profile "$SECCY_NOTARY_PROFILE" \
    --wait --output-format json > "$result" || submit_exit=$?
cat "$result"

status=$(plutil -extract status raw -o - "$result" 2>/dev/null || true)
if [[ $submit_exit != 0 || $status != Accepted ]]; then
    submission_id=$(plutil -extract id raw -o - "$result" 2>/dev/null || true)
    if [[ -n $submission_id ]]; then
        if xcrun notarytool log "$submission_id" \
            --keychain-profile "$SECCY_NOTARY_PROFILE" "$log"; then
            printf 'Apple submission log: %s\n' "$log" >&2
        fi
    fi
    printf 'Notarization was not accepted. See %s and the errors above.\n' "$result" >&2
    exit 1
fi

xcrun stapler staple "$bundle"
xcrun stapler validate "$bundle"
spctl --assess --type execute --verbose=2 "$bundle"

ditto -c -k --keepParent "$bundle" "$temporary/Seccy-notarized.zip"
mv -f "$temporary/Seccy-notarized.zip" "$archive"
printf '\nSend this archive to your other Mac: %s\n' "$archive"
