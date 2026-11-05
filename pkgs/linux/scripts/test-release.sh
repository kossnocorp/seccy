#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp/opencode}/seccy-release-test.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
export SECCY_RELEASE_KEY="$temporary/signing key"
export SECCY_RELEASE_ARCHIVE="$temporary/release archive.tar.gz"
export SECCY_ALLOWED_SIGNERS="$temporary/allowed signers"
ssh-keygen -q -t ed25519 -N '' -f "$SECCY_RELEASE_KEY"
printf 'seccy-release namespaces="seccy-release" %s\n' "$(cat "$SECCY_RELEASE_KEY.pub")" > "$SECCY_ALLOWED_SIGNERS"
printf 'release payload\n' > "$SECCY_RELEASE_ARCHIVE"
bash "$root/pkgs/linux/scripts/release.sh" sign
bash "$root/pkgs/linux/scripts/release.sh" verify
printf 'tampering\n' >> "$SECCY_RELEASE_ARCHIVE"
if bash "$root/pkgs/linux/scripts/release.sh" verify; then
  echo 'Tampered artifact was accepted' >&2
  exit 1
fi
bash "$root/pkgs/linux/scripts/release.sh" sign
ssh-keygen -q -t ed25519 -N '' -f "$temporary/untrusted"
printf 'seccy-release %s\n' "$(cat "$temporary/untrusted.pub")" > "$SECCY_ALLOWED_SIGNERS"
if bash "$root/pkgs/linux/scripts/release.sh" verify; then
  echo 'Untrusted signing key was accepted' >&2
  exit 1
fi
printf 'release signature tests passed\n'
