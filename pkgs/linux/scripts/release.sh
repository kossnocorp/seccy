#!/usr/bin/env bash
# Release verification intentionally requires no execution of archive contents.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
artifact=${SECCY_RELEASE_ARCHIVE:-"$root/target/seccy-linux.tar.gz"}

case "${1:-}" in
  package)
    [[ $(uname -s) == Linux ]] || { echo 'Linux packaging requires Linux' >&2; exit 1; }
    cd -- "$root"
    cargo build --locked --release -p seccy_cli -p seccy_linux
    mkdir -p -- "$(dirname -- "$artifact")"
    staging=$(mktemp -d "$(dirname -- "$artifact")/.seccy-release.XXXXXXXX")
    trap 'rm -rf -- "$staging"' EXIT
    mkdir -p "$staging/seccy/bin" "$staging/seccy/fnox" "$staging/seccy/docs"
    install -m 755 target/release/seccy "$staging/seccy/bin/seccy"
    mkdir -p "$staging/seccy/system"
    install -m 755 target/release/seccy-tpm "$staging/seccy/bin/seccy-tpm"
    install -m 644 pkgs/linux/system/* "$staging/seccy/system/"
    cp pkgs/fnox/provider.lua "$staging/seccy/fnox/"
    cp README.md "$staging/seccy/"
    cp docs/linux/README.md docs/linux/bin-signing.md "$staging/seccy/docs/"
    {
      git rev-parse HEAD
      rustc --version
      uname -sm
      sha256sum Cargo.lock
      if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
        echo 'Source working tree contains uncommitted changes.'
      fi
    } > "$staging/seccy/BUILD.txt"
    tar -czf "$staging/archive.tar.gz" -C "$staging" seccy
    # Remove the old signature before publishing different bytes.
    rm -f -- "$artifact.sig"
    mv -- "$staging/archive.tar.gz" "$artifact"
    printf 'Packaged %s\n' "$artifact"
    ;;
  sign)
    : "${SECCY_RELEASE_KEY:?Set SECCY_RELEASE_KEY to your release signing key}"
    [[ -f "$artifact" ]] || { echo "Archive not found: $artifact" >&2; exit 1; }
    staging=$(mktemp -d "$(dirname -- "$artifact")/.seccy-sign.XXXXXXXX")
    trap 'rm -rf -- "$staging"' EXIT
    cp -- "$artifact" "$staging/archive"
    ssh-keygen -Y sign -f "$SECCY_RELEASE_KEY" -n seccy-release "$staging/archive"
    cmp -- "$artifact" "$staging/archive"
    mv -- "$staging/archive.sig" "$artifact.sig"
    printf 'Signed %s\n' "$artifact"
    ;;
  verify)
    : "${SECCY_ALLOWED_SIGNERS:?Set SECCY_ALLOWED_SIGNERS to your trusted allowed-signers file}"
    ssh-keygen -Y verify -f "$SECCY_ALLOWED_SIGNERS" -I seccy-release \
      -n seccy-release -s "$artifact.sig" < "$artifact"
    ;;
  *) echo 'Usage: release.sh package|sign|verify' >&2; exit 2 ;;
esac
