#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
if [[ ${1:-} == --archive ]]; then
    exec bash scripts/install.sh "$@"
fi
[[ $# == 0 ]] || { echo 'Usage: build.sh [--archive PATH [--install-only]]' >&2; exit 2; }
version=$(cargo metadata --no-deps --format-version 1 --locked | jaq -r '.packages[] | select(.name == "seccy_cli") | .version')
if [[ -n ${GITHUB_REF_NAME:-} && ${GITHUB_REF_TYPE:-} == tag ]]; then
    [[ $GITHUB_REF_NAME == "cli@$version" ]] || { echo "Tag must match Cargo version cli@$version" >&2; exit 1; }
fi
arch=$(uname -m)
[[ $arch != arm64 ]] || arch=aarch64
mkdir -p target/release-assets
case $(uname -s) in
    Linux)
        export SECCY_RELEASE_ARCHIVE="$root/target/release-assets/seccy-cli@$version-linux-$arch.tar.gz"
        bash pkgs/linux/scripts/release.sh package
        ;;
    Darwin)
        cargo build --locked --release -p seccy_cli
        bash pkgs/macos/scripts/package.sh
        bash pkgs/macos/scripts/notarize.sh
        cp target/Seccy-notarized.zip "target/release-assets/seccy-cli@$version-macos-$arch.zip"
        ;;
    *) echo 'Only Linux and macOS are supported' >&2; exit 1 ;;
esac
