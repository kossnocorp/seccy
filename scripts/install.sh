#!/usr/bin/env bash
# Also published verbatim at https://seccy.fyi/install.sh.
set -euo pipefail
usage() {
    cat <<'EOF'
Usage: install.sh [--version cli@X.Y.Z] [--archive PATH]
Installs or updates Seccy and its fnox provider.
--archive PATH   Use a local archive (verify its provenance before running).
SECCY_REPOSITORY defaults to kossnocorp/seccy; XDG_BIN_HOME defaults to ~/.local/bin.
EOF
}
# Parse the complete installer before running it when stdin contains the script.
main() {
archive= version=
while (($#)); do
    case $1 in
        --archive|--version) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; option=$1; shift; if [[ $option == --archive ]]; then archive=$1; else version=$1; fi ;;
        -h|--help) usage; exit ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
[[ $(id -u) != 0 ]] || { echo 'Run as your desktop user, not root.' >&2; exit 1; }
os=$(uname -s)
arch=$(uname -m)
[[ $arch != arm64 ]] || arch=aarch64
case $os in Darwin) platform=macos; extension=zip ;; Linux) platform=linux; extension=tar.gz ;; *) echo 'Unsupported OS' >&2; exit 1 ;; esac
case $arch in aarch64|x86_64) ;; *) echo 'Unsupported CPU' >&2; exit 1 ;; esac
bin=${XDG_BIN_HOME:-"$HOME/.local/bin"}
[[ $bin = /* ]] || { echo 'XDG_BIN_HOME must be absolute' >&2; exit 1; }
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
[[ $data = /* ]] || data="$HOME/.local/share"
prefix="$data/seccy"
if [[ $os == Darwin ]]; then
    executable="$prefix/Seccy.app/Contents/MacOS/seccy"
else
    executable="$prefix/bin/seccy"
fi
installed_version=$("$executable" --version 2>/dev/null) || installed_version=
refresh_macos_service() {
    # A bundle replacement does not restart launchd's existing process. Reuse
    # service install to enable/restart it, or bootstrap an unloaded definition.
    # Leave first-time service setup to the user.
    if [[ $os == Darwin && -f $HOME/Library/LaunchAgents/fyi.seccy.agent.plist ]]; then
        if ! "$executable" service install; then
            echo 'Seccy is installed, but refreshing its service failed. Run seccy service install to retry.' >&2
            return 1
        fi
    fi
}
skip_if_installed() {
    if [[ -n $1 && $installed_version == "seccy ${1#cli@}" ]]; then
        refresh_macos_service
        echo "Seccy ${1#cli@} is already installed."
        echo 'https://seccy.fyi/install'
        exit 0
    fi
}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/seccy-install.XXXXXXXX")
trap 'rm -rf "$temporary"' EXIT
if [[ -z $archive ]]; then
    if [[ $os == Darwin && $arch == x86_64 ]]; then
        echo 'Prebuilt macOS releases require Apple Silicon. On Apple Silicon, run from a native ARM64 terminal; Intel Macs require a locally built archive (--archive PATH).' >&2
        exit 1
    fi
    repository=${SECCY_REPOSITORY:-kossnocorp/seccy}
    base="https://github.com/$repository/releases"
    if [[ -z $version ]]; then
        url=$(curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$base/latest")
        version=${url##*/}
    fi
    [[ $version =~ ^cli@[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected version cli@X.Y.Z' >&2; exit 1; }
    skip_if_installed "$version"
    name="seccy-$version-$platform-$arch.$extension"
    archive="$temporary/$name"
    curl -fSL --proto '=https' --proto-redir '=https' "$base/download/$version/$name" -o "$archive"
    curl -fsSL --proto '=https' --proto-redir '=https' "$base/download/$version/SHA256SUMS" -o "$temporary/SHA256SUMS"
    expected=$(awk -v name="$name" '$2 == name {print $1}' "$temporary/SHA256SUMS")
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || { echo 'Missing or invalid checksum' >&2; exit 1; }
    if [[ $os == Darwin ]]; then actual=$(shasum -a 256 "$archive"); else actual=$(sha256sum "$archive"); fi
    [[ ${actual%% *} == "$expected" ]] || { echo 'Archive checksum mismatch' >&2; exit 1; }
fi
[[ -f $archive ]] || { echo "Archive not found: $archive" >&2; exit 1; }
mkdir -p "$bin" "$temporary/extracted"
if [[ $os == Darwin ]]; then
    ditto -x -k "$archive" "$temporary/extracted"
    app="$temporary/extracted/Seccy.app"
    codesign --verify --strict "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute "$app"
    candidate_version=$("$app/Contents/MacOS/seccy" --version)
    skip_if_installed "${candidate_version#seccy }"
    mkdir -p "$prefix"
    destination="$prefix/Seccy.app"
    # Preserve the previous installation until the new bundle has been verified.
    if [[ -e $destination ]]; then mv "$destination" "$temporary/previous.app"; fi
    if ! ditto "$app" "$destination"; then
        rm -rf "$destination"
        [[ ! -e $temporary/previous.app ]] || mv "$temporary/previous.app" "$destination"
        exit 1
    fi
    executable="$destination/Contents/MacOS/seccy"
    ln -sfn "$executable" "$bin/seccy"
else
    tar -xzf "$archive" -C "$temporary/extracted"
    source="$temporary/extracted/seccy"
    for file in bin/seccy bin/seccy-tpm fnox/provider.lua system/seccy-tpm.conf system/seccy-tpm.service; do
        [[ -f $source/$file ]] || { echo "Incomplete archive: $file" >&2; exit 1; }
    done
    if ! candidate_version=$("$source/bin/seccy" --version); then
        echo 'Cannot run Seccy. See https://seccy.fyi/install' >&2
        exit 1
    fi
    skip_if_installed "${candidate_version#seccy }"
    mkdir -p "$prefix/bin" "$prefix/fnox" "$prefix/system"
    for name in seccy seccy-tpm; do
        stage=$(mktemp "$prefix/bin/.$name.XXXXXXXX")
        install -m 755 "$source/bin/$name" "$stage"
        mv -f "$stage" "$prefix/bin/$name"
        ln -sfn "$prefix/bin/$name" "$bin/$name"
    done
    install -m 644 "$source/fnox/provider.lua" "$prefix/fnox/"
    install -m 644 "$source/system/"* "$prefix/system/"
    executable="$prefix/bin/seccy"
fi
refresh_macos_service
export PATH="$bin:$PATH"
"$executable" fnox init
if command -v fnox >/dev/null; then
    fnox plugin link --force seccy "$("$executable" fnox info --jq-raw .plugin_dir)"
fi
echo 'https://seccy.fyi/install'
}

main "$@"; exit "$?"
