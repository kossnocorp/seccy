#!/usr/bin/env bash
# Also published verbatim at https://seccy.fiy/install.sh.
set -euo pipefail
usage() {
    cat <<'EOF'
Usage: install.sh [--version cli@X.Y.Z] [--archive PATH] [--install-only]
Installs a complete Seccy release, then configures keys, fnox, and the login agent.
--archive PATH   Use a local archive (verify its provenance before running).
--install-only   Install files without sudo, device enrollment, or service setup.
SECCY_REPOSITORY defaults to kossnocorp/seccy; XDG_BIN_HOME defaults to ~/.local/bin.
EOF
}
# Parse the complete installer before running it when stdin contains the script.
main() {
archive= version= install_only=false
while (($#)); do
    case $1 in
        --archive|--version) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; option=$1; shift; if [[ $option == --archive ]]; then archive=$1; else version=$1; fi ;;
        --install-only) install_only=true ;;
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
if [[ $install_only == false && ! -t 0 ]]; then
    if ! { exec </dev/tty; } 2>/dev/null; then
        echo 'Setup requires a terminal. Run from an interactive terminal or use --install-only.' >&2
        exit 1
    fi
fi
temporary=$(mktemp -d "${TMPDIR:-/tmp}/seccy-install.XXXXXXXX")
trap 'rm -rf "$temporary"' EXIT
if [[ -z $archive ]]; then
    repository=${SECCY_REPOSITORY:-kossnocorp/seccy}
    base="https://github.com/$repository/releases"
    if [[ -z $version ]]; then
        url=$(curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$base/latest")
        version=${url##*/}
    fi
    [[ $version =~ ^cli@[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected version cli@X.Y.Z' >&2; exit 1; }
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
bin=${XDG_BIN_HOME:-"$HOME/.local/bin"}
[[ $bin = /* ]] || { echo 'XDG_BIN_HOME must be absolute' >&2; exit 1; }
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
[[ $data = /* ]] || data="$HOME/.local/share"
mkdir -p "$bin" "$temporary/extracted"
for name in seccy seccy-tpm; do
    if [[ -e "$bin/$name" && ! -L "$bin/$name" ]]; then
        echo "Move existing file $bin/$name aside first" >&2; exit 1
    fi
done
if [[ $os == Darwin ]]; then
    ditto -x -k "$archive" "$temporary/extracted"
    app="$temporary/extracted/Seccy.app"
    codesign --verify --strict "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute "$app"
    mkdir -p "$HOME/Applications"
    destination="$HOME/Applications/Seccy.app"
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
    prefix="$data/seccy"
    for file in bin/seccy bin/seccy-tpm fnox/provider.lua system/seccy-tpm.conf system/seccy-tpm.service; do
        [[ -f $source/$file ]] || { echo "Incomplete archive: $file" >&2; exit 1; }
    done
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
export PATH="$bin:$PATH"
if [[ $os == Linux ]] && ! "$executable" --version; then
    echo 'Install Linux runtime dependencies first; see https://github.com/kossnocorp/seccy/blob/main/docs/linux/README.md' >&2
    exit 1
fi
"$executable" fnox init
if command -v fnox >/dev/null; then
    fnox plugin link seccy "$("$executable" fnox info --jq-raw .plugin_dir)"
else
    echo 'Install fnox >= 1.47, then run: fnox plugin link seccy "$(seccy fnox info --jq-raw .plugin_dir)"'
fi
if [[ $install_only == true ]]; then
    printf 'Installed. Add %s to PATH. Rerun without --install-only to configure services and keys.\n' "$bin"
    exit
fi
if [[ $os == Linux ]]; then
    sudo install -d -m 755 /usr/local/libexec /etc/sysusers.d /etc/systemd/system
    sudo install -o root -g root -m 755 "$prefix/bin/seccy-tpm" /usr/local/libexec/seccy-tpm
    sudo install -o root -g root -m 644 "$prefix/system/seccy-tpm.conf" /etc/sysusers.d/seccy-tpm.conf
    sudo systemd-sysusers /etc/sysusers.d/seccy-tpm.conf
    sudo install -o root -g root -m 644 "$prefix/system/seccy-tpm.service" /etc/systemd/system/seccy-tpm.service
    sudo systemctl daemon-reload
    sudo systemctl enable seccy-tpm.service
    sudo systemctl restart seccy-tpm.service
    "$executable" init --list
    read -r -p 'FIDO2 device path for enrollment (empty uses automatic selection): ' device
    if [[ -n $device ]]; then "$executable" init --device "$device"; else "$executable" init; fi
fi
config=${XDG_CONFIG_HOME:-"$HOME/.config"}
[[ $config = /* ]] || config="$HOME/.config"
mkdir -p "$config/seccy"
if [[ ! -e $config/seccy/config.toml ]]; then
    (umask 077; set -o noclobber; cat > "$config/seccy/config.toml" <<'EOF'
log_level = "info"

[keys.personal]
mode = "prompt"
github = "auth"

[keys.signing]
mode = "prompt"
github = "signing"

[keys.secrets]
mode = "prompt"
EOF
    )
fi
"$executable" provision
"$executable" service install
"$executable" service status
state=${XDG_STATE_HOME:-"$HOME/.local/state"}
[[ $state = /* ]] || state="$HOME/.local/state"
runtime=${XDG_RUNTIME_DIR:-"$state"}
[[ $runtime = /* ]] || runtime="$state"
socket="$runtime/seccy/agent.sock"
mkdir -p "$config/seccy"
printf 'export PATH=%q:"$PATH"\nexport SSH_AUTH_SOCK=%q\n' "$bin" "$socket" > "$config/seccy/env.sh"
printf '\nSetup complete. Add this to your Bash/Zsh startup file:\n  source %q\n' "$config/seccy/env.sh"
printf 'Public keys: %s/seccy/keys\nConfig: %s/seccy/config.toml\n' "$state" "$config"
echo 'Register public keys with your host (or use seccy gh sync after gh auth login).'
echo 'For Git signing: git config --global gpg.format ssh'
printf '  git config --global user.signingkey %q\n' "$state/seccy/keys/signing.pub"
echo '  git config --global commit.gpgsign true'
}

# Exit without asking Bash to read further commands from the setup terminal.
main "$@"; exit "$?"
