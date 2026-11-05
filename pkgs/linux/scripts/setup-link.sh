#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'setup:link currently supports Linux' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# XDG defines data storage, but no standard executable-directory variable.
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
[[ $data = /* ]] || data="$HOME/.local/share"
bin=${XDG_BIN_HOME:-"$HOME/.local/bin"}
[[ $bin = /* ]] || { echo 'XDG_BIN_HOME must be absolute' >&2; exit 1; }
prefix="$data/seccy"
mkdir -p "$bin"
for name in seccy seccy-tpm; do
    if [[ -e "$bin/$name" && ! -L "$bin/$name" ]]; then
        echo "Refusing to replace existing file $bin/$name; move it aside first" >&2
        exit 1
    fi
done
cd -- "$root"
cargo build --locked --release -p seccy_cli -p seccy_linux
target=${CARGO_TARGET_DIR:-"$root/target"}
mkdir -p "$prefix/bin" "$prefix/fnox" "$prefix/system"
for name in seccy seccy-tpm; do
    # Replace atomically so rebuilding works while a user agent is running.
    temporary=$(mktemp "$prefix/bin/.$name.XXXXXXXX")
    install -m 755 "$target/release/$name" "$temporary"
    mv -f -- "$temporary" "$prefix/bin/$name"
    ln -sfn -- "$prefix/bin/$name" "$bin/$name"
done
install -m 644 pkgs/fnox/provider.lua "$prefix/fnox/provider.lua"
install -m 644 pkgs/linux/system/* "$prefix/system/"
printf 'Linked commands into %s\nInstallation: %s\n' "$bin" "$prefix"
printf 'Add %s to PATH, then follow docs/linux/README.md for system service setup.\n' "$bin"
