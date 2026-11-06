#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/seccy-tpm.XXXXXXXX")
cleanup() {
    if [[ -f "$temporary/pid" ]]; then kill "$(cat "$temporary/pid")" || true; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
swtpm socket --tpm2 --tpmstate "dir=$temporary" \
    --ctrl "type=unixio,path=$temporary/tpm.sock.ctrl" \
    --server "type=unixio,path=$temporary/tpm.sock" \
    --flags not-need-init,startup-clear --pid "file=$temporary/pid" --daemon
cd -- "$root"
SECCY_TEST_TCTI="swtpm:path=$temporary/tpm.sock" \
    cargo test --locked -p seccy_linux physical_tpm_signing_and_ecdh -- --ignored --test-threads=1
