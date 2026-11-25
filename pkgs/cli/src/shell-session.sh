#!/usr/bin/env bash
# Embedded in seccy shell. No global config or launchd changes.
set -euo pipefail
directory=$1 executable=$2 shell=$3 kind=$4 command=$5 mode=$6
agent= child=
stop() {
    local pid=$1 signal=$2 i
    kill "-$signal" "$pid" 2>/dev/null || true
    for ((i=0; i<50; i++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
cleanup() {
    trap - EXIT HUP TERM INT
    if [[ -n $child ]]; then
        stop "$child" HUP
    fi
    if [[ -n $agent ]]; then
        # Allow pending authorization to unwind, but never hang on shell exit.
        stop "$agent" TERM
    fi
    rm -rf "$directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 143' TERM
trap ':' INT
export XDG_RUNTIME_DIR="$directory"
"$executable" --json agent --socket "$directory/seccy/agent.sock" \
    >"$directory/agent.log" 2>&1 </dev/null &
agent=$!
ready=false
for ((i=0; i<200; i++)); do
    if grep -Eq '"event"[[:space:]]*:[[:space:]]*"ready"' "$directory/agent.log"; then
        ready=true
        break
    fi
    if ! kill -0 "$agent" 2>/dev/null; then break; fi
    sleep 0.1
done
if [[ $ready != true ]]; then
    cat "$directory/agent.log" >&2
    echo 'Seccy agent did not become ready.' >&2
    exit 1
fi

# Read startup files normally, then apply session overrides last. Noninteractive
# commands use the same environment without running interactive startup files.
if [[ $mode == command ]]; then
    # fish has different export syntax, so source its generated apply file there.
    if [[ $kind == fish ]]; then
        "$shell" -c 'source "$argv[1]"; eval "$argv[2]"' "$directory/apply" "$command" <&0 &
    else
        "$shell" -c '. "$1"; eval "$2"' seccy-shell "$directory/apply" "$command" <&0 &
    fi
elif [[ $kind == fish ]]; then
    # Use an environment variable so spaces/quotes in the temp path stay literal.
    SECCY_SHELL_INIT="$directory/apply" "$shell" --init-command 'source "$SECCY_SHELL_INIT"; set -e SECCY_SHELL_INIT' -i <&0 &
elif [[ $kind == bash ]]; then
    "$shell" --rcfile "$directory/bashrc" -i <&0 &
else
    ZDOTDIR="$directory" "$shell" -i <&0 &
fi
child=$!
status=0
wait "$child" || status=$?
# A trapped signal can interrupt wait before the command has actually exited.
if ! kill -0 "$child" 2>/dev/null; then child=; fi
exit "$status"
