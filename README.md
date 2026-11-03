# seccy

Config-driven Secure Enclave SSH agent and CLI, written in Rust with [usage](https://usage.jdx.dev/rust/quickstart).

- SSH authentication, including Git over SSH.
- Git commit/tag signing through OpenSSH's SSH signing format.
- `touchid`: hardware-enforced biometric authorization for private-key operations.
- `notify`: no biometric prompt; send a macOS notification identifying the key and local client executable/PID after signing.
- `--json`: machine-readable command results and errors; newline-delimited events for the foreground agent.

## Build

```sh
mise install
mise run build
mise run check
mise run test
mise run run -- --help
mise run run -- list --json
```

Workspace:

| Crate | Responsibility |
| --- | --- |
| `pkgs/core` / `seccy_core` | Strict TOML config, key-store interface, SSH wire protocol and public-key encoding; portable to Linux |
| `pkgs/macos` / `seccy_macos` | Security.framework Secure Enclave access, biometric ACLs, notifications, socket peer identification |
| `pkgs/cli` / `seccy_cli` | `seccy` executable, usage command definitions, JSON output, Unix socket agent |

## macOS packaging

Requires an Apple Silicon or Secure Enclave-equipped Intel Mac, a logged-in GUI user session, and enrolled Touch ID for `touchid` keys. Keys are non-exportable P-256 (`ecdsa-sha2-nistp256`); there is no software fallback or private-key import.

The data-protection keychain requires a code-signing identity and a provisioning profile authorizing the app identifier and keychain group. A plain `cargo build` is sufficient for tests and commands with an empty config, but is not a deployment build for keychain operations. See [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

Create a macOS App ID (default `fyi.seccy.cli`) and matching provisioning profile in your Apple Developer account, and install its signing certificate. Package with:

```sh
export SECCY_SIGNING_IDENTITY='Apple Development: Your Name (TEAMID)'
export SECCY_PROFILE='/absolute/path/to/seccy.provisionprofile'
# Set SECCY_BUNDLE_ID if using a different registered identifier.
mise run package
export PATH="$PWD/target/Seccy.app/Contents/MacOS:$PATH"
```

Run the executable **inside** the bundle; retain the bundle and embedded profile together when installing it elsewhere. Keep the same app identifier, keychain group and signing team across upgrades. Signing and provisioning credentials are not included in this repository. The package task builds and signs; it does not notarize or distribute the application.

## Configure and provision

Create `seccy.toml` (or pass `--config /path/to/seccy.toml`):

```toml
[user]
email = "koss@nocorp.me"

[keys.personal]
mode = "touchid"

[keys.automation]
mode = "notify"
```

```sh
seccy provision --json
seccy list --json
seccy get personal --json
seccy sync --json
seccy agent --json
```

Missing `seccy.toml` (including an explicitly selected missing file) means an empty configuration. `list`, `sync`, and `provision` return empty key arrays; `get` returns `key: null` for an unknown name. An empty agent still runs and advertises zero identities. Malformed or unreadable config files remain errors.

`list` and `get` report `status` (`provisioned` or `not_provisioned`), `mode`, `public_key_path`, `public_key`, `fingerprint`, and `synced`. Missing key material is reported as null rather than failing the command. Actual keychain access errors remain errors. The agent advertises only provisioned keys.

Provisioning is idempotent by key name and mode, within the signed app's keychain group. It creates missing keys and persists their public files. `sync` writes missing/outdated public files for existing keys without creating private keys; unprovisioned keys are reported and skipped. Public-key comments use `[user].email`, or the key name when email is absent. Updating the email and running `sync` changes only the comment, not the key or fingerprint. Identical files are left untouched; replacements are atomic.

Changing an existing key's mode is rejected: choose a new name and register its public key to rotate. A failed multi-key provision may have created earlier keys; rerun it to finish. Removing a key from config stops advertising it after the agent restarts but retains the keychain item and public file. Config is loaded at startup, not live-reloaded.

### XDG storage

| Item | Path | Default |
| --- | --- | --- |
| Public keys | `$XDG_DATA_HOME/seccy/keys/<name>.pub` | `~/.local/share/seccy/keys/<name>.pub` |
| Agent socket | `$XDG_RUNTIME_DIR/seccy/agent.sock` | When unset: `$XDG_CACHE_HOME/seccy/run/agent.sock`, default `~/.cache/seccy/run/agent.sock` |
| Provision/sync lock | `$XDG_STATE_HOME/seccy/provision.lock` | `~/.local/state/seccy/provision.lock` |

Relative XDG values are ignored, as required by the XDG specification. Socket and lock directories are owner-only. Existing `~/.seccy` sockets are no longer used. Public files can be regenerated with `sync`; private keys remain in the keychain. The config path still defaults to `./seccy.toml`.

Touch ID uses `biometryCurrentSet` plus `privateKeyUsage`: password fallback is not enabled, and changing enrolled fingerprints invalidates access. Notification-only keys use `privateKeyUsage`. Both modes require an unlocked device and use device-only keychain protection.

Notifications are submitted via `/usr/bin/osascript`; enable notifications for that sender in macOS. macOS notification settings and Focus can suppress banners. Failure to submit a notification causes the agent to withhold the signature. Agent events also record successful signature responses. No signing payloads or private material are logged.

## SSH / Git transport

In another terminal:

```sh
if [ -n "$XDG_RUNTIME_DIR" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/seccy/agent.sock"
else
    export SSH_AUTH_SOCK="${XDG_CACHE_HOME:-$HOME/.cache}/seccy/run/agent.sock"
fi
ssh-add -L
```

Set `SSH_AUTH_SOCK` to the socket path from the agent's `ready` event. With the default macOS fallback, use `export SSH_AUTH_SOCK="$HOME/.cache/seccy/run/agent.sock"`. Register `~/.local/share/seccy/keys/personal.pub` (or its XDG override) with your SSH server or Git hosting provider. Optionally select a particular key in `~/.ssh/config` (these paths assume the default macOS fallback):

```sshconfig
Host github.com
    IdentityAgent ~/.cache/seccy/run/agent.sock
    IdentityFile ~/.local/share/seccy/keys/personal.pub
    IdentitiesOnly yes
    ForwardAgent no
```

The agent runs in the foreground until SIGINT/SIGTERM. `--socket` supports another location whose parent is also owner-only. Concurrent agents cannot own the same socket; a stale socket can be recovered on restart.

## Git commit signing

Requires Git 2.34+ and OpenSSH with SSH signing support. Register the public key as a **signing key** with your Git hosting provider too.

```sh
export SSH_AUTH_SOCK="$HOME/.cache/seccy/run/agent.sock" # or your XDG runtime socket
git config --global gpg.format ssh
git config --global user.signingkey "${XDG_DATA_HOME:-$HOME/.local/share}/seccy/keys/personal.pub"
git config --global commit.gpgsign true
git commit -m 'Signed with Secure Enclave'
```

For local verification, create an allowed-signers file containing `your@email.example` followed by the full public-key line, then:

```sh
git config --global gpg.ssh.allowedSignersFile /absolute/path/to/allowed_signers
git verify-commit HEAD
```

## JSON contract

`--json` works before or after a subcommand. Successes have `"ok":true`; failures have `"ok":false` and `"error"`. Command results are a single JSON object on stdout. Exit status is 0 for success, 1 for operational errors, 2 for CLI parse errors. Help/version requests in JSON mode return a `text` field.

```json
{"ok":true,"keys":[{"name":"personal","mode":"touchid","status":"not_provisioned","public_key_path":"/Users/you/.local/share/seccy/keys/personal.pub","public_key":null,"fingerprint":null,"synced":false}]}
```

Agent stdout is JSON Lines with `ready`, `signed`, and `request_error` events; SSH protocol bytes travel only over the socket. A `signed` event includes the local client's executable and PID. It means a signature was returned, not that a remote server accepted it.

## Scope and verification

The kernel identifies the immediate local socket client, usually `ssh` for authentication and `ssh-keygen` for commit signing. This is not an attribution to a parent terminal, IDE, repository, remote host, or forwarded application. A forwarded agent connection can only be attributed to its local forwarding process. Forwarding constraints and session-binding extensions are not implemented.

The agent accepts same-user clients, advertises only configured keys, bounds frames/connections, serializes signing prompts, and rejects key mutation requests. A process running as your user can request signatures from notification-only keys; this mode is notification, not per-application authorization.

Tests cover config rejection, malformed/truncated/oversized requests, signing flags, unknown keys, CLI JSON errors, and real `ssh-add` plus a Git signed commit verified by OpenSSH. Protocol tests use an isolated software **test** key. Secure Enclave persistence, repeated Touch ID prompts/cancellation, notification delivery, and signed packaging must also be checked interactively on provisioned hardware; the automated tests do not establish those behaviors.
