# seccy

Config-driven Secure Enclave SSH agent and CLI, written in Rust with [usage](https://usage.jdx.dev/rust/quickstart).

- SSH authentication, including Git over SSH.
- Git commit/tag signing through OpenSSH's SSH signing format.
- `prompt`: hardware-enforced biometric authorization for private-key operations.
- `notify`: no biometric prompt; send a macOS notification identifying the key and local client executable/PID after signing.
- `--json`: machine-readable command results and errors; newline-delimited events for the foreground agent.
- `encrypt` / `decrypt`: authenticated encryption with a selected Secure Enclave key, including a fnox Lua provider.

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
| `pkgs/fnox` | fnox Lua encryption provider (not a Rust crate) |

## macOS packaging

Requires an Apple Silicon or Secure Enclave-equipped Intel Mac, a logged-in GUI user session, and enrolled Touch ID for `prompt` keys. Keys are non-exportable P-256 (`ecdsa-sha2-nistp256`); there is no software fallback or private-key import.

The data-protection keychain requires a code-signing identity and a provisioning profile authorizing the app identifier and keychain group. A plain `cargo build` is sufficient for tests and commands with an empty config, but is not a deployment build for keychain operations. See [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

Create a macOS App ID (default `fyi.seccy.cli`) and matching provisioning profile in your Apple Developer account, and install its signing certificate. Package with:

```sh
export SECCY_SIGNING_IDENTITY='Developer ID Application: Your Name (TEAMID)'
export SECCY_PROFILE='/absolute/path/to/seccy.provisionprofile'
# Set SECCY_BUNDLE_ID if using a different registered identifier.
mise run package
export PATH="$PWD/target/Seccy.app/Contents/MacOS:$PATH"
```

Run the executable **inside** the bundle; retain the bundle and embedded profile together when installing it elsewhere. Keep the same app identifier, keychain group and signing team across upgrades. Signing and provisioning credentials are not included in this repository. The package task builds and signs; it does not notarize or distribute the application.

### Notarize for another Mac

Use a Developer ID Application certificate and matching Developer ID profile.
Set these alongside the signing settings in `mise.local.toml` (see
`mise.local.toml.example`):

```toml
SECCY_APPLE_ID = "your-apple-account@example.com"
SECCY_TEAM_ID = "YOUR_TEAM_ID"
SECCY_NOTARY_PROFILE = "seccy-notary"
```

Create an app-specific password at [account.apple.com](https://account.apple.com/),
then run the one-time setup in an interactive terminal:

```sh
mise run notarize:setup
```

Enter the app-specific password when prompted, or supply it through the environment:

```sh
SECCY_APPLE_PASSWORD='xxxx-xxxx-xxxx-xxxx' mise run notarize:setup
```

You can also set `SECCY_APPLE_PASSWORD` in your local mise config or inject it
through fnox later. The setup script passes it to `notarytool --password`.
Credentials are validated and stored in Keychain under `SECCY_NOTARY_PROFILE`.
If that Keychain profile is already configured, skip setup.

For each release:

```sh
mise run notarize
```

This builds and signs the app, submits a snapshot to Apple, waits for acceptance,
staples and validates the ticket, checks Gatekeeper, and produces
**`target/Seccy-notarized.zip`**. Send that archive, rather than the original
`target/Seccy.app`, to the other Mac. The original build bundle isn't stapled;
the archive contains the stapled snapshot.

Submission results are saved in `target/notarization-result.json`; when a
submission fails, the script also attempts to download Apple's diagnostic log
to `target/notarization-log.json`. A failed run does not replace a previously
successful release archive. Notarization requires Apple's network services and
can take several minutes or longer.

## Configure and provision

Create `seccy.toml` (or pass `--config /path/to/seccy.toml`):

```toml
[user]
email = "koss@nocorp.me"

[keys.personal]
mode = "prompt"

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

Provisioning records keys in `$XDG_STATE_HOME/seccy/state.toml` (default
`~/.local/state/seccy/state.toml`). Each record retains its mode, public identity,
email/comment, and absolute source `config` path. `list`, `get`, `sync`, and
`provision` use this inventory even when the original config is unavailable.
The current `./seccy.toml` (or `--config` file) contributes additional entries;
registered entries take precedence. Missing config files contribute no entries.
Malformed or unreadable configs remain errors for commands that consume them.
With neither registry entries nor config entries, results are empty.

`list` and `get` report `status` (`provisioned` or `not_provisioned`), `mode`, `public_key_path`, `public_key`, `fingerprint`, `synced`, and `config` (also shown in the Config column). Source paths are absolute, shortened to `~/…` when inside home. Provisioned registered keys show their provisioning source. Unprovisioned keys show the current config when it defines them, otherwise their recorded source. Missing key material is reported as null rather than failing the command. Actual keychain access errors remain errors. The agent advertises only provisioned, registered keys.

Provisioning is idempotent by key name and mode, within the signed app's keychain group. It creates missing keys and persists their public files and registry records. Run `provision` once with each existing config to register keys created by older versions; existing private keys are reused. `sync` writes missing/outdated public files for existing keys without creating private keys; unprovisioned keys are reported and skipped. Public-key comments use `[user].email`, or the key name when email is absent. Updating the source email and running `provision` updates the stored comment, not the private key or fingerprint. Identical public files are left untouched; replacements and registry writes are atomic.

Changing a registered key's mode or provisioning the same name from another
config is rejected. Choose another name, or explicitly remove the old key first.
A failed multi-key provision may have completed earlier keys; rerun it to finish.
Removing an entry from a source config does not remove it from the registry.
If a registered private key is missing, `list` reports `not_provisioned` and
`provision` creates a replacement. That replacement has a new identity and cannot
decrypt ciphertext encrypted for the old key. A missing `.pub` file alone is
recreated from the existing private key by `sync` or `provision`.

```sh
seccy remove personal        # asks for confirmation, default No
seccy remove personal -y     # --yes also skips confirmation
seccy reset                 # asks before deleting all seccy-managed keys
seccy reset --yes
```

Removal deletes private-key material, exported public files, and registry entries.
Reset also discovers orphaned seccy-labelled Keychain keys and exported public
files. Both preserve source configs, logs, and service registration. A key still
in the current config appears as unprovisioned after removal. Non-interactive
invocations require `-y`/`--yes`; prompts go to stderr, preserving JSON stdout.
Mutations take an exclusive registry lock; if a key operation is in flight,
retry after it finishes.

The agent uses only the internal registry, not source configs. It checks file
metadata before each request and reparses only after changes; provisioning and
removal take effect without restarting, including on existing SSH connections.
Malformed registry updates fail requests rather than serving stale identities.

With `LOG_LEVEL=debug` (or `trace`), inventory commands record the full registry
as JSON, including stored absolute source paths, so it can be compared with the
displayed inventory. Events in the normal JSON log file are:

- `state_loaded`: persisted `state_json` before merging the current config.
- `inventory_view`: merged `state_json`, plus `config_json` and `config_path`.
- `inventory_result`: the command's exact structured output as `result_json`.
- `state_saved`: `state_json` after a successful registry write (including
  provision/remove/reset changes).
- `state_cache_hit`: the agent reused an unchanged parsed registry.

These JSON fields are encoded as strings, like `caller_json`. For example:

```sh
LOG_LEVEL=debug seccy list
jq 'select(.fields.event == "state_loaded") | .fields.state_json | fromjson' \
  "${XDG_STATE_HOME:-$HOME/.local/state}/seccy/logs/seccy.jsonl"
```

Debug records go to the log file, not command stdout. Registry snapshots contain
public identities and configuration metadata, not private keys or secret payloads.

### Query command output

Every command supporting `--json` also accepts global `--jq '<jq expression>'`.
The query overrides `--json` and runs against the same complete JSON response,
using the embedded jaq interpreter and its standard library:

```sh
seccy list --jq '.keys[] | {name, status, config}'
seccy get personal --jq '.key.fingerprint'
seccy get personal --jq-raw '.key.public_key'
seccy service status --jq '.running'
seccy agent --jq 'select(.event == "signed") | .key'
```

Use `--jq-raw '<expression>'` instead of `--jq` for jq-style raw output: string
results are printed without quotes or JSON escaping, followed by a newline.
Other values remain JSON. Both options override `--json` and cannot be combined.

Results from `--jq` use jq-style pretty-printed JSON: strings remain quoted, each result is
written separately, and `empty` / unmatched `select` produce no output. Agent
events are filtered individually. Decryption queries receive `value_base64`,
just like `--json`. Help and command-error JSON responses can also be queried.
Command failures retain their nonzero exit status; `false`, `null`, or no query
results do not themselves cause failure. Query syntax/compilation errors fail
before the command runs; evaluation errors go to stderr and exit nonzero (earlier
results may already have been written). Queries affect output, not command actions.

### XDG storage

| Item | Path | Default |
| --- | --- | --- |
| Public keys | `$XDG_DATA_HOME/seccy/keys/<name>.pub` | `~/.local/share/seccy/keys/<name>.pub` |
| Agent socket | `$XDG_RUNTIME_DIR/seccy/agent.sock` | When unset: `$XDG_STATE_HOME/seccy/agent.sock`, default `~/.local/state/seccy/agent.sock` |
| Key registry | `$XDG_STATE_HOME/seccy/state.toml` | `~/.local/state/seccy/state.toml` |
| Secrets socket | Alongside the agent socket, named `secrets.sock` | `~/.local/state/seccy/secrets.sock` when runtime/state overrides are unset |
| Provision/sync lock | `$XDG_STATE_HOME/seccy/provision.lock` | `~/.local/state/seccy/provision.lock` |

Relative XDG values are ignored, as required by the XDG specification. Socket and lock directories are owner-only. Existing `~/.seccy` sockets are no longer used. Public files can be regenerated with `sync`; private keys remain in the keychain. The config path still defaults to `./seccy.toml`.

Touch ID uses `biometryCurrentSet` plus `privateKeyUsage`: password fallback is not enabled, and changing enrolled fingerprints invalidates access. Notification-only keys use `privateKeyUsage`. Both modes require an unlocked device and use device-only keychain protection.

Notifications are submitted via `/usr/bin/osascript`; enable notifications for that sender in macOS. macOS notification settings and Focus can suppress banners. Failure to submit a notification causes the agent to withhold the signature. Agent events also record successful signature responses.

Both notifications and Touch ID's custom authentication reason include the key
name/fingerprint/mode, signature algorithm, payload size, client executable/PID,
socket-peer UID/GID, and available process metadata and ancestry. macOS can
truncate long UI text; the file log contains the complete metadata. Each Touch ID
operation uses a fresh `LAContext` with biometric reuse disabled and the reason
attached to the actual keychain signing operation.

### File logging and payload inspection

`LOG_LEVEL` accepts `off`, `error`, `warn`, `info` (default), `debug`, or `trace`.
Logs are appended as JSON Lines to:

```text
$XDG_STATE_HOME/seccy/logs/seccy.jsonl
# Default: ~/.local/state/seccy/logs/seccy.jsonl
```

The directory is private (`0700`) and the log file is `0600`. Logs are separate
from CLI stdout, so `--json` keeps its existing contract. The file is append-only
and is not automatically rotated; stop the agent before moving/removing it.

```sh
LOG_LEVEL=debug seccy agent --json
tail -f ~/.local/state/seccy/logs/seccy.jsonl
```

At `info`, signing requests record the key, algorithm, flags, byte count, SHA-256
digest (base64), and `caller_json`: a JSON-encoded snapshot with peer PID/path,
peer UID/GID, process name, effective/real UID/GID, parent PID, process group,
start time, and up to 16 observed ancestors. Missing process details are null or
absent from the ancestor list. The snapshot is refreshed for each request, with
a start-time comparison to detect reuse of a previously observed peer PID.

Each process and ancestor also has a `details` object:

- Working directory from `PROC_PIDVNODEPATHINFO`, controlling terminal device
  number and terminal foreground process group.
- Containing app bundles (including nested helpers), with names, bundle IDs,
  versions, builds, executable and icon filenames from their `Info.plist` files.
  This is filesystem metadata, not a window association or an assertion that
  all bundle resources were validated.
- Dynamic code-signing metadata selected by PID: signing identifier, team ID,
  certificate subject names, code format/flags, ad-hoc and hardened-runtime flags,
  and the code-directory hash. `validation_status` is the OSStatus from default
  dynamic identity validation (zero means success). This is not a notarization
  assessment or proof that the application authorized a request. An ad-hoc
  signature may validate without identifying a developer.
- Conservative interpretations of `git`, `ssh`, and `ssh-keygen` arguments:
  Git subcommand and `-C`/`--git-dir`/`--work-tree` context; SSH destination argument,
  explicit `-l` username and `-p` port; `ssh-keygen -Y` operation.
- Repository candidates discovered from the working directory and `.git`
  directory/worktree markers, or explicit Git directory arguments. These are
  candidates: environment overrides, SSH configuration, aliases, and wrappers
  can change actual behavior. No Git commands or hooks are executed to inspect them.
- Collection source, timestamp, elapsed milliseconds, and notes for unavailable,
  denied, malformed, or oversized data. If the observed process's start time or
  executable changes during inspection, its enriched snapshot is discarded.

With `LOG_LEVEL=debug` or `trace`, `details.arguments` contains the complete
UTF-8 argv array when available. At other levels it is omitted, although selected
interpreted arguments remain. The parser stops after the kernel-reported argument
count and never includes trailing process environment entries. Argument arrays
can contain secrets passed on a command line. Non-UTF-8 or oversized argument
buffers are reported as unavailable rather than silently altered.

Collection is read-only, with bounded buffers, file sizes, and ancestry depth;
individual OS/filesystem calls are synchronous, not subject to a hard timeout.
It does not use Accessibility, window enumeration, screenshots, or automation
permissions. Full metadata is in `caller_json`; prompts show the useful observed
context and may be truncated by macOS.

At `debug`/`trace`, a `sign_payload` event additionally contains the **exact bytes
passed to the signing backend**, encoded as base64 in `fields.payload`, and a
UTF-8 representation when valid. This includes requests that are later cancelled
or fail. Private key material is never exported or logged. Debug payloads can
contain authentication/signing context; use `info` to omit the raw bytes.

For example, extract the latest payload using `jq` and macOS `base64`:

```sh
jq -r 'select(.fields.event == "sign_payload") | .fields.payload' \
  ~/.local/state/seccy/logs/seccy.jsonl | tail -n 1 | base64 -D > payload.bin
hexdump -C payload.bin
```

The `sign` span carries `agent_pid` and `request_id` to correlate request,
payload, backend failure, and signature-creation events. `signature_created`
means the backend produced a signature; `signature_delivered` means it was
written to the client socket. Neither proves a server accepted authentication.

### Decoded signing context and known hosts

Prompts, notifications, and the `sign_requested` log's `payload_json` field
include a best-effort decoding of the request:

- **SSH authentication:** remote username, service, method, algorithm, session
  identifier (in logs), and the server host-key algorithm/fingerprint when the
  request uses OpenSSH host-bound authentication.
- **SSH signatures:** namespace (for example, `git`), hash algorithm, and the
  document digest (in logs). The repository, commit message, and document content
  cannot be recovered from that digest.
- **Unknown:** malformed, unsupported, or opaque payloads retain the generic
  signing description. Decoding doesn't change the bytes signed or reject an
  otherwise valid agent signing request.

For host-bound requests, seccy matches the **entire embedded host public key**
against `~/.ssh/known_hosts`, `~/.ssh/known_hosts2`, `/etc/ssh/ssh_known_hosts`, and
`/etc/ssh/ssh_known_hosts2`. Matching names/patterns, source files, and line numbers
are shown. Multiple aliases and `[host]:port` entries are preserved. Hashed-host
entries can be recognized by their public key, but their hostnames cannot be
recovered. `@revoked` matches are explicitly labeled; `@cert-authority` entries
are not treated as direct server-key matches.

These are local **key associations**, not proof of the actual destination:
payloads are client-supplied and one server key may be shared by many hosts.
This lookup does not replace SSH's host-key verification. No DNS or network
lookups are performed, and seccy does not parse `ssh_config` or run its commands.
For custom known-hosts locations, set a colon-separated list of absolute paths:

```sh
SECCY_KNOWN_HOSTS="$HOME/.ssh/known_hosts:/path/to/company_known_hosts" \
  seccy agent
```

This replaces the default list (up to 16 files). Missing files are ignored;
unreadable/non-regular files and files larger than 4 MiB are skipped with lookup
notes. At most 64 key matches are retained. Files are reread for each request.

macOS controls the Touch ID window's layout, typography, size, and biometric
controls. `LAContext` lets us set the reason and cancel/fallback labels and control
authentication reuse. It does not provide custom fields or extra action buttons.
The application name/icon come from the app bundle. Long descriptions may be
truncated by macOS; logs retain the complete decoded information.

## SSH / Git transport

In another terminal:

```sh
if [ -n "$XDG_RUNTIME_DIR" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/seccy/agent.sock"
else
    export SSH_AUTH_SOCK="${XDG_STATE_HOME:-$HOME/.local/state}/seccy/agent.sock"
fi
ssh-add -L
```

Set `SSH_AUTH_SOCK` to the socket path from the agent's `ready` event. With the default macOS fallback, use `export SSH_AUTH_SOCK="$HOME/.local/state/seccy/agent.sock"`. Register `~/.local/share/seccy/keys/personal.pub` (or its XDG override) with your SSH server or Git hosting provider. Optionally select a particular key in `~/.ssh/config` (these paths assume the default macOS fallback):

```sshconfig
Host github.com
    IdentityAgent ~/.local/state/seccy/agent.sock
    IdentityFile ~/.local/share/seccy/keys/personal.pub
    IdentitiesOnly yes
    ForwardAgent no
```

The agent runs in the foreground until SIGINT/SIGTERM. `--socket` supports another location whose parent is also owner-only. Concurrent agents cannot own the same socket; a stale socket can be recovered on restart.

### Start automatically at login

Place the complete signed app at a permanent location (for example,
`/Applications/Seccy.app`), provision your configs, then run:

```sh
/Applications/Seccy.app/Contents/MacOS/seccy service install
seccy service status
seccy service restart
seccy service uninstall
```

Installation writes `~/Library/LaunchAgents/fyi.seccy.agent.plist` and starts the
agent in your GUI login session. launchd starts it at subsequent logins and
restarts it on exit, throttled to avoid rapid restart loops. Stop a manually
running agent before installing the service. Installation must run from the
bundled executable; keep the app at that location or reinstall the service after
moving it. No source config is needed by the service.

The plist captures the resolved storage/socket paths and optional `LOG_LEVEL`
and `SECCY_KNOWN_HOSTS` values at installation. Reinstall to change these settings;
launchd does not inherit shell startup files. Bootstrap stdout/stderr are in
`~/.local/state/seccy/logs/service.{stdout,stderr}.log` alongside normal JSON logs
(respecting `XDG_STATE_HOME`). Configure `SSH_AUTH_SOCK` or `IdentityAgent` in your
clients as above. Uninstall stops the service and removes its plist, retaining
keys and state. These commands also support `--json`.

## GitHub key sync

Mark keys for GitHub authentication or signing in your config:

```toml
[keys.personal]
mode = "prompt"
github = "signing"

[keys.work]
mode = "notify"
github = "auth"
```

Authenticate the GitHub CLI with SSH as the Git protocol, skip SSH key generation,
and authorize management of both authentication and signing keys:

```sh
gh auth login \
    --hostname github.com \
    --git-protocol ssh \
    --skip-ssh-key \
    --scopes admin:public_key,admin:ssh_signing_key
```

If already authenticated, add the required permissions:

```sh
gh auth refresh -h github.com -s admin:public_key
gh auth refresh -h github.com -s admin:ssh_signing_key
```

Both scopes are required because sync lists and reconciles both key types.
Missing scopes can produce `404 Not Found` responses from these endpoints.
Provision your keys, then run:

```sh
seccy gh sync
seccy gh sync --yes
seccy gh sync --cmd 'mise x gh@latest --' -y
```

Sync lists both GitHub key types and manages titles matching
`<whoami>@<hostname>/seccy/<key>`. It removes stale, duplicate, changed, or
wrong-type entries and adds missing keys. Public-key comments do not affect
matching. The plan is printed before confirmation, including with `-y`/`--yes`.
An unprovisioned selected key stops sync before remote changes.

Only keys with `github = "signing"` or `github = "auth"` are selected. The current
config's GitHub settings override registered settings; provisioning persists them
for use when the source config is unavailable. `--cmd` accepts a shell-quoted
command prefix, without shell expansion. Successful gh stdout is captured;
failed gh stdout and stderr are forwarded verbatim and the command exits nonzero.
The command also supports seccy's `--json` and `--jq`; plans go to stderr.

## Git commit signing

Requires Git 2.34+ and OpenSSH with SSH signing support. Register the public key as a **signing key** with your Git hosting provider too.

```sh
export SSH_AUTH_SOCK="$HOME/.local/state/seccy/agent.sock" # or your XDG runtime socket
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

## Encryption and fnox

seccy uses Apple's **ECIES P-256 / X9.63 SHA-256 / AES-GCM** implementation.
Encryption uses the public key without Touch ID. Decryption uses the private key
in the Secure Enclave, with the same `prompt` or `notify` policy as signing.
Existing keys can be selected; a dedicated key makes secret-key rotation independent
of SSH key rotation:

```toml
# Add to your seccy.toml
[keys.secrets]
mode = "prompt"
```

Build/package the updated signed application as described above, then provision
and start its agent (or use the login service above):

```sh
seccy --config "$HOME/.config/seccy/seccy.toml" provision
seccy agent
```

The agent opens both SSH and secrets sockets. Private-key operations share one
lock, so SSH and decryption prompts are serialized. `--socket` on `agent` selects
the SSH socket; the secrets socket is always `secrets.sock` in the same directory.
Its path is included as `secrets_socket` in the JSON `ready` event.

### CLI

```sh
seccy --config "$HOME/.config/seccy/seccy.toml" encrypt secrets < secret.txt > secret.enc
seccy decrypt secrets < secret.enc > recovered.txt
seccy crypto-check secrets --json
```

`encrypt` reads up to 64 KiB of arbitrary bytes from stdin and emits one versioned
`seccy:v1:...` ciphertext string. It requires the configured, provisioned key but
does not require a running agent. `decrypt` reads ciphertext from stdin and writes
the exact plaintext bytes without adding a newline. It uses the running agent's
configured keys; `--config` does not change the agent's configuration. Both
`decrypt` and `crypto-check` accept `--socket /absolute/path/to/secrets.sock`.

`crypto-check` verifies agent connectivity, key presence, and ECIES capability
without decrypting or prompting. To verify actual private-key authorization, run
the round-trip above and compare with `cmp secret.txt recovered.txt`; repeat the
decryption to check fresh Touch ID prompts, and cancel a prompt to verify failure.

JSON encryption returns `{"ok":true,"value":"seccy:v1:..."}`. JSON decryption
returns `{"ok":true,"value_base64":"..."}` to preserve binary data and trailing
newlines. Ciphertext includes its recipient fingerprint: a replacement key with
the same name cannot decrypt old values.

### fnox setup

Use **fnox 1.47.0 or newer**, with the Lua provider API described in the
[fnox documentation](https://fnox.jdx.dev/providers/lua.html). Install the plugin
from the source embedded in the Rust binary, then link it in place:

```sh
seccy fnox init
fnox plugin link seccy "$(seccy fnox info --jq-raw .plugin_dir)"
```

`init` writes `provider.lua` to `~/.local/share/seccy/fnox`, or
`$XDG_DATA_HOME/seccy/fnox` when `XDG_DATA_HOME` is absolute. It works with a
standalone binary and needs no source checkout or app resources. Run it again
after upgrading seccy to replace the installed plugin with the embedded version.
Installation also writes `metadata.json` beside `provider.lua`, recording the
version from the CLI crate’s Cargo manifest (embedded at compile time).

`seccy fnox info` first checks for the installed provider in that directory,
then falls back to `Seccy.app/Contents/Resources/fnox`. Bundle paths are resolved
from the running executable, including symlink invocation. If neither copy
exists, it reports an error suggesting `seccy fnox init`.

Both commands support `--json`, `--jq`, and `--jq-raw`; JSON contains `ok`,
`plugin_dir`, `provider_path`, `version` (the selected plugin), and `binary_version`
(the running CLI). Installed plugin versions are read from `metadata.json`;
older installations without metadata report `version: null` until `init` is run
again. The bundled plugin uses the binary’s version. Malformed metadata reports
an error with instructions to repair it using `init`. Neither command requires
a secrets configuration.
When linking the in-app copy without running `init`, keep the app at a stable
location or link again after moving it.

For local development, link the source checkout instead:

```sh
fnox plugin link seccy /absolute/path/to/seccy/pkgs/fnox
```

Add this to `fnox.toml` (replace paths with your actual installation paths):

```toml
default_provider = "seccy"
if_missing = "error"
env = "exec"

[providers.seccy]
type = "lua"
plugin = "seccy"
daemon_cache = false

[providers.seccy.options]
key = "secrets"
bin = "/absolute/path/to/Seccy.app/Contents/MacOS/seccy"
config = "/absolute/path/to/seccy.toml"
# Optional, when the agent uses a custom secrets socket:
# socket = "/absolute/path/to/secrets.sock"
```

Alternatively set `plugin = "/absolute/path/to/Seccy.app/Contents/Resources/fnox"`
directly, using the directory printed by `seccy fnox info --jq-raw .plugin_dir`.
`bin` defaults to `seccy` on PATH. Use absolute `bin`, `config`, and `socket` option
paths: Lua option paths do not receive fnox's config-relative path resolution or
shell `~` expansion. The executable must stay inside its signed app bundle.

```sh
fnox provider test seccy
fnox set API_TOKEN --provider seccy --from-file /path/to/token.txt
fnox exec -- ./your-app
```

fnox stores ciphertext in its config. The plugin passes data through stdin and
JSON stdout, never shell interpolation or secret-bearing command arguments.
Batch reads run sequentially; **each secret decryption requires its own Touch ID
authorization** for `prompt` keys. Keep `daemon_cache = false` to prevent later
commands receiving cached plaintext without a fresh key operation. Avoid fallback
defaults for secrets that must fail when authorization fails.

Decryption audit events include the key and local caller metadata, never plaintext
or encryption keys, even at debug/trace. fnox and the launched program necessarily
receive plaintext after authorization. Notification-only keys retain their existing
same-user access model. The immediate socket client is seccy; fnox appears in
best-effort process ancestry.

**Recovery:** this initial format has a single recipient. Loss of the Mac/key or
invalidation by biometric enrollment changes makes its ciphertext unrecoverable.
Keep a separate source of truth for secrets, and reencrypt while the old key is
still usable when rotating. There is no private-key export or recovery recipient.

Adapter tests can be run with `lua pkgs/fnox/test.lua` (or `luajit`). Rust tests
exercise ECIES with ephemeral software test keys; Secure Enclave ACLs, Touch ID,
and notification delivery must also be checked with the signed app on hardware.

## JSON contract

`--json` works before or after a subcommand. Successes have `"ok":true`; failures have `"ok":false` and `"error"`. Command results are a single JSON object on stdout. Exit status is 0 for success, 1 for operational errors, 2 for CLI parse errors. Help/version requests in JSON mode return a `text` field.

```json
{"ok":true,"keys":[{"name":"personal","mode":"prompt","status":"not_provisioned","public_key_path":"/Users/you/.local/share/seccy/keys/personal.pub","public_key":null,"fingerprint":null,"synced":false}]}
```

Agent stdout is JSON Lines with `ready`, `signed`, and `request_error` events; SSH protocol bytes travel only over the socket. A `signed` event includes the local client's executable and PID. It means a signature was returned, not that a remote server accepted it.

## Scope and verification

The kernel identifies the immediate local socket client, usually `ssh` for authentication and `ssh-keygen` for commit signing. Process ancestry is a best-effort OS snapshot, not proof that a parent terminal or IDE authorized the request; processes may exit, reparent, or exec. Names/paths, code-signing observations, argument-derived context, and repository candidates are reported separately with their sources. Neither ancestry nor a focused application establishes a remote destination or forwarded application's identity. A forwarded agent connection can only be attributed to its local forwarding process. Forwarding constraints and session-binding extensions are not implemented.

The agent accepts same-user clients, advertises only registered provisioned keys, bounds frames/connections, serializes signing prompts, and rejects key mutation requests over its sockets. A process running as your user can request signatures from notification-only keys; this mode is notification, not per-application authorization.

Tests cover config rejection, malformed/truncated/oversized requests, signing flags, unknown keys, CLI JSON errors, and real `ssh-add` plus a Git signed commit verified by OpenSSH. Protocol tests use an isolated software **test** key. Secure Enclave persistence, repeated Touch ID prompts/cancellation, notification delivery, and signed packaging must also be checked interactively on provisioned hardware; the automated tests do not establish those behaviors.
