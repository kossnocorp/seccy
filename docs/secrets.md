# Managed secrets

`seccy secrets` (alias `seccy s`) manages encrypted values using multiple public
recipients. This initial implementation is available only on macOS. Decryption
uses a provisioned Secure Enclave key through the running, signed Seccy agent.
Encryption needs only public recipients, not a local private key or running agent.

## Start

Provision a `mode = "prompt"` key with the normal Seccy configuration and start
or restart the agent using the newly built/signed application. Enroll that key:

```sh
seccy s enroll personal
seccy s set DATABASE_URL
seccy s list
seccy s get DATABASE_URL
seccy s get -g DATABASE_URL                 # ignore project definitions
seccy s get -s ~/code/project/seccy.toml DATABASE_URL
seccy s exec DATABASE_URL -- ./application
```

`enroll` without a key shows an arrow-key picker of registered prompt keys. It marks
the selected key `secrets = true` in Seccy's internal registry and adds its public
recipient to the active secrets file. `seccy list --json` and `get --json` expose
that marker. It does not create a private key, change its hardware ACL, or remove
its existing SSH functionality. Notify keys cannot be enrolled for this workflow.
Enrollment is idempotent; if writing the secrets file fails after the registry
update, rerun it. Do not edit the registry manually.

`set` without a secret name offers a picker of existing secret names. To create a
new name, specify it. Interactive input disables terminal echo. Names must be
valid environment variable names: ASCII letters, digits and underscores, starting
with a letter or underscore. Secret values are limited to 64 KiB.

```sh
seccy s set CERTIFICATE --from-file ./certificate.pem
cat ./token | seccy s set TOKEN --from-stdin
```

File/stdin input preserves arbitrary bytes and trailing newlines. Values are never
accepted as positional command-line arguments. Pickers use `/dev/tty`, keeping
stdout clean; structured output requires explicit names instead of pickers.

## Files and recipients

The user file is `$XDG_CONFIG_HOME/seccy/secrets.toml`, defaulting to
`~/.config/seccy/secrets.toml`, followed by `secrets.local.toml` beside it.
Seccy then reads `seccy.toml` and `seccy.local.toml` at each directory from
filesystem root through the current directory. At the same level the local file
wins; a closer base file overrides both files at higher levels. Local-only
directories are included. `--global-secrets PATH` (`--gs`) replaces the global
base path; `--config PATH` selects key configuration independently. The closest definition of
a secret wins over ancestors and the user file. Recipient aliases merge, but the
same alias naming different public keys is an error: use a new alias for rotation.
Each secret must reference recipients available at its defining file, rather than
relying on a descendant file to supply them.

```toml
[recipients]
macbook = "seccy-se1:<base64-uncompressed-P256-public-point>"
backup_mac = "seccy-se1:<another-public-point>"

[secrets]
DATABASE_URL = { recipients = ["macbook", "backup_mac"], value = "seccy:secrets:v1:<ciphertext>" }
```

The placeholders above are illustrative, not valid recipients. Get an actual
recipient from `enroll` or `recipients list`. A fingerprint alone cannot encrypt:
the recipient contains the public key. Lists report its SHA-256 SSH fingerprint
for out-of-band comparison. Verify recipients before adding them; anyone who can
change the configured recipients can redirect newly encrypted secrets.

By default, mutations write the nearest existing project `seccy.toml`, or create
one in the current directory. Setting an inherited secret creates an override in
that active file when there is no ambiguity. If multiple existing secrets files
are detected, mutations (`set`, `enroll`, `reencrypt`, `reset`, `remove`, and recipient
add/remove) first show an arrow-key file picker, closest file first and global last.
Each row includes recipient aliases and secret names, never values. Use Up/Down
(or j/k), then Enter; Escape or Ctrl-C cancels without changing any files. Picking
a file is exactly equivalent to passing `--secrets PATH`: only that file is loaded,
so inherited secrets and recipients are not included for that operation. Explicit
`-s` skips the picker. `-g` restricts candidates to the global base and local
companion; when both exist a mutation still needs a target. Structured output and
noninteractive invocations must select `-s`, or `-g` with only one global file. Piped `--from-stdin` values remain
untouched because selection uses the controlling terminal.

Existing comments are preserved. Public recipients referenced by a newly written
secret are copied into that file, keeping it portable.

- `-g` / `--global` reads only the global base/local pair; writes select a file within that pair.
- `-s PATH` / `--secrets PATH` reads and writes only the specified file, without global inheritance.
- Both options can appear after the subcommand; they are mutually exclusive.
  `--file` remains a compatibility alias for `--secrets`.
- Without either flag, read commands (`list`, `get`, `exec`, `recipients list`)
  always merge the full hierarchy and never ask which file to read.
- `list --json` reports the active file and the source of each effective secret.
- `reencrypt` changes only secrets defined in the active file, not inherited ones.
- `remove NAME` removes only an active-file definition; an inherited value may
  become visible again.

The files contain public metadata and ciphertext. They can be version-controlled,
but secret names and recipients are visible. Writes use a private temporary file
in the same directory, fsync and atomic replacement; the resulting mode is 0600.
Concurrent Seccy writers use private lock files in
`$XDG_STATE_HOME/seccy/secrets-locks/` (default
`~/.local/state/seccy/secrets-locks/`). Each filename is a SHA-256 hash of the
canonical parent directory plus the secrets filename, so directory aliases share
a lock even before the secrets file exists. Writers must use the same state
directory to coordinate. No lock files are created in the project directory.
The lock files are intentionally empty: the OS tracks the advisory lock and
releases it when the command exits, including after a crash. Files remain in
place to avoid races; their presence does not mean a writer holds a lock.
Detected external edits abort a write. Symlinks and foreign-owned or
group/world-writable destination files are not replaced. Configuration files
are trusted inputs: review project secrets files before executing commands with
secrets. This format has only `[recipients]` and `[secrets]`; provisioning keys
still belongs in the global `config.toml`.

## Sharing, rotation and recovery

```sh
seccy s recipients list
seccy s recipients add teammate 'seccy-se1:...'
seccy s set TOKEN --recipient macbook --recipient teammate
seccy s enroll backup --name backup_mac
seccy s reencrypt
```

By default `set` and `reencrypt` encrypt to **all effective recipients**. Use
repeated `--recipient ALIAS` to select a subset. Every selected recipient can
independently decrypt; this is not threshold encryption. The limit is 32 distinct
public keys. Two aliases for the same public key cannot both be selected.

Adding a recipient does not change old ciphertext. `reencrypt` decrypts each
active secret, then encrypts it with fresh randomness for the selected recipients.
Every decryption has its own authorization. All operations must succeed before
one atomic file replacement; cancellation leaves the original file unchanged.

```sh
seccy s reencrypt --recipient backup_mac --recipient teammate
seccy s recipients remove macbook
```

A recipient cannot be removed while referenced by an effective secret. Re-encrypt
to the remaining recipients first. To manage an ancestor/user file explicitly,
use `--secrets`/`--global`. Removing a recipient cannot revoke old ciphertext copies:
rotate the underlying credential if its previous recipient was compromised.
Enroll a second hardware recipient before losing or deleting the first device's
key. Public metadata alone cannot recover secrets. Key replacement changes the
fingerprint and does not restore access to existing ciphertext.

Decryption automatically selects a registered, explicitly enrolled prompt key
whose fingerprint occurs in the envelope. If several match, selection is
lexicographic by local key name; use `-i KEY` / `--identity KEY` to choose another. Cancellation
or failure does not silently try other identities or weaker policies.

`SECCY_IDENTITY` takes precedence over `-i` / `--identity`. The value is the logical
key handle from `[keys.<handle>]` (for example `auth2`), not a recipient alias,
fingerprint, or hardware credential ID. Selection applies to decryption in `get`,
`exec`, and `reencrypt`; it does not change encryption recipients or the key passed
to `enroll`. An empty environment value is an error; unset it to restore flag or
automatic selection. Currently the selected key must already be enrolled for
secrets on this machine.

The authorization prompt says `Decrypt secret SECRET_VAR?` and identifies the key
and requesting process chain. It never displays the secret value. Signing and SSH
authentication retain their own operation-specific prompts. Legacy decryption in
notify mode uses the notification title `seccy: secret decrypted` and completed-action
wording; managed secrets still require prompt authorization.

```sh
seccy s get SECRET_VAR -i auth2
seccy s -i auth2 get SECRET_VAR
SECCY_IDENTITY=auth2 seccy s get SECRET_VAR
```

## Output and execution

```sh
seccy s list --json
seccy s list --jq-raw '.secrets[].name'
seccy s recipients list --jq '.recipients[] | {name, fingerprint}'
seccy s get TOKEN --json
seccy s get TOKEN --jq-raw '.value_base64'
seccy s exec FIRST SECOND -- command --its-flags
seccy s x FIRST SECOND -- command --its-flags
seccy s exec -- command
```

`get` writes the exact plaintext bytes without an added newline. JSON/query output
uses `value_base64`, matching legacy `decrypt`; listing/mutation output never
includes plaintext. `--jq`, `--jq-raw` and `--jq-exit-status` work as usual.

`exec` (alias `x`) decrypts the selected secrets, or all effective secrets if no names are
provided, and adds them to the child's inherited environment. On macOS, one
batch request uses a single Touch ID authorization context with the selected
secret names in the prompt. The context is invalidated after the batch; a later
invocation requires fresh authorization. Restart the agent after upgrading to
use the batch protocol. Batches must fit the agent's 256 KiB request/response
frame limit. It starts no child
if authorization fails. NUL bytes cannot be represented in environment variables
and are rejected; other bytes are preserved on Unix. The child receives normal
stdin/stdout/stderr and its exit status/signals are preserved. `exec` does not
support structured output because stdout belongs to the child. Use `--` before
the command; flags after it belong to that command.

Environment injection deliberately exposes plaintext to the command and its
children. Seccy neither logs values nor guarantees that the invoked program will
keep them private. A scoped authorization session that initially exports no values
is future work in `TODO.md`, not part of `exec`.

## Cryptography and authorization

This is **age-style envelope encryption, not age wire-format compatibility**.
Each value gets a fresh random 256-bit file key and 96-bit nonce. Apple Security
framework ECIES (`ECIESEncryptionCofactorX963SHA256AESGCM`) wraps the file key
independently for each P-256 public recipient. AES-256-GCM encrypts the payload.
Its authenticated associated data includes the version/domain, secret name,
complete recipient/wrapped-key map, and nonce, using a canonical ordered JSON
serialization. Recipient metadata must match the configured recipient list.
Tampering, changing the secret name, or removing a recipient stanza fails
validation/authentication. File keys are never reused across secrets or rewrites.

The agent verifies the local socket peer, registry enrollment and prompt mode,
asks Secure Enclave to unwrap the file key, verifies the payload authentication,
and returns plaintext. Each request creates a fresh authentication context; the
prompt includes the requested secret name and caller information. The displayed
name is request context until payload authentication succeeds, not proof of a
trusted sender. Public-key encryption provides confidentiality and integrity,
not sender authentication. No long-lived private key is exported. Temporary file
keys and plaintext necessarily exist in host memory; sensitive working buffers
are erased where practical, not guaranteed absent from every OS/library copy.

Legacy `encrypt`, `decrypt`, fnox integration and their ciphertext formats remain
available. This initial managed-secrets format supports Secure Enclave recipients
only; Linux returns an explicit unsupported-platform error.

Automated tests exercise Apple's ECIES with ephemeral software test keys,
multi-recipient payload authentication, public-only CLI encryption, discovery,
atomic writes and mock-agent routing. They do **not** establish physical Secure
Enclave/Touch ID behavior. Before release, verify the signed app on hardware:
enroll two prompt keys, encrypt without an agent, restart the new agent, decrypt
with each key, cancel a prompt, and confirm re-encryption leaves the file intact
on cancellation. Test malformed requests and verify notify/unenrolled keys are
rejected without private operations.

## Touch ID changes and recovery

Older Seccy prompt keys, and new keys explicitly configured with
`verify = "biometry-current-set"`, use Apple's
[`biometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset).
Adding **or removing** a fingerprint invalidates keys protected with this policy.
Removing the newly added finger, restarting the agent, or entering a password
does not restore an invalidated key. Secure Enclave private keys
[cannot be exported or imported](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
New prompt keys default to `verify = "biometry-any"`, which survives fingerprint
enrollment changes. `verify = "user-presence"` additionally permits system password
fallback. These creation-time settings never modify an existing key. Set `verify`
in the key or its provider profile and run `seccy rebuild NAME` to create a new
generation using that policy; see [provider configuration](providers.md).

CryptoTokenKit `-3` means corrupted data, not definitive evidence of changed
enrollment. Seccy therefore reports enrollment changes as a possible cause,
preserves the underlying error, and sends a rate-limited notification on relevant
prompt-key failures. Cancellation is not classified as invalidation. Notify-mode
keys do not use the current-biometric-set policy.

Apple Passwords/iCloud Keychain passkeys have a different lifecycle:
[they can sync across approved devices](https://support.apple.com/en-us/109016).
They are not Seccy's non-exportable, device-bound keys with this enrollment ACL;
adding a fingerprint does not imply your synced passkeys were destroyed.

Inspect before replacing values:

```sh
seccy crypto-check secrets --verify
```

Inspect recipients directly in `seccy.toml` or `secrets.toml`. A listed recipient
does not prove its private key still works. If a secret has only one recipient
and its key is invalidated, its value must be re-entered. With multiple recipients,
a working private key on another machine can recover and re-encrypt the value.

Create replacement keys **using the same logical names**:

```sh
seccy rebuild                 # confirms once before rebuilding all active keys
# Or rebuild one key:
# seccy rebuild secrets
seccy gh sync
seccy secrets enroll secrets --global
seccy crypto-check secrets --verify
```

Rebuilding asks before switching aliases (`--yes` skips confirmation).
With no name it lists and rebuilds all active registered keys, excluding retired
generations; each keeps its mode unless `--mode` is given. Completed replacements
are saved individually. If a later key fails, inspect inventory and retry only
remaining keys by name.
It retains previous generations under their full SHA-256 key IDs and preserves
their enrollment for old ciphertext. SSH/signing use the active generation;
old public-key registrations on servers must be updated. The agent reloads the
registry automatically. Start/restart it after installing this updated version.

Enrollment preserves existing recipient mappings. If `secrets` already names
the old public recipient, enrollment automatically uses the new full key ID as
the recipient alias and prints it. An explicit `--name replacement` is also
available. Copy the emitted public recipient to the recovery machine using
`seccy secrets recipients add replacement <public-recipient>`.

If another recipient can decrypt, run on that machine:

```sh
seccy secrets reencrypt --secrets ./seccy.toml --recipient replacement --identity working-key
```

Select all recipients you want to keep with repeated `--recipient` flags.
Distribute the re-encrypted file back to the rebuilt machine and verify it there.
For local retained generations, automatic selection matches ciphertext
fingerprints and prefers active matching generations. `--identity secrets`
can select a retained generation of that alias when only that generation matches;
`--identity <retired-key-id>` selects it explicitly. A failed authorization does
not silently try other identities. Preserve old generations until all files and
backups that need them have been considered.

If no recipient can decrypt, replace every value in the selected file:

```sh
seccy secrets reset --global --recipient replacement
seccy secrets reset TOKEN --global --recipient replacement
seccy secrets reset --secrets ./seccy.toml --recipient replacement
```

To read one replacement value from an environment variable:

```sh
seccy secrets reset TOKEN --global --recipient replacement --from-env NEW_TOKEN
```

This reads `NEW_TOKEN` from the command's environment; an unset variable is an
error, and an empty value is preserved. `--from-env` requires a secret name.
Confirmation is still required unless `--yes` is supplied. `SECCY_IDENTITY`
selects decryption identities and does not select reset's encryption recipients.

Use the recipient alias printed by enrollment in place of `replacement`.
`reset` requires explicit recipients, confirms replacement, and prompts without
echo for each selected secret. Pass a secret name to replace only that definition;
omit it to replace every secret in the active file. It does not need the old private key or
running agent. All prompts and encryptions must succeed before a single atomic
file replacement; cancellation, an encryption failure, or a detected concurrent
edit preserves the original file. Only the active file's definitions are reset,
not inherited definitions. `--global` and `--secrets PATH` work before or after
the subcommand and are mutually exclusive. No plaintext is logged or written
to temporary files. For binary/multiline values, use `secrets set NAME --from-file`
individually instead of the line-oriented reset prompt.

Single-recipient `seccy:v1:` ciphertext from `seccy encrypt` has no alternative
recipient or named-secret inventory. If its key is invalidated, recover the value
from its original source and encrypt it again. `secrets reset` operates on managed
`seccy:secrets:v1:` files only.
