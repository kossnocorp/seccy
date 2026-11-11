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
`~/.config/seccy/secrets.toml`. Seccy also reads `seccy.toml` from filesystem-root
ancestors through the current directory, in that order. The closest definition of
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
are detected, mutations (`set`, `enroll`, `reencrypt`, `remove`, and recipient
add/remove) first show an arrow-key file picker, closest file first and global last.
Each row includes recipient aliases and secret names, never values. Use Up/Down
(or j/k), then Enter; Escape or Ctrl-C cancels without changing any files. Picking
a file is exactly equivalent to passing `--secrets PATH`: only that file is loaded,
so inherited secrets and recipients are not included for that operation. Explicit
`-g` or `-s` skips the picker. Structured output and noninteractive invocations must
specify `-g` or `-s` when multiple files exist. Piped `--from-stdin` values remain
untouched because selection uses the controlling terminal.

Existing comments are preserved. Public recipients referenced by a newly written
secret are copied into that file, keeping it portable.

- `-g` / `--global` reads and writes only the user secrets file.
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
Concurrent Seccy writers lock `<file>.lock`, and detected external edits abort a
write. Symlinks and foreign-owned or group/world-writable destination files are
not replaced. Add `seccy.toml.lock` to repository ignore rules. Configuration files
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
seccy s exec -- command
```

`get` writes the exact plaintext bytes without an added newline. JSON/query output
uses `value_base64`, matching legacy `decrypt`; listing/mutation output never
includes plaintext. `--jq`, `--jq-raw` and `--jq-exit-status` work as usual.

`exec` decrypts the selected secrets, or all effective secrets if no names are
provided, and adds them to the child's inherited environment. It starts no child
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
