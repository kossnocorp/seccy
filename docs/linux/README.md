# Linux / GNOME setup

Seccy uses a dedicated FIDO2 credential, TPM-generated P-256 keys, GNOME's Gcr
system prompter, and Secret Service (normally GNOME Keyring). It uses the same
SSH/secrets sockets, registry, config, CLI, JSON/jq output, GitHub synchronization,
and fnox provider as macOS.

## Dependencies and device access

On Fedora, install build dependencies:

```sh
sudo dnf install gcc pkgconf-pkg-config libfido2-devel tpm2-tss-devel libsecret-devel gcr-devel
```

Runtime dependencies are the matching shared libraries, GNOME Shell's system
prompter, a Secret Service provider, and the user's session D-Bus. Run Seccy in
your logged-in desktop session, not with sudo. FIDO hidraw access should be
provided by the distribution's security-key udev rules.

Only the dedicated `seccy-tpm` system service opens `/dev/tpmrm0`. On Fedora it is
normally owned by `root:tss`; the service receives that supplementary group.
Your desktop account does not need membership. After extracting the release,
install the service once as administrator:

```sh
sudo install -d -m 755 /usr/local/libexec /etc/sysusers.d /etc/systemd/system
sudo install -o root -g root -m 755 seccy/bin/seccy-tpm /usr/local/libexec/seccy-tpm
sudo install -o root -g root -m 644 seccy/system/seccy-tpm.conf /etc/sysusers.d/seccy-tpm.conf
sudo systemd-sysusers /etc/sysusers.d/seccy-tpm.conf
sudo install -o root -g root -m 644 seccy/system/seccy-tpm.service /etc/systemd/system/seccy-tpm.service
sudo systemctl daemon-reload
sudo systemctl enable --now seccy-tpm.service
```

If you previously added your user to `tss`, remove that membership with
`sudo gpasswd -d "$USER" tss`, then log out of the entire desktop session and back
in. The system daemon is separate from the desktop `seccy-agent.service`.
Inspect failures with `journalctl -u seccy-tpm.service`. Restart the system service
after replacing its executable. Seccy creates transient
objects under the owner hierarchy; it does not clear the TPM, change hierarchy
passwords, or occupy persistent handles. An owner hierarchy requiring an external
authorization value is not supported by this backend. Do not clear an existing
TPM to make Seccy work: that can invalidate disk-encryption and other credentials.

The authenticator must support FIDO2 `hmac-secret`, ES256, and credential
protection with user verification required. A U2F key that works with PAM may
not meet these requirements. Set up its PIN or enroll its on-device biometrics
using the authenticator vendor's tools before initializing Seccy.

## Build, install, and initialize

For local development, no archive extraction is needed:

```sh
mise run setup:link
export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$PATH"
```

This builds release binaries, installs the bin/fnox/system layout under
`${XDG_DATA_HOME:-$HOME/.local/share}/seccy`, and links `seccy` and
`seccy-tpm` into `~/.local/bin`. `XDG_BIN_HOME` is an optional project convention
(not part of the XDG specification). Relative `XDG_DATA_HOME` is ignored.
Existing regular command files are preserved; move them aside before linking.
The fnox provider and system service assets are included in this installation.

For the administrator commands above, replace `seccy/bin/seccy-tpm` with
`$PREFIX/bin/seccy-tpm` and `seccy/system/` with `$PREFIX/system/`, where
`PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/seccy"` (use the printed
installation path if your XDG variable is relative).
The system daemon must remain a root-owned copy in `/usr/local/libexec`, rather
than a symlink into your writable installation. After rebuilding, restart the
user agent; to update the daemon, copy it again as root and restart its service.

For release archive testing instead:

```sh
mise run linux:package
```

For downloaded releases, follow [binary signing and trust](bin-signing.md) before
extracting. For your own build, extract `target/seccy-linux.tar.gz` into a staging
directory, then install its contents:

```sh
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/seccy"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
install -d "$BIN" "$PREFIX/bin" "$PREFIX/fnox" "$PREFIX/system"
install -m 755 seccy/bin/* "$PREFIX/bin/"
install -m 644 seccy/fnox/provider.lua "$PREFIX/fnox/"
install -m 644 seccy/system/* "$PREFIX/system/"
ln -sfn "$PREFIX/bin/seccy" "$BIN/seccy"
ln -sfn "$PREFIX/bin/seccy-tpm" "$BIN/seccy-tpm"
```

With `~/.local/bin` on PATH:

```sh
seccy init --list --json
seccy init --device /dev/hidraw14 --json # use the path actually listed above
```

Installation files are separate from persistent state. Exported public keys are
in `$XDG_STATE_HOME/seccy/keys` (default `~/.local/state/seccy/keys`), alongside
the registry, vault metadata, and logs. Configuration is loaded only from
`$XDG_CONFIG_HOME/seccy/config.toml` (default `~/.config/seccy/config.toml`).
User sockets are in `$XDG_RUNTIME_DIR/seccy`. Encrypted records remain in Secret
Service. Upgrades replace managed installation files, never vault state.

When upgrading from the earlier layout, run `seccy sync` to regenerate public
exports in the state directory, update SSH `IdentityFile` and Git
`user.signingkey` paths, and rerun `seccy service install` to capture the new
executable path. Old exports and the previous `seccy/local` installation are
left intact; remove them only after updating references. The public-key path
change applies to both Linux and macOS.

Device paths are only selection hints during enrollment; they are not stored as
authenticator identity. Enrollment stores a credential ID and public key, vault
identifier, derivation salt, and TPM parent name in
`$XDG_STATE_HOME/seccy/linux-vault.json` (default `~/.local/state/seccy/`).
The corresponding encrypted enrollment marker and TPM key records are in Secret
Service. Repeating `init` reports the existing enrollment; it does not replace it.

Initialization can require two touch/verification operations: creating the FIDO
credential and deriving/validating its secret. GNOME prompts show PIN entry or
on-device verification instructions. Biometric verification is preferred when
available; supported biometric-failure responses can fall back to the token PIN.
An explicit cancellation does not trigger that fallback. FIDO operations time
out after 30 seconds. There is no password-only, software-key, or PAM fallback.

Currently, connect only the enrolled FIDO authenticator during ordinary key
operations. Multiple attached authenticators fail with an actionable error;
UV-protected credentials cannot always be silently probed to select the right
device. A wrong authenticator never results in automatic replacement enrollment.

## Keys, agent, Git, and fnox

```toml
email = "you@example.com"

[keys.personal]
mode = "prompt"
github = "auth"

[keys.signing]
mode = "prompt"
github = "signing"
email = "work@example.com" # Optional override of the top-level email.

[keys.secrets]
mode = "prompt"
```

```sh
seccy provision --json
seccy agent --json
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/seccy/agent.sock"
ssh-add -L
```

Register the exported public keys with your servers, or use `seccy gh sync` with
the GitHub CLI. Git SSH commit signing uses the same setup documented in the
repository README, substituting the Linux socket path. `seccy fnox info --json`
locates the installed provider. The provider protocol and binary-preserving
encrypt/decrypt commands are unchanged.

Each signature, decryption, new-key creation, and existing-key removal requires
FIDO verification. Public-key encryption and public inventory inspection do not.
No unlock secret is cached across operations. Completed provisioning is
idempotent; interrupted Secret Service writes are journaled in the private vault
metadata and resumed by `provision`. Missing persisted key blobs fail rather than
silently replacing a key. `reset` removes managed SSH/encryption keys while
retaining the vault's FIDO enrollment, service, configs, and logs.

## Login service

```sh
seccy service install
seccy service status --json
seccy service restart
seccy service uninstall
```

This installs `seccy-agent.service` under the user's systemd configuration and
starts it with the graphical session. The service captures the installation's
configuration/storage paths and optional `SECCY_KNOWN_HOSTS`. Set `log_level` in
the user `config.toml` and restart the service to change logging. Reinstall after moving
the binary or changing those settings. Inspect service startup errors with
`journalctl --user -u seccy-agent.service`; structured application logs remain in
the shared XDG state log directory.

Set SSH_AUTH_SOCK in the clients' environment, or configure `IdentityAgent` in
SSH configuration. The systemd service does not overwrite an existing desktop
SSH agent's environment. GUI and terminal clients must select Seccy's socket.

## Hardware protection and portability boundaries

- The TPM generates the private keys. FIDO-derived secrets separately authorize
  TPM key use and encrypt the persisted TPM blobs. Ordinary host memory does not
  contain the raw SSH private scalar.
- The broker accepts only fixed key operations, authenticates peers with
  `SO_PEERCRED`, and restricts use to blobs created for that Unix UID. Other local
  processes can connect, but cannot use another UID's catalog entries. Processes
  under the same UID still need the FIDO-derived authorization for private use.
  The daemon sees authorization values and ECDH outputs temporarily. Socket
  access is not proof of executable identity or fresh FIDO verification.
- `/var/lib/seccy-tpm` contains the private UID ownership catalog and must be
  retained across upgrades and backed up alongside vault metadata and keychain
  records. Restoring under a different UID requires administrator recovery.
  Earlier direct-TPM prototype keys are not automatically imported: the broker
  rejects unregistered blobs rather than assuming ownership or replacing keys.
  Creation interrupted before the client saves its record can leave a catalog
  entry; the 512-entry per-UID quota includes such entries. Missing keychain blobs
  can likewise prevent quota reclamation. Administrator recovery is currently
  manual; do not delete the whole catalog while live keys depend on it.
- Wrapping/authentication secrets do temporarily enter process memory. A
  compromised agent could retain them; fresh prompting is partly agent policy.
- TPM binding is to the owner-hierarchy storage parent on this machine. This
  initial backend does not additionally enforce Secure Boot/PCR policies.
- Linux `notify` keys are rejected: this enrolled-vault policy requires FIDO
  verification and does not provide unattended private-key operations.
- Linux encryption uses ephemeral P-256 ECDH, HKDF-SHA256, and AES-256-GCM with
  the versioned `seccy:linux:v1:` envelope. It supports the same encrypt/decrypt
  commands but is not Apple's ECIES wire format. macOS non-exportable keys and
  their existing ciphertext cannot be migrated to this TPM.
- Linux process metadata comes from SO_PEERCRED and bounded `/proc` reads.
  Command/repository interpretation is shared with macOS. macOS code-signing and
  application-bundle identity fields have no equivalent and remain absent.
- `crypto-check` checks the catalog, TPM parent, keychain record, and presence of
  a FIDO device. Only a real private operation proves that it is the enrolled key
  and can perform the required verification. Keychain access may itself prompt
  if its collection is locked.

Losing/resetting the authenticator, clearing/replacing the TPM, or losing the
encrypted keychain records can make keys and ciphertext unrecoverable. There is
no recovery recipient or second-authenticator enrollment in this version.
`reset` deletes records; copies of previously backed-up encrypted records are not
cryptographically revoked by deleting the current copies.

## Verification

Automated tests cover the shared CLI/protocol flows, envelope tampering, key
derivation separation, and binary-preserving encryption. They do not establish
that GNOME prompts, FIDO verification, or physical TPM operations work correctly
on a particular machine.

The direct transient TPM test requires device access and is intended for an
administrator/developer test account, not the desktop user:

```sh
cargo test -p seccy_linux physical_tpm_signing_and_ecdh -- --ignored
```

The same native signing/ECDH paths have also been tested against an isolated
software TPM. With `swtpm` installed, reproduce that check using
`mise run linux:tpm:test`. The emulator transport override exists only in test
builds; production always uses `/dev/tpmrm0`.

Then initialize/provision, verify SSH authentication and a Git signature, and
perform an encryption round trip:

```sh
printf 'test secret\n' | seccy encrypt secrets > secret.enc
seccy decrypt secrets < secret.enc
```

Repeat to confirm fresh verification, cancel the prompt, unplug the key, and
try a different key. Each rejected private operation must fail. Test restart,
logout/login, and fnox independently. Hardware verification is still pending for
the initial implementation; do not infer it from a successful build alone.
