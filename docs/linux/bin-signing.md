# Linux binary signing and trust

Release packaging/signing and the Linux TPM/FIDO backend are implemented.
See [Linux setup](README.md) for prerequisites and the interactive hardware
verification required before relying on a newly built installation.

Linux does not have a universal equivalent of Apple's Developer ID, notarization,
or Gatekeeper. A detached signature establishes that an artifact was signed by a
particular key and has not changed. It does not establish that the program is
safe, identify its publisher without an independently trusted key, or prevent
another executable from using your TPM/FIDO devices.

## Signing a release

Seccy's Linux release workflow uses OpenSSH signatures with the dedicated
`seccy-release` namespace. OpenSSH 8.0 or newer is required for SSH signatures.
The signing key must be independent of the Seccy installation being verified.

1. Create a release signing key on a trusted machine:

   ```sh
   ssh-keygen -t ed25519 -f ~/.ssh/seccy-release -C seccy-release
   ```

   A hardware-backed `ed25519-sk` or `ecdsa-sk` key is also suitable when supported
   by your authenticator. Keep the private key outside the repository and release
   archive. Protect it with a passphrase or hardware verification policy.

2. Build and sign:

   ```sh
   mise run linux:package
   SECCY_RELEASE_KEY="$HOME/.ssh/seccy-release" mise run linux:sign
   ```

   This produces `target/seccy-linux.tar.gz` and its detached `.sig` file.
   Repackaging invalidates any existing signature; sign the final archive.

3. Publish the archive and signature together. Publish the signing public key
   and its SHA-256 fingerprint through an independently authenticated channel:

   ```sh
   ssh-keygen -lf ~/.ssh/seccy-release.pub
   ```

## Verifying before installation

Obtain the publisher's public key through a trusted channel. Downloading an
archive, signature, and previously unknown public key from the same untrusted
location does not establish publisher identity.

Create an allowed-signers file with this format (replace the example key):

```text
seccy-release namespaces="seccy-release" ssh-ed25519 AAAA...publisher-public-key...
```

Then verify the downloaded archive:

```sh
SECCY_ALLOWED_SIGNERS="$HOME/.config/seccy/release-signers" mise run linux:verify
```

Or verify directly, without running any code from the downloaded archive:

```sh
ssh-keygen -Y verify \
  -f "$HOME/.config/seccy/release-signers" \
  -I seccy-release -n seccy-release \
  -s seccy-linux.tar.gz.sig < seccy-linux.tar.gz
```

Only extract and run the release after verification succeeds. Inspect its file
list before extracting into an empty staging directory. Installing a binary in
`~/.local/bin` does not cause Linux to verify its signature on subsequent runs.
Verify every update before replacing the installed binary. Track the expected
release version as well: a valid signature alone does not prevent rollback.

## What makes an installation trustworthy?

- **Release provenance:** pin the publisher's signing key and verify every
  downloaded release. For a self-built release, you are the publisher; a signature
  records your approval of those bytes, not an independent audit of the source.
- **Build provenance:** review the source revision and dependency changes, use
  `Cargo.lock`, build with `--locked`, and record the revision/toolchain used.
- **Installed-file integrity:** user-owned executables can be replaced by other
  processes with the same UID. A root-owned installation under `/usr/local` or a
  signed distribution package provides a stronger ownership boundary.
- **Runtime enforcement:** IMA appraisal can enforce file signatures, but requires
  administrator-managed kernel policy and trusted keys. It is separate from these
  OpenSSH release signatures. SELinux policy can restrict a signing service and
  device access; it likewise requires system-level integration.
- **Boot integrity:** Secure Boot and TPM measured-boot policies protect different
  parts of the system. Secure Boot does not automatically authenticate an ordinary
  ELF executable, and a firmware/MOK enrollment is not needed for this release
  signing workflow.

GNOME does not grant a special trusted-application status when an ELF file is
signed. Its system prompt displays application-supplied descriptions; that display
is not publisher attestation. TPM/FIDO protection must be enforced by Seccy's key
backend independently of release verification.

## Key rotation

Authenticate a replacement release key through the previously trusted channel,
then update the allowed-signers file. Remove compromised keys from that file;
old signatures made by them should no longer be accepted. Keep release signing
credentials separate from SSH identities and vault-enrollment credentials.
