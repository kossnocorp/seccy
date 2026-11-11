# Seccy roadmap

## Hardware backends and authorization policies

- [ ] Introduce global defaults and per-key overrides for a **backend** (where the private key lives) and an **authorization policy** (what permits its use). Prefer explicit validated combinations over arbitrary storage/auth cross-products. Decide whether named profiles are useful shorthand.
- [ ] Document each supported combination in `docs/strategies/<backend>-<authorization>.md`: provisioning, firmware/protocol requirements, key export guarantees, private operations, user verification, fallback, recovery, migration, and trust boundary.
- [ ] Support these eligible combinations, distinguishing production from experimental and signing-only from decryption-capable:
  - Secure Enclave + per-operation biometric authorization (signing and key agreement/decryption).
  - Native FIDO SSH security keys + mandatory user presence and verification (SSH authentication and SSHSIG/Git signing only).
  - Direct PIV + PIN Always and Touch Always on YubiKey 5/5 FIPS (on-device key generation; signing and decryption/key agreement).
  - Direct PIV + MatchAlways on supported Bio Multi-protocol devices; enforce touch on PIN fallback and document that MatchAlways is not fingerprint-only.
  - TPM + fresh FIDO assertion verified by an isolated Seccy authorization service (signing and key agreement; service is trusted to enforce approval).
  - TPM + PIV PolicySigned authorization bound to a fresh TPM session and exact command (signing and key agreement).
  - TPM + FIDO previewSign PolicySigned authorization, experimental and capability-gated.
  - Direct FIDO previewSign P-256 signing, experimental and signing-only.
  - Direct OpenPGP with keys generated on-device and per-operation touch; validate PIN policies separately for signing, authentication and decryption slots.
- [ ] Rework current FIDO hmac-secret + TPM flow: remove reusable authorization secrets from the user process. Extend `seccy-tpm` to own enrollment bindings, generate single-use operation-bound challenges, verify FIDO signatures/RP/UP/UV, and authorize TPM operations through PolicySigned. Protect enrollment changes as carefully as key use. Document service/kernel compromise and optional remote-broker tradeoffs.
- [ ] For PolicySigned, disable password/HMAC authorization bypasses, bind nonceTPM and cpHashA, enforce expiry/session consumption, test replay/substitution, and use separate narrowly scoped signing and decryption keys. Hardware-back the policy authority where feasible; its use remains subject to the service trust boundary.
- [ ] Add native FIDO SSH support, including Git SSHSIG and enforced UP/UV. Hardware-held credential handles are not exported private keys.
- [ ] Add direct PIV and TPM + PIV support, metadata/attestation checks and on-device generation. Do not import software-generated private keys into a profile claiming "never exportable".
- [ ] Add `preview = false` by default, with explicit opt-in for direct and TPM-mediated previewSign. Probe firmware/extensions/algorithms. Yubico labels previewSign non-production; firmware 5.8 is not available on current 5 FIPS devices and installed firmware cannot be upgraded.
- [ ] Add ordinary P-256 SSH/Git signatures for new backends. Existing Secure Enclave/TPM P-256 signing is not preview; only previewSign-dependent paths require preview opt-in.
- [ ] Add OpenPGP support; distinguish OpenPGP-format Git signatures from SSHSIG. Validate per-slot confirmation and middleware caching behavior.
- [ ] Enforce PIN verification plus fresh touch, or fresh fingerprint, for every relevant private operation. Disable consent caches/batching in strict profiles. PIN re-verification does not prove fresh human typing; hosts can cache PINs. Never silently fall back to weaker authorization or software keys.
- [ ] Validate backend + authorization + hardware/firmware + algorithm + mode at config load/provision/use, returning actionable errors. Detect Bio FIDO vs Bio Multi-protocol; do not infer capability from marketing names. Strict profiles must reject notify-only operation.
- [ ] Include public-key fingerprints in GitHub titles and physical storage identifiers. Separate human aliases from immutable key identity; support alias reuse and explicit replacement when backend/mode changes. Preserve old decryption keys until ciphertext migration succeeds; never silently destroy access.
- [ ] Keep FIDO-encrypted software private keys outside strict profiles: they expose the private key in RAM. PRF-based symmetric encryption also does not provide public-recipient-only encryption. Track weaker optional profiles separately if ever added.

## Secrets

- [ ] Extend the initial macOS multi-recipient secrets envelope to other eligible hardware backends; consider actual age interoperability/plugin support separately from age-style semantics.
- [ ] Explore `seccy secrets session -- <command>`: authenticate a scoped session without exporting secrets up front; subsequent `get` calls within that session notify instead of prompting. Define OS-authenticated process scope, expiry, revocation, child inheritance, concurrency and replay protection. An environment variable alone must not be an authorization capability. Explain that hardware per-operation biometric/UV policies may prevent this mode; do not weaken strict keys silently. Explicit get still reveals plaintext to its caller.

## Research references

- [YubiKey comparison](https://www.yubico.com/sg/store/compare/)
- [PIV authorization policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html)
- [Bio editions](https://www.yubico.com/products/yubikey-bio-series/)
- [Firmware capabilities](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-overview.html)
- [previewSign limitations](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html)
- [TPM PolicySigned](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policysigned.1/)
- [OpenPGP policies](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)
- [age format](https://c2sp.org/age)
