# Security audit — seccy

Date: 2026-11-05  
Revision: `e9420ac8fc1631d238526256f899574fabccc30c`  
Environment: macOS 27.2 (26B123), Rust 1.95.0  
Scope: Rust workspace, Lua fnox adapter, packaging/notarization scripts, launchd configuration, and documented security model.

## Executive assessment

Two actionable issues were confirmed: connection-slot exhaustion and unescaped process identity text. Neither establishes private-key extraction, remote code execution, or a biometric bypass. The more consequential unresolved assurance gap is that existing keychain items are trusted by label without checking their hardware provenance or access policy; exploiting that requires access to the application's keychain group, which was not demonstrated.

The implementation has useful defenses: bounded SSH frames, strict protocol parsing, same-UID socket checks, private runtime directories, atomic inventory updates, OS-managed cryptography, and per-operation authentication contexts. Notification mode deliberately permits same-user key use without biometric authorization. This report does not treat that documented behavior as an authentication vulnerability.

| ID | Severity | Finding | Evidence |
| --- | --- | --- | --- |
| SEC-001 | Medium | One client can exhaust the shared connection capacity | Reproduced against an isolated empty agent |
| SEC-002 | Low | Process paths and names can inject lines into authorization text | Reproduced through the actual description formatter |

Severity assumes an unprivileged process running as the logged-in user, including a process that can reach a forwarded agent. A fully compromised account can already disrupt its own processes. Findings here concern additional protection and reliability expected from a key broker, not privilege escalation across macOS users.

## Method and verification

Reviewed the application source for protocol parsing, authorization, key lifecycle, filesystem races, secret handling, subprocess invocation, process attribution, and resource limits. No application code was changed.

- `cargo test --workspace --locked --offline`: **47 tests passed**, no failures. Includes native process observations, protocol rejection cases, OpenSSH/Git interoperability with test keys, and ECIES round trips/tampering with ephemeral software keys.
- `/Users/koss/.local/share/mise/installs/lua/5.5.0/bin/lua pkgs/fnox/test.lua`: **passed**. The initial `lua` shim invocation failed because no version was selected; the installed interpreter worked.
- A temporary agent with an empty registry reproduced SEC-001. Its state and sockets were isolated under `/tmp`, and it was terminated afterward. The initial sandboxed attempt could not bind a socket; the approved isolated rerun succeeded.
- A temporary Rust program linked to the workspace's compiled core library reproduced SEC-002.
- `cargo audit --version` reported that cargo-audit is unavailable. A targeted RustSec web search is not a dependency audit; **no comprehensive current advisory scan was completed**, and no claim that dependencies are vulnerability-free is made.

No production secrets were decrypted, no real keys were provisioned or deleted, and no GitHub or launchd changes were made. Signed-app Secure Enclave behavior, biometric cancellation/reuse, lock-state enforcement, enrollment invalidation, notification delivery, and cross-UID denial were not interactively tested. Automated software-key tests do not establish those properties.

## Reproduction scripts

Run from the repository root:

```sh
node security/SEC-001/test.ts
node security/SEC-002/test.ts
```

Both scripts run directly with Node.js native TypeScript support, without a Bash wrapper or npm dependencies. They build the current source with Cargo's locked, offline dependency resolution and require the Rust toolchain. SEC-001 additionally requires macOS and permission to bind local Unix sockets. It starts only a temporary empty agent, verifies baseline behavior, holds 16 admitted connections idle, checks rejection of a new request, and verifies recovery after release. SEC-002 calls the real core formatter from a temporary Rust program; it does not test native UI rendering.

Exit status is **1 when the vulnerability is reproduced**, **0 when the expected vulnerable behavior is absent**, and **2 for setup/runtime errors**. Both scripts currently fail with status 1 because the vulnerabilities remain unfixed. A zero exit status means only that the specific probe did not reproduce the issue, not that all related security properties are verified. Temporary files and the temporary agent are cleaned up; Cargo build artifacts remain in the configured target directory. No real keys are provisioned or used.

## SEC-001 — Shared connection slots can be monopolized

**Severity:** Medium. **Confidence:** High.

**Locations:** `pkgs/cli/src/server.rs:104–112,189–195`; `pkgs/cli/src/secrets.rs:111–116`; `pkgs/core/src/agent.rs:44–56`.

The agent shares a maximum of 16 active connections between SSH and secret decryption. Each accepted connection consumes a worker slot before receiving a request. There is no per-peer quota, admission fairness, or reserved capacity for the other protocol. Once the limit is reached, new connections are dropped.

Read timeouts are 120 seconds per blocking read, rather than an absolute frame or connection deadline. A peer can therefore hold all slots idle for approximately two minutes, reconnect to repeat the denial, or send partial data before each read times out. Completed SSH requests also leave the connection open for more requests. A frame-size limit does not bound a connection's total lifetime.

**Reproduction performed:** Start `target/debug/seccy agent --json` with temporary `XDG_STATE_HOME` and `XDG_RUNTIME_DIR`, no registered keys, and `LOG_LEVEL=off`. Send an identity-list frame (`00 00 00 01 0b`) on a baseline connection, close it, then open 16 connections without sending data. Send the same frame on a seventeenth connection. Finally close the 16 idle connections and retry.

Observed output:

```text
baseline: 000000050c00000000
17th connection: b''
after release: 000000050c00000000
```

**Impact:** A same-user client can deny SSH signing and secret retrieval without knowing any key or triggering biometric authorization. An agent-forwarding endpoint can also expose this availability risk, subject to the forwarding transport. The forwarding scenario was not tested.

**Remediation:** Apply a short initial-request deadline and an absolute frame deadline, limit outstanding connections per kernel-observed peer, and provide separate capacity/fair queues for SSH and secrets. Support persistent legitimate SSH connections without letting idle connections monopolize workers. Bound queue waits and metadata-enrichment work as well; socket timeouts do not cover those operations.

**Regression checks:** Demonstrate that one peer holding partial frames cannot starve another peer or the secrets socket; test trickled input against an absolute deadline and verify recovery after cancellation/disconnection.

## SEC-002 — Unescaped caller names can forge lines in authorization text

**Severity:** Low. **Confidence:** High for formatting; native prompt rendering not tested.

**Locations:** `pkgs/core/src/lib.rs:261–278`; consumers at `pkgs/macos/src/platform.rs` in `sign`, `decrypt`, and `authentication_context`; terminal output at `pkgs/cli/src/server.rs` after `signature_delivered`.

`Caller::description()` interpolates executable paths, process names, and ancestor executable paths using unescaped display formatting. Other context fields correctly use debug quoting. A process can run an executable from a path containing newlines or terminal control characters. Kernel-observed provenance does not make that path safe for display.

**Reproduction performed:** Linked a temporary program to `seccy_core`, constructed a `Caller` with executable `/tmp/tool\nCode signing: trusted`, and called `description()`. The literal newline produced:

```text
/tmp/tool
Code signing: trusted (PID 123, peer UID 0, GID 0)
```

This demonstrates a forged line in the exact string used for prompts and notifications. It does not demonstrate bypassing Touch ID, forging the real Security.framework identity, or changing JSON audit structure. JSON serialization escapes the string. The native UI's handling of control characters was not tested.

**Impact:** A malicious local requester can make approval text misleading and exploit limited UI space. Successful-signature terminal output also prints the executable unescaped, allowing terminal control sequences if the output is viewed in a terminal. Key and fingerprint fields precede caller text, which limits the spoofing impact.

**Remediation:** Consistently quote and escape all OS-derived text before rendering it in UI or terminals, including executable, process name, and ancestors. Bound each field's display length and prioritize the key, operation, and immediate peer over ancestry. Preserve full structured metadata separately.

**Regression checks:** Test newline, carriage return, ESC, Unicode directional controls, and long paths across caller descriptions and human-readable output. Confirm the signed app displays escaped text without displacing security-critical fields.

## Additional risks and hardening recommendations

### Existing keychain items are accepted without provenance/policy validation

`pkgs/macos/src/platform.rs:239–263,276–277` queries a private key by label and accepts its public P-256 point. It does not verify the Secure Enclave token, expected access-control policy, or uniqueness of matches. `pkgs/core/src/state.rs:97–105` does not compare the returned identity to the persisted public key/fingerprint. Operation-time comparisons use a freshly resolved identity, so they do not pin historical identity across key replacement.

Creation does explicitly request Secure Enclave, device-only unlocked protection, and `biometryCurrentSet` for prompt keys. Apple's documentation identifies the token attribute and access-control object as the properties establishing these protections: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).

**Conditional consequence:** A software or less-protected key already present under the expected label in an accessible keychain group could be reported as a prompt-mode Secure Enclave key. A fresh LAContext is not a substitute for a key's biometric ACL. This is a source-level assurance gap, **not a demonstrated same-user biometric bypass**: ordinary unrelated applications do not thereby gain permission to write the app's keychain group.

Validate available key attributes, reject ambiguous lookup results, pin registered public material, and require explicit reconciliation for identity changes. Verify policy provenance with a controlled signed fixture in a dedicated test group. Avoid silently deleting/recreating mismatched keys because existing ciphertext may become unrecoverable.

### Diagnostic logging captures sensitive context and grows without a bound

`pkgs/macos/src/process.rs:71–72` retains complete argv at debug/trace, including ancestors. `pkgs/core/src/agent.rs:108–116` records raw signing bytes before authorization completes. `pkgs/cli/src/server.rs:194` records caller metadata even for a client that only connects. `pkgs/cli/src/logging.rs:30–50` appends without rotation, retention, or a size cap.

These behaviors are partly documented and logs are private. They nevertheless turn transient command-line credentials or arbitrary signing data into persistent copies, and repeated requests can grow the log indefinitely. Decrypt/encrypt payload fields are not directly logged, but the README's absolute claim that decryption audit metadata never contains plaintext is too strong when ancestor argv can contain secrets. Existing tests check payload isolation, not sensitive ancestor arguments.

Separate raw-payload/argv capture from ordinary debug verbosity, make it explicitly opt-in, redact or omit argv, and add bounded retention and rate-limited repetitive events. Clarify the documentation's distinction between protocol payloads and process metadata. No actual user secret was inspected to validate this risk.

### Filesystem enrichment can block outside socket timeouts

`pkgs/macos/src/process.rs:180–186` and `pkgs/core/src/payload.rs` (`HostKey::lookup`) check pathname metadata, open the path, then inspect the opened file. A writable path can change to a FIFO between the first check and `File::open`, causing the open to block before the second check. Slow filesystems can also stall enrichment. Paths derived from caller-controlled app bundles and working directories make this relevant to hostile local clients.

This race was identified statically, not reproduced. Use nonblocking opens followed by descriptor-based type checks, and put best-effort enrichment under an overall deadline or bounded worker isolation. Preserve availability when enrichment fails. The README already acknowledges that individual enrichment calls have no hard timeout.

### Caller attribution and notification mode have deliberate limits

Same UID is the authorization boundary; collected code-signing information is descriptive and is not an allowlist. Connection PID/start-time checks improve observations but do not establish the origin of bytes relayed over inherited/passed descriptors or SSH forwarding. Session-binding/destination constraints are unsupported. Keep these limits prominent, especially for notification-mode secrets and forwarded agents.

`osascript` receives notification text as an argument to constant script source, avoiding script injection. Submission success is not proof that the user saw a banner; Focus and notification settings can suppress it. Notify mode should not be represented as approval. These are documented trust-model limits rather than newly discovered vulnerabilities.

## Positive controls observed

- SSH request sizes are capped at 256 KiB; truncation, trailing data, unknown keys, and unsupported signature flags fail before signing. Mutation requests are unsupported.
- Secrets use bounded inputs, strict envelopes and request fields, key fingerprint checks, and authenticated ECIES through Security.framework. Parser errors for untrusted secret JSON are intentionally sanitized.
- Prompt-key creation uses biometric-current-set access control; each private operation creates a new LAContext with reuse disabled. Native enforcement remains a hardware verification item.
- Socket parents require owner-only directories; sockets are mode 0600; peers must have the agent's UID. Inventory operations hold shared/exclusive locks and save atomically.
- Main audit logs reject symlinks/nonregular files/hard links and enforce 0600. Public key and Lua provider updates use temporary files and atomic replacement.
- GitHub and notification subprocesses use argument arrays rather than interpolated shell source. GitHub mutations require confirmation unless the user explicitly opts out.
- Packaging requests hardened runtime and verifies the signature; notarization submits and staples the same copied bundle and checks acceptance before replacing the distribution archive.

## Prioritized follow-up

1. Add connection admission fairness and absolute deadlines; reproduce SEC-001 as a regression test.
2. Escape and bound caller display fields; inspect actual signed-app prompts with hostile path fixtures.
3. Validate existing key provenance and persisted identity; exercise mismatched-key cases in an isolated signed test group.
4. Reduce diagnostic secret retention, bound logs, and keep filesystem enrichment from blocking key operations.
5. Run a current RustSec scan of `Cargo.lock` and complete the signed-hardware verification matrix: repeated approval/cancellation, lock/unlock, enrollment changes, notification suppression/failure, cross-UID access, concurrent operations, and key removal during requests.

This is a source review with targeted local validation, not a certification or exhaustive penetration test.
