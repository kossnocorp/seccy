# Providers and configuration

Seccy resolves each key to a provider: a concrete implementation and its authorization
policy. The config is unversioned. Existing macOS prompt/notify configurations remain
valid; new configurations should declare `use` explicitly.

```toml
email = "koss@nocorp.me"
mode = "prompt"
# provider omitted: secure-enclave on macOS; error on Linux.

[keys.auth]
use = "ssh-auth"
forge = ["github", "gitlab"]

[keys.signing]
use = "ssh-sign"
forge = "github"
mode = "notify"

[keys.secrets]
use = "secrets"
name = "Machine secrets"
```

`use` accepts a single string or a nonempty list. Explicit permissions restrict SSH
agent operations and secrets access. Secrets-only keys are not advertised by the SSH
agent. SSH authentication and SSHSIG signing are checked independently; an unrecognized
signing payload is rejected for an explicitly restricted key. Managed secrets also
require prompt mode and enrollment with `seccy s enroll secrets`.

Legacy keys without `use` retain their previous permissions and enrollment behavior.
`name` is display text; the table name remains the stable CLI key handle.
`forge` requires explicit `use` and derives authentication/signing registrations from it.
GitHub sync supports both roles. GitLab selection and deprecated scalar/list `gitlab`
roles are parsed, but GitLab synchronization is not implemented yet. Deprecated
`github`/`gitlab` fields still work and cannot be combined with `forge` on the same key.
Review role differences before migrating a key shared between forges.

## Selection and overrides

```toml
provider = { os = { macos = "secure-enclave", linux = "workstation" } }

[providers.workstation]
kind = "tpm-fido2-hmac"
mode = "prompt"

[keys.auth]
use = "ssh-auth"

[keys.signing]
use = "ssh-sign"
```

Alternatively use `provider = { host = { kossbook = "secure-enclave", kosspc = "workstation" } }`.
Host names match the OS hostname exactly. A selector contains either `os` or `host`.
A missing match, an omitted selector, or `provider = "default"` resolves to Secure
Enclave on macOS and no provider on Linux. Linux operations require an explicit selection.
A key inherits the root selector unless it declares its own `provider` or inline `kind`.

```toml
[keys.auth]
kind = "secure-enclave"
mode = "prompt"
use = ["ssh-auth", "ssh-sign"]
```

A key cannot declare both `kind` and `provider`. Inline `kind` bypasses the root
selector. Supported parameter overrides resolve key → named provider → implementation
default; mode resolves key → named provider → root → prompt. Parameters include
`auth`, `mode`, `verify`, `slot`, and `algorithm`, but only when supported by that kind.
Secure Enclave supports P-256 and prompt/notify modes, and rejects `auth` and `slot`.
For prompt keys, `verify` accepts `biometry-any` (the default for every new key),
`user-presence` (biometrics or system password), and `biometry-current-set`
(invalidated by fingerprint enrollment changes). Explicit `verify` with notify mode
is rejected. Other provider kinds retain their own verification choices.

```toml
[keys.auth]
use = "ssh-auth"

[keys.signing]
use = "ssh-sign"
verify = "user-presence"

[keys.secrets]
use = "secrets"
```

On macOS this uses Secure Enclave automatically. Auth and secrets use `biometry-any`;
signing explicitly overrides it. A named provider can set a shared `verify` choice,
and each key can override it. There is no root-level `verify` field.

Verification is pinned when the key is created and shown in key inspection. Existing
keys without recorded verification retain `biometry-current-set`; omitting `verify`
does not change them. To change an existing key, set `verify` and run
`seccy rebuild NAME`. Rebuild reads that key's registered source configuration and
creates a new generation; an omitted `verify` uses `biometry-any`. Retired generations
keep their original policy and ciphertext remains unchanged.

## Availability and inspection

```sh
seccy providers list --json
seccy config inspect --json
seccy config inspect -c ./config.toml --jq '.keys'
```

Inspection performs no private-key operations. It reports resolved keys, availability,
source files, field provenance and deprecation warnings. Planned kinds can be inspected
but cannot be provisioned or used, including with `preview = true`.

| Kind | Current availability |
| --- | --- |
| `secure-enclave` | macOS; SSH authentication/signing and managed secrets |
| `tpm-fido2-hmac` | Existing Linux TPM/FIDO2-HMAC backend; SSH signing/authentication |
| `tpm-fido2-broker`, `tpm-piv` | Planned |
| `tpm-fido2-preview-sign`, `fido2-preview-sign` | Planned; also require preview opt-in |
| `fido2-ssh`, `piv`, `openpgp` | Planned |
| `fido2-hmac-secret`, `fido2-wrapped-key` | Candidates; portable-encryption decision pending |

`preview` defaults to false. The Linux HMAC backend retains its existing security
properties; this config work does not implement PolicySigned or remove its reusable
authorization-secret limitation. See the [design](strategy-config-design.md) and
[roadmap](../TODO.md) for planned guarantees, auth records and binding formats.

## Files, overrides and existing keys

`--config PATH` (`-c`, `--c`) replaces the global key-config path. Its adjacent
`<stem>.local.toml` file is merged over it, for example `config.local.toml` or
`work.local.toml`. Selecting a `.local.toml` file reads that file alone. Missing files
are allowed. Unknown fields and invalid combinations are errors.

Tables merge by field; arrays/scalars replace. Provider selectors replace atomically,
so an OS map does not accidentally combine with a host map. Changing a named provider
or auth record's `kind` replaces that record; incompatible inherited key fields remain
errors instead of silently disappearing. Inspection exposes the resulting provenance.

`--global-secrets PATH` (`--gs`) independently replaces the global secrets path.
It does not follow `--config`. Global secrets and each project directory load base
then local companion, with closer directories winning. `-g` restricts reads to the
global pair; `-s PATH` isolates exactly one file. See [secrets](secrets.md) for mutation
selection. Add `config.local.toml`, `secrets.local.toml` and `seccy.local.toml` to your
ignore rules if their contents should remain machine-local.

Provisioning records the resolved policy, permissions and display name alongside the
existing identity. It reuses compatible keys. Changing provider or mode is rejected
with `migration_required`. Use `seccy rebuild [NAME]` for explicit generation
replacement under the same provider (`--mode` can change prompt/notify where
permitted). Retired generations retain their original policy for decryption.
Cross-provider migration is not implemented.
Current source config can immediately narrow permissions. Expanding persisted explicit
permissions requires provisioning again. If the source disappears, persisted permissions
remain in effect. Removing a config entry does not remove the registered key.

Install/restart the updated agent to enforce these checks in running SSH and secrets
operations. Config parsing does not provision keys, discover physical devices, or make
portable bindings usable before their provider is implemented.
