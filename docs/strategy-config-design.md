# Provider and configuration model

Status: the configuration foundation is implemented. See [current provider support](providers.md)
for the supported syntax, inspection commands, overlays and compatibility behavior.
Secure Enclave and the existing Linux TPM/FIDO2-HMAC backend are connected to the resolver.
Same-provider key rebuilding and retained generations are implemented.
New hardware providers, portable bindings, cross-provider replacement and sessions below
remain planned. Naming a planned provider never enables it or falls back to another backend.

## Recommendation

Use **provider** for a complete, validated way to create and use a key. Provide
built-in provider IDs and reusable named provider configurations. Each selects one built-in
kind and supplies its supported parameters; it cannot assemble arbitrary storage,
authentication and encryption components.

Use **key handle** for `auth`, **identity** for the private-operation capability it
selects, **binding** for immutable credential/key metadata, and **recipient** for
information used to encrypt a secret for an identity. An **authenticator** is a
separately bound approval credential used by a composite provider such as TPM +
FIDO2. Neither a profile nor an authenticator label is a cryptographic identity.

The config uses concise field names: `auth = "nano"` references `[auth.nano]`,
`bind` holds the credential binding, and `verify` selects a supported verification
policy. `[auth.nano]` is an approval credential; `[keys.auth]` is a key whose handle
happens to be `auth`. They belong to separate namespaces.

Keep `storage`, authorization mechanism and encryption suite as resolved properties
of a provider, visible in inspection output. Do not introduce independent public
`storage = "fido"` and `auth = "touch"` knobs: FIDO2 is a protocol, touch alone is not
user verification, and many such combinations cannot implement decryption at all.
`default` is the built-in selection policy; OS/host selectors choose a concrete
provider without introducing a synthetic storage backend.

## Proposed configuration

### Naming decision: provider

Use `provider` for selection and `[providers.<name>]` for reusable named provider
configurations. `kind` selects the built-in implementation; a named provider adds
its supported authorization and operation parameters. “Profile” may describe this
configuration conceptually, but it is not a separate config field or namespace.

OpenSSL uses provider for implementations supplying cryptographic operations.
Seccy uses the term for its complete validated implementation path, including
composite paths such as TPM plus an external approval credential. This terminology
does not imply OpenSSL-provider or PKCS #11 interoperability.
[OpenSSL providers](https://docs.openssl.org/master/man7/provider/).

The earlier `strategy` / `[strategies]` spellings are superseded design proposals,
not compatibility aliases. Selector precedence, OS/host fallback, bindings and
security guarantees are unchanged by this rename.

### Schema and combined example

`provider` and `mode` at the root provide defaults; there is no `[defaults]` table.
Keys can override them, and a selected profile can supply its own mode.
There is no config `version` field. Omitting provider selection means `default`:
Secure Enclave on macOS, and no selected provider on Linux. Linux key operations
require an explicit provider; they must not silently choose a TPM approval method.
Profiles are optional; adding an unused profile never changes default resolution.
Versioning still belongs in generated bindings, registry formats and ciphertext.

```toml
email = "koss@nocorp.me"

provider = { os = { macos = "secure-enclave", linux = "workstation" } }
mode = "prompt"

[providers.workstation]
kind = "tpm-fido2-broker"
auth = "nano-approval"
mode = "prompt"

[auth.nano-approval]
kind = "fido2"
name = "YubiKey Nano"
bind = "seccy-authenticator:v1:<generated-public-binding>"

[keys.auth]
use = "ssh-auth"
forge = ["github", "gitlab"]

[keys.signing]
use = "ssh-sign"
forge = "github"

[keys.secrets]
use = "secrets"

# Planned alternative, not a decision to implement PIV ahead of FIDO2.
[providers.portable]
kind = "piv"
verify = "pin-touch"

[keys.recovery]
provider = "portable"
use = "secrets"
bind = "seccy-identity:v1:<generated-public-binding>"
name = "Recovery YubiKey"
```

These placeholders are not valid credentials. `tpm-fido2-broker` and `piv` are
planned kinds. An example using only the current macOS implementation would be:

```toml

[keys.auth]
provider = "secure-enclave"
mode = "prompt"
use = "ssh-auth"
forge = "github"

[keys.signing]
provider = "secure-enclave"
mode = "notify"
use = "ssh-sign"
forge = "github"

[keys.secrets]
provider = "secure-enclave"
mode = "prompt"
use = "secrets"
```

The proposed fields have the following rules:

| Field | Meaning and resolution |
| --- | --- |
| `provider` | Root default or per-key override: built-in ID, profile name, `default`, or exactly one inline `os`/`host` map. A key inherits the root selector when both its `provider` and `kind` are omitted; absent root means `default`. |
| `kind` | Exactly one concrete built-in ID, in a named provider or directly in a key. A key's `kind` selects an inline provider instead of inheriting the root selection. Key `kind` and key `provider` are mutually exclusive. Profiles cannot extend profiles, refer to `default`, or form cycles. Built-in names and `default` are reserved. |
| `mode` | Key override → selected profile → root `mode` → `prompt`. `notify` is legal only for providers and uses that explicitly support it. It changes authorization, not merely presentation. |
| `use` | A single permission string or a nonempty list: `ssh-auth`, `ssh-sign`, `secrets`, or `openpgp-sign`. Existing backends retain their legacy permissions when omitted, including secrets enrollment already recorded in state. New provider kinds require explicit `use`. No new implicit secrets permission. Unsupported uses are errors. |
| `bind` | Optional before explicit creation, required for an existing portable identity. Generated, versioned, public descriptor; never an inline private key. Treated as an atomic value during merging. |
| `auth.<handle>.name` / `keys.<handle>.name` | Optional display hints; never proof of device/key identity. The auth table handle remains the reference used by a provider. |
| `verify` | Provider-specific choice where needed, such as Secure Enclave `biometry-any`, `user-presence`, `biometry-current-set`, or PIV `pin-touch` / `biometric-or-pin-touch`. New Secure Enclave prompt keys default to `biometry-any`; existing bindings retain their creation policy. Unsupported or weaker combinations fail. |
| `slot` | Optional PIV/OpenPGP creation selector, validated against uses and algorithm. Existing bindings pin the actual slot; a different requested slot is a migration, not an automatic move. Without a creation selector, an explicit enrollment UI chooses a suitable empty slot. |
| `auth` | Required approval-credential reference for applicable composite providers; not needed for direct Secure Enclave/PIV/FIDO identities. |
| `algorithm` | Optional only for kinds supporting multiple reviewed algorithms; otherwise a documented fixed suite. Never opportunistically downgrade. Protocol/encoding version belongs in bindings and ciphertext too. |
| `preview` | Global feature gate, default false. Experimental kinds additionally need an explicit provider selection and suitable hardware; preview is not a policy downgrade switch. |
| `email` | Public-key comment/signing identity metadata; not authorization or capability. |
| `forge` | Per-key publication targets: a string such as `"github"` or a list such as `["github", "gitlab"]`. Roles derive from explicit `use` and the public-key format. Omitted or `[]` means no publication. |
| `github`, `gitlab` | Deprecated publication fields, accepted with diagnostics during migration; prefer `forge`. GitLab accepts `"auth"`, `"signing"`, or a list containing either/both. |

Derive forge registration roles from `use`, never key permissions from publication settings. New strict
composite TPM profiles create separate signing and decryption keys; a declaration
asking for both fails with instructions to split it. Existing dual-use keys remain
supported through their explicit compatibility provider. Other kinds permit combined
uses only where their operation/slot/policy matrix supports them.

## Inline providers and per-key overrides

Named providers are optional reuse, not the only place provider parameters can be
configured. The provider field set is `kind`, `auth`, `mode`, `verify`, `slot` and
`algorithm`; each is also accepted directly in `[keys.<handle>]`. Future
provider-specific parameters should follow this same rule, with the same typed
validation. Key metadata (`use`, `forge`, `name`, `email`, `bind`) stays on keys;
global settings such as `preview` remain global and cannot be overridden here.

### A provider defined entirely on one key

```toml
[auth.nano-approval]
kind = "fido2"
name = "YubiKey Nano"
bind = "seccy-authenticator:v1:<fido2-approval-credential>"

[keys.auth]
kind = "tpm-fido2-broker"
auth = "nano-approval"
mode = "prompt"
use = "ssh-auth"
```

The key's explicit `kind` bypasses the root provider selector, including on Linux
where the implicit platform default is unresolved. It starts with that kind's own
defaults; it does not inherit `auth`, `verify`, `slot` or `algorithm` from an unrelated
root-selected profile. Root `mode` still supplies a default when key mode is omitted.

### Reuse a provider, then override parameters on one key

```toml
provider = "token"
mode = "prompt"

[providers.token]
kind = "piv"
verify = "pin-touch"

[keys.auth]
use = "ssh-auth"
slot = "9a"

[keys.signing]
use = "ssh-sign"
slot = "9c"

[keys.recovery]
use = "secrets"
slot = "9d"
verify = "biometric-or-pin-touch"
name = "Bio Multi-protocol recovery key"
```

These are declarations for explicit creation on suitable hardware, not instructions
to overwrite occupied slots. Per-key overrides neither edit the shared profile nor
relax the provider's mandatory guarantees. For instance, `mode = "notify"` on a
TPM/FIDO key fails, and a biometric PIV policy requires compatible hardware.

Resolution and validation rules:

1. Reject a key containing both `kind` and `provider`, including when local overlays
   introduce the conflict. To customize a referenced provider, override its parameters
   without repeating `kind`; to select a different kind, use an inline key or select
   another provider. There is no ambiguous “same kind is okay” exception.
2. With inline `kind`, use that built-in implementation directly. Otherwise select
   the key's `provider`, root `provider`, or `default` in the normal order.
3. For `auth`, `verify`, `slot` and `algorithm`, key value overrides selected-profile
   value, then the implementation's documented default applies. Required fields with
   no default must be supplied. `mode` resolves key → selected profile → root → prompt.
4. Reject fields unsupported by the resolved kind; never silently ignore them. Thus
   an inline `auth` without `kind` is legal only if the inherited provider accepts it.
   Provider parameters cannot create a valid provider when selection itself is unresolved.
5. Validate the fully resolved settings against `use`, hardware capabilities and any
   existing immutable binding before private operations. Changing a creation-time
   parameter requires migration rather than rewriting a key's ACL or slot implicitly.

Local overlays may change parameter values using normal field precedence. A key-kind
change must leave a complete valid declaration: old provider-specific parameters
cannot be carried into an incompatible kind or silently discarded. Conflicting
`provider`/`kind` fields must be removed from their defining sources. Inspection
reports where each effective parameter came from, including key-level overrides.

### Existing configuration remains valid

```toml
[keys.signing]
mode = "notify"
github = "signing"
```

This existing macOS declaration keeps working with the default Secure Enclave
provider and deprecated GitHub field. Linux still needs an explicit provider under
the newly agreed selection rules. The key handle `signing` does not grant signing
permissions by itself; omitted `use` follows the legacy compatibility rules.

The equivalent recommended form keeps notify mode explicit:

```toml
[keys.signing]
mode = "notify"
use = "ssh-sign"
forge = "github"
```

## Configuration examples at a glance

Every example uses the **proposed schema**, including those mapping to existing
backends. They are independent alternatives, not blocks to concatenate into one
file. Bindings are illustrative placeholders that Seccy would generate; they are
not usable credentials. A profile's `kind` selects the implementation, whereas a
key inherits root `provider` unless it supplies an override. A selector can choose
a built-in kind, profile name, `default`, or an OS/host mapping.

### Key permissions and forge publication

`use = "secrets"` and `use = ["secrets"]` are equivalent. Normalize a scalar to a
one-element set internally; list order has no meaning. Reject unknown values,
duplicates, empty strings and an empty `use` list. The earlier proposed `uses`
spelling is superseded, not a second field to merge. Both auth and key display
names use `name`; the table handle remains the stable config reference.

```toml
[keys.secrets]
use = "secrets"
name = "Machine secrets"

[keys.recovery]
provider = "piv"
use = ["secrets"]
name = "Recovery YubiKey"
bind = "seccy-identity:v1:<piv-recovery-key>"

[keys.auth]
use = "ssh-auth"
forge = "github"

[keys.signing]
use = "ssh-sign"
forge = ["github", "gitlab"]

# One key serving both SSH roles, where its provider supports that combination.
[keys.shared]
use = ["ssh-auth", "ssh-sign"]
forge = ["github", "gitlab"]
```

`forge` chooses destinations, not permissions. It accepts a string or a list of
supported forge IDs (`github`, `gitlab` initially). Normalize like `use`, except an
empty list explicitly disables publication. Unknown/duplicate targets fail. An
omitted `forge` publishes nowhere; listing or provisioning does not itself publish
keys. Existing explicit sync commands remain responsible for remote changes.

| Explicit `use` | GitHub registration | GitLab registration |
| --- | --- | --- |
| `"ssh-auth"` | SSH authentication key | SSH key with `usage_type = "auth"` |
| `"ssh-sign"` | SSH signing key | SSH key with `usage_type = "signing"` |
| `["ssh-auth", "ssh-sign"]` | Register the public key for both SSH roles through their separate APIs | One SSH key with `usage_type = "auth_and_signing"` |
| `"openpgp-sign"` | GPG public-key registration through the planned adapter | GPG public-key registration through the planned adapter |
| `"secrets"` | No registration | No registration |

For a mixed set containing `secrets`, publish only roles corresponding to signing
or authentication. A nonempty `forge` with no publishable role is an error. New
`forge` declarations require explicit `use`, even where omitted permissions are
otherwise accepted for legacy compatibility. Do not guess a role from a key's name
or the forge API's default. Reject unsupported formats/provider-role combinations
before publishing; do not broaden permissions or silently skip a requested role.

GitLab accepts a single SSH usage scope including `auth_and_signing`; the list is
Seccy's config representation, not a JSON list passed to that API.
[GitLab user keys API](https://docs.gitlab.com/api/user_keys/).
GitHub exposes separate [SSH auth](https://docs.github.com/en/rest/users/keys),
[SSH signing](https://docs.github.com/en/rest/users/ssh-signing-keys) and
[GPG key](https://docs.github.com/en/rest/users/gpg-keys) APIs.

Deprecated compatibility examples (alternatives to `forge`, not fields to combine
with it on the same key):

```toml
[keys.auth]
use = "ssh-auth"
github = "auth"
gitlab = "auth"

[keys.signing]
use = "ssh-sign"
github = "signing"
gitlab = ["signing"]

[keys.shared]
use = ["ssh-auth", "ssh-sign"]
gitlab = ["auth", "signing"]
```

Preserve legacy `github = "auth"`/`"signing"` behavior and accept scalar/list GitLab
roles during migration, with deprecation diagnostics. Legacy role settings never
grant operations disallowed by explicit `use`. Reject an effective key containing
both `forge` and either deprecated field, including combinations produced by local
overlays. Migration must remove old fields from their defining sources explicitly.
Do not simply rename old fields if the resulting `forge` would publish extra roles:
show a concrete migration plan, retain the legacy form until resolved, or split the
key declarations/identities as appropriate. A per-forge role subset is intentionally
not another override in the new schema: every selected forge receives the same
publishable roles derived from `use`. Keep legacy omission of `use` compatible with
existing state, but materialize explicit permissions when migrating to `forge`.

### Default: auth, signing and secrets on a Mac

All three keys use Secure Enclave and require per-operation biometric approval.
No provider definitions, selection or mode setting are needed for this default.
The same omission on Linux leaves provider unresolved and key operations fail
with an actionable configuration error. Selecting the existing Linux backend
explicitly still does not add managed-secrets support to that backend.

```toml
email = "koss@nocorp.me"

[keys.auth]
use = "ssh-auth"
forge = "github"

[keys.signing]
use = "ssh-sign"
forge = "github"

[keys.secrets]
use = "secrets"
```

The implicit root settings are `provider = "default"`, `mode = "prompt"` and
`preview = false`. `use` is shown explicitly to make each key's role clear, and
`use = "secrets"` explicitly declares secrets eligibility. GitHub publication
is optional; remove the `forge` fields when not needed. For a Mac-only config,
root `provider = "secure-enclave"` makes the same backend selection explicit.

### Secure Enclave: notify signing, prompt secrets

Existing backend, proposed syntax. The per-key mode overrides the root mode.
Notify is deliberately limited to signing here; it cannot authorize managed secrets.

```toml
provider = "secure-enclave"
mode = "prompt"

[keys.auth]
use = "ssh-auth"

[keys.signing]
mode = "notify"
use = "ssh-sign"

[keys.secrets]
use = "secrets"
```

### Existing Linux TPM + FIDO2 hmac-secret

This compatibility profile refers to the existing locally initialized Linux vault.
Its approval credential remains in the existing vault metadata; this example does
not invent a portable binding for that state. Managed `seccy s` support is still
absent on Linux, so no managed-secrets key is advertised here. Legacy encryption
remains an existing compatibility capability outside the new `use` example.

```toml
provider = "linux-current"
mode = "prompt"

[providers.linux-current]
kind = "tpm-fido2-hmac"

[keys.auth]
use = "ssh-auth"

[keys.signing]
use = "ssh-sign"
```

### Shared Mac/Linux config with the planned FIDO2 approval broker

On Mac, the machine keys use Secure Enclave. On Linux, they use separate TPM keys
approved by the named FIDO2 credential. Sharing the approval credential does not
merge these keys or cache approval across operations. The authenticator declaration
is an approval identity, not a secrets recipient.

```toml
provider = { os = { macos = "secure-enclave", linux = "pc" } }
mode = "prompt"

[providers.pc]
kind = "tpm-fido2-broker"
auth = "nano"

[auth.nano]
kind = "fido2"
name = "YubiKey Nano — TPM approval"
bind = "seccy-authenticator:v1:<fido2-approval-credential>"

[keys.auth]
use = "ssh-auth"
forge = ["github", "gitlab"]

[keys.signing]
use = "ssh-sign"
forge = "github"

[keys.secrets]
use = "secrets"
```

For a different Linux workstation, a **separate `config.local.toml`** can supply a
PIV approval profile instead. This leaves the shared base and its FIDO profile
intact. Resolving a different provider for an already-created key still requires
migration; an overlay never replaces hardware keys on its own.

```toml
provider = { os = { linux = "pc-piv" } }

[providers.pc-piv]
kind = "tpm-piv"
auth = "piv-approval"

[auth.piv-approval]
kind = "piv"
verify = "pin-touch"
name = "YubiKey — TPM approval signing key"
bind = "seccy-authenticator:v1:<piv-approval-signing-slot>"
```

### Direct PIV: PIN plus touch

Planned. Each role uses its own slot/binding. The profile can be reused because it
does not pin one slot for all keys. At explicit creation, select suitable empty
slots; existing bindings already specify the slots and public keys. A secret key
generated on-device stays there, while encryption uses its public recipient.

```toml
provider = "token"
mode = "prompt"

[providers.token]
kind = "piv"
verify = "pin-touch"

[keys.auth]
use = "ssh-auth"
bind = "seccy-identity:v1:<piv-auth-key>"

[keys.signing]
use = "ssh-sign"
bind = "seccy-identity:v1:<piv-signing-key>"

[keys.secrets]
use = "secrets"
bind = "seccy-identity:v1:<piv-decryption-key>"
```

### Direct PIV: biometric verification with PIN-plus-touch fallback

Planned, for suitable Bio Multi-protocol hardware, not FIDO-only Bio. This is an
alternative to the previous PIV profile. `slot` below is a proposed creation hint;
the generated binding must confirm that same slot and its actual policy.

```toml
mode = "prompt"

[providers.bio-recovery]
kind = "piv"
verify = "biometric-or-pin-touch"
slot = "9d"

[keys.recovery]
provider = "bio-recovery"
use = "secrets"
name = "Bio Multi-protocol recovery key"
bind = "seccy-identity:v1:<piv-9d-recovery-key>"
```

`pin-touch` and `biometric-or-pin-touch` are the proposed PIV verification variants.
The latter must not be described as fingerprint-only. A corresponding `kind = "piv"`
approval authenticator may use either supported policy, but its bound slot must
support signing the TPM authorization rather than serving as the payload key.

### Native FIDO2 SSH credentials with separate machine secrets

Planned. These are direct key identities, so there is no `[auth]` table.
The FIDO credentials sign OpenSSH security-key messages; they cannot decrypt
secrets. The separate Secure Enclave identity provides that capability on this Mac.

```toml
mode = "prompt"

[providers.ssh-token]
kind = "fido2-ssh"

[keys.auth]
provider = "ssh-token"
use = "ssh-auth"
bind = "seccy-identity:v1:<fido2-ssh-auth-credential>"

[keys.signing]
provider = "ssh-token"
use = "ssh-sign"
bind = "seccy-identity:v1:<fido2-ssh-signing-credential>"

[keys.secrets]
provider = "secure-enclave"
use = "secrets"
```

### Direct FIDO2 secrets wrapping

Candidate; encryption decision still pending. The binding identifies an
hmac-secret-enabled credential. This is the portable recovery identity, not a
separate approval credential for another key. Both encrypting to it and decrypting
with it require the authenticator; its derived symmetric material enters RAM.

```toml
mode = "prompt"

[providers.portable-secrets]
kind = "fido2-hmac-secret"

[keys.recovery]
provider = "portable-secrets"
use = "secrets"
name = "Dotfiles recovery YubiKey"
bind = "seccy-identity:v1:<fido2-hmac-secret-credential>"

[keys.secrets]
provider = "secure-enclave"
use = "secrets"
```

The two keys become separate recipients when explicitly enrolled. They do not form
a combined authorization requirement: either recipient can decrypt independently.

### FIDO2-protected software decryption key

Candidate outside the hardware-only private-key guarantee. This illustrates provider
selection only: the encrypted software-identity artifact and its config reference
remain an open design decision, so this is not a complete provisioning recipe.
The binding alone cannot recover the software key. Public encryption is possible,
but decryption exposes that private key in host memory.

```toml
mode = "prompt"

[providers.portable-software-key]
kind = "fido2-wrapped-key"

[keys.recovery]
provider = "portable-software-key"
use = "secrets"
bind = "seccy-identity:v1:<software-public-key-and-fido2-binding>"
```

### OpenPGP card: separate signing, authentication and decryption roles

Planned, including the reviewed SSH adapter and managed-secrets format adapter.
Each binding pins the relevant card slot/subkey and its verified policy. OpenPGP
Git signatures use `openpgp-sign`, not `ssh-sign`. No generic PIN-policy spelling
is invented here: the provider must establish its per-slot policy before use.

```toml
provider = "card"
mode = "prompt"

[providers.card]
kind = "openpgp"

[keys.auth]
use = "ssh-auth"
bind = "seccy-identity:v1:<openpgp-authentication-subkey>"

[keys.signing]
use = "openpgp-sign"
bind = "seccy-identity:v1:<openpgp-signing-subkey>"

[keys.secrets]
use = "secrets"
bind = "seccy-identity:v1:<openpgp-decryption-subkey>"
```

### Experimental direct previewSign

Planned experimental signing only. `preview = true` is necessary but insufficient:
the extension, algorithm, policy and consumer format must all be supported.
Ordinary Secure Enclave/PIV P-256 signing does not require this switch.

```toml
preview = true
mode = "prompt"

[providers.raw-signing-token]
kind = "fido2-preview-sign"

[keys.signing]
provider = "raw-signing-token"
use = "ssh-sign"
bind = "seccy-identity:v1:<previewSign-signing-identity>"
```

### Experimental TPM + previewSign authorization

Planned experimental composite. The previewSign credential signs TPM policy
authorizations, while the separate TPM keys perform payload operations. Here
`fido2-preview-sign` is an authenticator kind as well as a direct provider kind;
their descriptors have different roles and cannot be substituted for one another.

```toml
preview = true
provider = "experimental-pc"
mode = "prompt"

[providers.experimental-pc]
kind = "tpm-fido2-preview-sign"
auth = "preview-approval"

[auth.preview-approval]
kind = "fido2-preview-sign"
name = "Experimental TPM approval token"
bind = "seccy-authenticator:v1:<previewSign-policy-authority>"

[keys.signing]
use = "ssh-sign"

[keys.secrets]
use = "secrets"
```

### Authenticator kinds and provider-specific parameters

| Context | `kind` / option | Reference or parameter |
| --- | --- | --- |
| TPM + FIDO broker | Provider `tpm-fido2-broker` | `auth` references an authenticator with `kind = "fido2"`. |
| TPM + PIV | Provider `tpm-piv` | `auth` references `kind = "piv"`; `verify` is `pin-touch` or supported `biometric-or-pin-touch`. |
| TPM + previewSign | Provider `tpm-fido2-preview-sign` | `auth` references `kind = "fido2-preview-sign"`; `preview = true` required. |
| Existing Linux vault | Provider `tpm-fido2-hmac` | Existing local vault enrollment; do not reinterpret it as a new broker credential. |
| Direct token key | `piv`, `openpgp`, `fido2-ssh`, or a direct FIDO secrets/signing kind | Key owns its `bind`; no extra approval-authenticator reference. |
| Secure Enclave | Provider `secure-enclave` | Local key binding in registry; no portable token binding or authenticator declaration. |
| PIV/OpenPGP creation | `slot` | Optional profile selector; existing binding is authoritative. Reusing a fixed-slot profile does not permit overwriting that slot for another key. |
| Algorithm selection | `algorithm` | Reserved for reviewed per-kind choices. Exact value sets remain undecided; examples use each kind's fixed/default suite rather than inventing interchangeable algorithms. |

`auth.<name>.kind` has its own allowed set: `fido2`, `piv`, and experimental
`fido2-preview-sign`. It is not the full provider catalog. Authenticator records
accept `name`, `bind`, and only parameters valid for that kind (such as PIV
`verify`/`slot`); mode comes from the operation's resolved key/profile.
Direct FIDO kinds enforce fresh UP/UV as part of their contract, without a
configurable touch-only alternative. Providers requiring multiple pieces of
hardware must verify all bindings rather than using an authenticator label as a
device selector.

## Built-in provider catalog

The IDs below are proposed configuration names. “Existing” means code is present,
not that every hardware/OS combination has passed physical-device verification.
Public encryption means encryption needs no private identity or attached token.

| Kind | Status / platform | Private operations | Modes | Boundary and encryption behavior |
| --- | --- | --- | --- | --- |
| `secure-enclave` | Existing, macOS | P-256 SSH auth/signing; legacy decryption; managed secrets | `prompt`; `notify` for existing SSH/legacy paths only | Hardware private key. Prompt uses current-set biometric ACL; notify has no biometric ACL. Public encryption. Managed secrets require prompt. |
| `tpm-fido2-hmac` | Existing, Linux compatibility | TPM P-256 SSH auth/signing and legacy decryption | `prompt` only | Hardware-generated TPM private key; FIDO-derived wrapping/authorization secrets enter the client. Public encryption. Managed `seccy s` integration is not implemented on Linux. |
| `tpm-fido2-broker` | Planned, Linux first | TPM signing or key agreement | `prompt` only | Broker verifies fresh FIDO assertions and authorizes PolicySigned. TPM holds the private key; broker remains a trusted policy authority. Public encryption. |
| `tpm-piv` | Planned, Linux first | TPM signing or key agreement | `prompt` only | PIV signing key authorizes operation-bound TPM PolicySigned; TPM holds the payload key. Public encryption. |
| `tpm-fido2-preview-sign` | Planned experimental | TPM signing or key agreement | `prompt` only | previewSign authorizes TPM policy; depends on experimental protocol/firmware and TPM interoperability validation. Public encryption via TPM public key. |
| `fido2-ssh` | Planned, macOS/Linux | Native OpenSSH security-key auth and SSHSIG | `prompt` only | Hardware credential, mandatory UP/UV, `sk-*` signature format. No secrets decryption. SSHSIG consumer support must be checked. |
| `piv` | Planned, macOS/Linux | Slot/algorithm-dependent SSH auth/signing and key agreement/decryption | `prompt` only | Keys generated on-device; public encryption. Require explicit per-operation verification/touch policy and suitable slot. |
| `openpgp` | Planned, macOS/Linux | OpenPGP signing/decryption; SSH authentication only through a reviewed authentication-slot adapter | `prompt` only initially | On-device keys, separate slot policies. Public encryption possible, but OpenPGP ciphertext/signatures are separate formats, not automatic compatibility with the Seccy envelope. |
| `fido2-preview-sign` | Planned experimental | Raw P-256 signing | `prompt` only | Hardware signing key; neither ordinary FIDO auth nor a decryption primitive. No secrets support. |
| `fido2-hmac-secret` | Candidate, decision pending | Symmetric secrets wrapping/unwrapping | `prompt` only | Credential root stays in authenticator; derived wrapping material enters host memory. Token needed for encryption and decryption. |
| `fido2-wrapped-key` | Candidate, decision pending; outside strict private-key guarantees | Software encryption identity unlocked by FIDO2 | `prompt` only | Public encryption, but persistent private decryption key enters host memory. Explicit opt-in kind; never an automatic fallback. |

The Linux compatibility implementation decrypts an **outer wrapper around a TPM
blob**, not a plaintext P-256 scalar. The exposed reusable authorization material
is still a material policy weakness compared with the proposed broker flow. Do not
describe existing `seccy-tpm` as already enforcing FIDO-bound PolicySigned.
Evidence: [vault operations](../pkgs/linux/src/vault.rs),
[native TPM operations](../pkgs/linux/src/native.c), and
[current Linux guarantees](linux/README.md).

No kind named `fido2` alone should be accepted as a key provider: native SSH,
symmetric wrapping, raw-signature extensions and TPM approval are different
capabilities with different security guarantees.

## Authorization is part of the provider

Keep `mode` for compatibility and user comprehension, but validate its meaning
against the concrete provider. `prompt` never means “show a dialog and proceed”;
the required hardware or broker authorization must succeed. Changing a mode/profile
does not retrofit an existing key's ACL or TPM policy. Treat differences affecting
the key's creation contract as migration-required.

For each resolved identity, report separate properties rather than a vague
`secure = true`: private-key location/exportability, approval enforcement boundary,
verification/presence requirements, whether reusable authorization or derived
secrets enter the host, public-encryption availability, portability, supported
operations, experimental status and hardware-validation status. These are computed
capabilities, never user assertions that can elevate a weak backend into a strict one.

FIDO requires verified assertion signatures, RP/challenge binding and UP/UV checks.
Per-operation host behavior must avoid consent/PIN-token caching, but cannot prove
that a compromised host did not retain a PIN or derived secret. `prompt` must not
claim otherwise.

PIV `pin-touch` requires PIN Always and Touch Always. The alternative
`biometric-or-pin-touch` permits supported MatchAlways behavior and an explicitly
defined PIN-plus-touch fallback; it is not fingerprint-only. Require policy evidence
from the device/attestation where available and fail if the guarantee cannot be
established. PIV policies are set at generation/import, and Bio FIDO Edition is not
PIV-capable. [Yubico PIV policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html)

TPM PolicySigned profiles must bind the session nonce, exact command/parameters,
policy reference and bounded validity, prevent replay/ticket reuse, and remove
password/HMAC bypass paths. The broker profile additionally protects credential
enrollment and verifies the caller; kernel/service compromise is a separate threat
from client compromise. [TPM PolicySigned parameters](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policysigned.1/)

Ordinary P-256 SSH/Git signatures are not preview features. Only extension-dependent
kinds are gated: Yubico currently documents previewSign as non-production and subject
to incompatible change. [Signing extension status](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html)

## OS/host selectors and shared dotfiles

A provider selector is either a string or a table containing exactly one of `os`
or `host`. It is accepted at the root and on individual keys. Map values are strings
naming built-in kinds, custom profiles, or `default`; nested selectors, combined
OS/host maps, wildcard patterns and profile inheritance are not supported initially.
Use the canonical field spelling `provider` throughout.

```toml
# Explicit platform selection. Missing OS entries use that OS's default.
provider = { os = { macos = "secure-enclave", linux = "workstation" } }

[providers.workstation]
kind = "tpm-fido2-hmac"

[keys.auth]
use = "ssh-auth"
```

```toml
# Equivalent on macOS; Linux selects the explicitly configured profile.
provider = { os = { linux = "workstation" } }

[providers.workstation]
kind = "tpm-fido2-hmac"

[keys.auth]
use = "ssh-auth"
```

```toml
# Host-specific alternative; no automatic hostname-to-backend guessing.
provider = { host = { kossbook = "secure-enclave", kosspc = "workstation" } }

[providers.workstation]
kind = "tpm-fido2-hmac"

[keys.auth]
use = "ssh-auth"
```

```toml
# Equivalent to omitting provider, or to the built-in OS default map below.
provider = "default"

[keys.auth]
use = "ssh-auth"
```

The built-in default is conceptually
`provider = { os = { macos = "secure-enclave" } }`: macOS resolves to Secure Enclave;
Linux and other unsupported-default platforms resolve to `None`. `None` is an
internal unresolved result, not a TOML value or a provider named `none`. Thus an
empty OS map or a missing Linux entry does not select the existing Linux backend.
The default mapping is stable; adding a backend in a release must not silently
change an existing configuration's resolution.

Resolution is deterministic:

1. If the key declares inline `kind`, select that implementation directly and reject
   a simultaneous key `provider`. Otherwise use the key's selector if present;
   otherwise the root selector; otherwise `default`.
2. A concrete string resolves to the named built-in kind/profile. Unknown names fail.
3. For an OS map, use the current OS entry (`macos`, `linux`; additional IDs only
   when explicitly supported). For a host map, use the exact local hostname returned
   by the OS hostname API, with no DNS lookup, case folding, suffix stripping or
   environment override. Inspection shows this value so users need not guess it.
   Quote TOML host keys containing dots. A hostname selects configuration; it is not
   cryptographic evidence or an authorization factor.
4. A missing current OS/host entry, or an entry set to `default`, resolves directly
   to the built-in default for the current OS. It does not retry a root selector or
   another map. Host fallback to the OS default is the proposed consistent behavior.
5. If still `None`, fail before any key creation or private operation with
   `provider_unresolved` and show the key, OS/host, source and how to choose a provider.
   Public config inspection remains available to explain the failure.
6. Resolve profile parameters, mode and capabilities, then validate platform support
   and immutable bindings. An explicit but unsupported choice is an error, never a
   reason to try the platform default.

A per-key selector replaces the entire inherited root selector. An omitted key
selector inherits it unchanged unless inline `kind` selects an implementation
directly; an explicit key `provider = "default"` bypasses the root selector.
For example, an explicit Linux-only key map on macOS uses the built-in Secure Enclave
default, not a different root provider. This prevents hidden multi-stage fallback.
Root selectors overridden by local files also replace as whole values; their map
entries are not merged across files. Other unrelated config fields still merge.

Shared config can define multiple profiles without selecting any of them implicitly.
A local `config.local.toml` can set root `provider` to an OS/host selector or a direct
profile for that workstation. No hostnames are required when OS selection suffices.
A common `keys.auth` declaration resolves to different actual public keys on different
machines; its logical name is not a portable recipient. Export separately named,
fingerprinted machine recipients such as `laptop-<short-fingerprint>`.

Registry records pin the concrete resolved kind, algorithm, mode, authorization
binding, generation and public fingerprint. Changing a selector, hostname or profile
cannot silently redirect an existing key. Differences affecting immutable parameters
produce `migration_required`. Cosmetic names/labels, comments and publication targets
can change without regenerating keys. Reloads must not combine an old binding with
a new policy halfway through an operation.

## Portable bindings and provisioning lifecycle

A portable identity descriptor is a versioned, canonical typed record with an
integrity fingerprint, generated/exported by Seccy. Its fields include the concrete
provider and public key/credential identity. FIDO adds RP, credential ID, public
verification key and required extensions/protection; PIV adds slot, algorithm and
public key with available policy/generation evidence; OpenPGP uses its key/subkey
fingerprints and card application details. AAGUID, serial and label are hints or
evidence inputs, never substitutes for cryptographic verification.

Use a single encoded `bind` value initially to avoid users manually combining
credential fields from different enrollments. Inspection provides decoded public
metadata as JSON. Bindings contain no PIN, TPM authorization value, derived wrapping
key or plaintext private key. If `fido2-wrapped-key` is adopted, its encrypted private
identity is a separate, explicitly classified artifact, not mislabeled public data.

Machine bindings remain in local state; copying a TPM blob or Enclave reference does
not make it portable. Portable bindings may live in reviewed dotfiles. A hash detects
accidental change but is not proof of trusted origin; imported bindings need a trusted
fingerprint/source and must be matched against the physical credential at use.

Proposed lifecycle:

1. **Declare**: key/profile exists in config, with requested uses and no created key.
2. **Create**: an explicit operation creates a new hardware credential/key and records
   its immutable generation. Never overwrite an occupied PIV/OpenPGP slot implicitly.
3. **Attach**: load and verify an existing portable binding without creating anything.
   Fresh-machine secrets use can attach for that operation without a local registry.
4. **Enroll recipient**: add the existing identity's recipient to a selected secrets
   file. This is independent of creating a key and does not re-encrypt existing data.
5. **Rotate/migrate**: create a new generation, verify it, re-encrypt selected secrets,
   reconcile remote registrations, then explicitly retire the previous generation.

`provision` stays idempotent. It creates missing machine keys explicitly requested
by the user, but never creates/replaces a portable credential merely because local
state is absent. First portable creation needs an explicit create action; provision
with an existing binding verifies/attaches it. An absent device is `unavailable`, not
`unprovisioned`. Multiple devices require a picker/hint when protected credentials
cannot be probed silently; do not emit a series of surprise verification prompts.

Use immutable generation IDs for internal storage and retain full fingerprints.
Where a storage label must be assigned before public-key generation, use a random
generation ID and attach/index the fingerprint afterward. Human handles can move to
new generations only through explicit migration; old generations remain addressable
for decryption. Remote titles include human handle, machine scope where applicable,
and fingerprint, with full-key comparisons to avoid shortened-hash collisions.

Provisioning and remote synchronization cannot be one filesystem transaction.
Journal completed operations, preserve old keys on partial failure, and make retries
idempotent. Do not automatically edit or commit every repository containing old
ciphertext; migration reports its scope and outstanding recipients.

## Configuration files, overlays and selectors

Keep key/provider configuration separate from secrets files. Project `seccy.toml`
does not implicitly become authority to provision keys, alter hardware policy, turn
on preview or replace an approval credential. Bootstrap selects a reviewed key
config explicitly through `--config`.

Proposed precedence, lowest first:

| Data | Sources |
| --- | --- |
| Key config | Global `config.toml`, then sibling `config.local.toml`. No ancestor discovery. |
| Secrets | Global `secrets.toml`, global `secrets.local.toml`, then each directory from `/` to cwd: `seccy.toml`, followed by `seccy.local.toml`. |

Local-only files count. The requested example therefore applies B → A → C → D → E;
the nearer base E overrides both base and local definitions farther away. Discovery
UI may display nearest first, but evaluation always applies lowest precedence first.

Merge named configuration tables by field; scalar fields and arrays replace, never
append. Provider selectors replace atomically, including their OS/host maps.
Empty lists explicitly clear list settings where allowed, such as `forge`;
`use = []` is invalid rather than an implicit default. Unknown fields fail. Typed
`providers.<name>` and `auth.<name>` records may merge only while their
`kind` stays the same; changing kind requires a whole valid replacement, and still
cannot migrate an already-bound key. Key `provider` changes trigger the registry
compatibility checks above. Treat binding strings and each secret record as atomic:
never combine ciphertext from one file with recipient names from another.

Validate in stages: parse every file and check names, kinds, references and permitted
fields; resolve the active platform/key; compare its immutable contract with any
existing binding; then probe actual capabilities before an operation. Profiles for
another platform may remain in shared config without requiring its hardware or
driver. Known planned kinds can be reported as unavailable, but selecting one for an
operation fails explicitly. Unknown names/parameters never silently disappear.
Two declarations cannot create different keys in the same occupied hardware slot;
aliases for one binding must not accidentally create duplicate recipients.

Recipient aliases remain an intentional safety exception to ordinary overriding:
the same alias with different public material is an error, including in local
overlays. Use a new alias and explicit re-encryption. Identical repeated recipients
are harmless. Validate each secret against the recipient definitions available at
its own level before a nearer secret override; do not silently hide corrupt input.

Resolve path flags once before config loading:

- `--config PATH` / `-c` (compatibility alias `--c`) relocates the global key-config
  base and its companion local file; it never changes the secrets path.
- `--global-secrets PATH` / `--gs` relocates the global secrets base and companion.
  For a custom `foo.toml` base, its companion is `foo.local.toml`. An explicitly
  selected `*.local.toml` is used directly with no extra companion.
- `-g` / `--global` limits secrets reads to the global base/local pair, excluding
  all project ancestors. It does not restrict where key identities are resolved.
- `-s` / `--secrets PATH` selects exactly that secrets file, without any automatic
  companion or inheritance. Mutations choosing a picker row are equivalent to this.
- `SECCY_IDENTITY` overrides `--identity` / `-i`; otherwise retain automatic matching.
  Empty/invalid/unavailable explicit identities fail, never fall back. For `exec`,
  everything after `--` belongs to the child command.

Reads merge automatically. Mutations never spread edits across files implicitly.
Keep the current keyboard file picker when multiple possible write targets exist,
showing provenance and public names. With `-g` and both global files present, offer
those two targets; noninteractive/structured output requires `-s` to disambiguate.
If only a base exists, do not silently create a local overlay. Set/remove/reencrypt
operate on the selected exact file. Explain when removing an override reveals an
ancestor value. Preserve locks, comment retention, symlink checks and atomic writes.

Config editing follows the same provenance discipline: write a portable binding to
the explicitly selected config, not an arbitrary overlaid source. Never rewrite a
shared base just because a host-local enrollment was created. Normal provisioning
pins machine-specific bindings in state instead.

## Secrets formats and bootstrap

Keep provider selection separate from the encryption wire suite. Existing `seccy-se1`
recipients and `seccy:secrets:v1` envelopes remain readable. A heterogeneous envelope
needs versioned typed recipient descriptors/stanzas, domain-separated derivation,
authenticated recipient identities, secret names and suite/version metadata, bounded
sizes, and strict rejection of unknown algorithms. Do not reinterpret legacy Apple
ECIES bytes as TPM/PIV ECDH ciphertext because both use P-256.

Plan a v2 envelope and a provider-specific wrapping interface. The payload remains
authenticated symmetric encryption with a fresh per-secret data key. The recipient
interface reports whether wrapping is public-only or requires an authenticator.
Validate all selected recipients and capabilities before reading plaintext or
starting private operations. Never drop an unavailable recipient to finish a write.
`set`/`reencrypt` with a symmetric FIDO recipient must request that token even when
decryption used the machine key. Public-key providers still encrypt offline.

Per-operation authorization applies to every required unwrap/wrap; no silent batching
or caching. Metadata and plaintext keys have different lifetimes and logging rules.
JSON/query output may expose public bindings and capability/provenance information,
never PINs or derived secrets; plaintext remains limited to explicit get/exec paths.

The portable encryption decision remains open:

| Choice | Preserves | Sacrifices |
| --- | --- | --- |
| Direct FIDO2 symmetric wrapping | Portability without a persistent software asymmetric key | Public-only encryption; derived secret appears in RAM |
| FIDO2-protected software identity | Portability and public-only encryption | Hardware-only private-key guarantee |
| PIV identity generated on-device | Portability, public encryption and hardware private key | Compatibility with FIDO-only devices; requires PIV policy/middleware support |

FIDO hmac-secret must be enabled when creating the credential, and produces derived
symmetric material. Do not assume an existing native SSH credential can acquire it
later. [Yubico extension semantics](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)

Proposed fresh-machine sequence (future commands/options, not current instructions):

```sh
# Repository includes an unencrypted, reviewed config with the portable binding.
seccy s get EMAIL -c ./bootstrap/config.toml -s ./seccy.toml -i recovery
# Generate dotfiles; the portable private capability never needs local provisioning.
# Once the normal config exists, create only the new machine's secrets key.
seccy provision secrets
seccy s enroll secrets -s ./seccy.toml --name laptop-<fingerprint>
seccy s reencrypt -s ./seccy.toml -i recovery
# Verify both paths before committing ciphertext and public metadata.
seccy s get EMAIL -s ./seccy.toml -i secrets
```

`enroll` is public-recipient management; it need not decrypt a secret and `-i` must
not change the positional key being enrolled. Re-encryption is the step that uses
the portable decryption identity. Existing machine keys can be enrolled without
provisioning again; a new Secure Enclave key necessarily needs an explicit creation.

## Sessions, integrations and diagnostics

Reserve `seccy s session -- <command>` for the future authenticated-session feature.
It starts no environment export. Subsequent get calls still reveal plaintext to
their callers. Authorization must be tied to OS-verified process scope, expiry,
revocation and child inheritance, not an environment variable bearer secret.
Hardware policies requiring verification per operation cannot be bypassed by a
session; report unsupported rather than weakening them. Any future session-capable
provider is explicitly distinct and must define its own approval boundary.

Keep SSH signatures, OpenPGP signatures and recipient encryption capabilities
separate. `forge` publication derives roles from `use` and checks format, provider/host support
and authentication scopes; missing remote support is an error, never a reason to
replace a hardware key. `gh sync` and future `glab sync` reconcile fingerprinted
generations, avoid duplicating portable identities per machine, and retire old
registrations only after the explicit rotation plan permits it. GitLab host selection
belongs to integration settings, not crypto providers. Preserve fnox and legacy
encrypt/decrypt formats with explicit adapters and gradual migration documentation.

Proposed inspection commands: `seccy providers list` for built-in support and
`seccy config inspect` for effective profile/field provenance. Both support JSON/jq.
Key inspection should separate configuration validity, binding presence, device
availability and verified usability: listing must not touch every authenticator.
Report stable statuses such as `unsupported_provider`, `preview_disabled`,
`binding_missing`, `device_unavailable`, `policy_mismatch`, `migration_required`
and `not_a_recipient`; do not present missing hardware as missing key material.

Prompts identify operation, logical key, selected binding/device hint and requesting
process. Decryption names the secret; signing describes the signed purpose; notify
uses completed-action wording. Untrusted labels are escaped, ciphertext/plaintext
is not echoed, and metadata shown before authenticated decryption is not presented
as proof of a trusted sender. Cancellation never tries another identity or policy.

## Implementation sequence and remaining decisions

1. Implement the provider parser/resolver, capability catalog and diagnostics with adapters
   for **existing** Secure Enclave and Linux TPM/FIDO behavior. No new cryptography.
   Add local overlays/path flags and deterministic provenance tests at this layer.
2. Version registry bindings and explicit generations; implement idempotent migration,
   targeted provisioning and portable attach/create separation. Preserve legacy
   key material and policy: macOS → Secure Enclave; Linux requires an explicit
   selection (existing installations can select `tpm-fido2-hmac`), never auto-upgrade.
3. Implement the chosen portable secrets provider and reviewed v2 envelope with
   fresh-machine bootstrap and mixed-recipient tests. Finish physical-device checks.
4. Implement the stronger TPM broker/PolicySigned path and explicit migration; then
   PIV/native FIDO SSH/OpenPGP adapters and experimental previewSign as separate work.
5. Extend publication/rotation and evaluate sessions only for policies that can
   honestly support them.

All configs use the same unversioned schema with additive, strictly validated fields.
Existing macOS configs without provider fields retain their backend. Existing Linux
configs need an explicit provider selection before key operations; inspection and
migration tools should explain this change and offer a config-only edit selecting
`tpm-fido2-hmac`, without replacing keys or choosing the future broker implicitly.
An omitted `use`
on an existing backend preserves its SSH/legacy operations and any explicit secrets
enrollment recorded in state; it never infers secrets permission from a key name.
An explicit `use` list narrows those operations or requests new eligibility through
the appropriate enrollment/authorization flow. Removing `secrets` from an explicit
list prevents its use even if older state recorded enrollment. For portable planned
kinds, explicit `use` plus a verified binding permits bootstrap without local state.
Migration materializes provider/mode/use from actual registry state, preserving
the explicit secrets flag.
Do not infer enrollment from a key's name. Existing notify keys stay notify and are
not eligible for managed secrets. Adding schema support must not create keys or
change remote registrations. Each supported combination gets a dedicated document
under `docs/providers/<kind>.md` before release.

Decisions still required: which portable encryption option(s) to implement first;
whether to offer the software-key option at all; exact v2 cryptographic suites and
serialization after review; per-device attestation acceptance requirements; final
create/attach/rotate command spelling; and whether any session-capable provider is
worth its weaker per-operation guarantee. The named-provider model can be implemented
without pretending those decisions have already been made.

Acceptance tests span all related roadmap items: legacy migration and no key churn;
inline/named provider equivalence, per-key parameter precedence and kind/provider conflicts;
profile/OS/host resolution, missing-map defaults, Linux unresolved errors and drift detection; malformed/unknown fields; overlays
including B/A/C/D/E, local-only files and recipient conflicts; selectors and stdin;
wrong-device/UV/cancellation paths; hardware capability checks and preview gates;
replay and command substitution in TPM policies; mixed-envelope authentication;
atomic writes/recovery journals; alias reuse and old-generation decryption; remote
publication duplicates/rotation/hosts; JSON/jq redaction; and real hardware tests
separate from emulator/mock assertions.
