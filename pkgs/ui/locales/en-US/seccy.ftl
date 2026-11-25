## Shared product copy. Keep legacy system prompts in core/src/prompt.rs unchanged.
## Variables are literal display values, never Markdown or UI markup.

ui-window-title = Seccy · Authorize request
ui-key = Key
ui-process = REQUESTING PROCESS
ui-process-chain = Process chain
ui-chain-previous = Previous process
ui-chain-next = Next process
ui-request-only = Approval applies to this request only.
ui-host-warning = Server identity needs attention
ui-cancel = Deny
ui-touch-id = Authorize with { ui-touch-id-name }
ui-touch-id-name = Touch ID
ui-details = Request details
ui-working-directory = Working directory
ui-touch-id-accessibility = Touch ID authentication
ui-state-ready = Ready
ui-state-authenticating = Touch ID
ui-state-success = Approved
ui-state-failure = Failed
ui-state-unavailable = Unavailable
ui-state-cancelled = Cancelled
ui-state-warning = Host warning
ui-status-ready = Use Touch ID to approve this request.
ui-status-authenticating = Place your finger on Touch ID.
ui-status-success = Identity verified.
ui-status-failure = Authentication failed. Try again or cancel.
ui-status-unavailable = Touch ID is unavailable. No access was granted.
ui-status-cancelled = Request cancelled. No access was granted.
ui-status-warning = Review the server key warning before approving.
ui-pid = PID { $pid }

header-permission = Allow { $app } to use { $key }
ui-request-diagnostics = Request and signing payload
ui-process-diagnostics = Full process snapshot
ui-chain-incomplete = Incomplete process chain
ui-retry = Retry Touch ID
ui-chain-running = running in
ui-chain-let = Let
ui-chain-use = use
ui-chain-to = to
prompt-chain = Let { $chain }
prompt-location = running in { $dir }
prompt-use = use { $keys } to { $action }?
prompt-decrypt = use { $keys } to { $action } { $names }?
prompt-title-ssh = Sign in with SSH?
prompt-title-commit = Sign Git commit?
prompt-title-tag = Sign Git tag?
prompt-title-git = Sign Git data?
prompt-title-sign = Sign data?
prompt-title-secrets = Decrypt secrets?
prompt-action-ssh = sign in as { $target }
prompt-ssh-target = { $user }@{ $host }
prompt-action-commit = sign a Git commit
prompt-action-tag = sign a Git tag
prompt-action-signature = sign data for { $namespace }
prompt-action-unknown = sign data of unknown purpose
prompt-action-secret = decrypt a secret
prompt-action-named = decrypt
ui-secret-list = Requested secrets
ui-request-details = Request details
ui-no-request-snapshot = No request snapshot available.
request-popover-title = { $operation ->
    [commit] Git commit sign request
    [tag] Git tag sign request
    [sign] Git signing request
    [push] Git push request
    [pull] Git pull request
    [fetch] Git fetch request
    [clone] Git clone request
    [ls-remote] Git remote lookup request
    [ssh] SSH authentication request
    [decrypt] Secret decryption request
   *[signature] Signing request
    }
ui-chain-using = using
ui-chain-more = %d more
ui-chain-all = All processes
ui-chain-others = Other processes
ui-chain-back = Back
ui-key-action-ssh = authenticate over SSH
ui-key-action-decrypt = decrypt secrets
ui-key-action-sign-git = sign Git data
ui-key-action-sign = sign data
ui-key-action-use = perform this operation
ui-chain-limited = Limited snapshot · kernel process table
ui-chain-unrecorded = Parent not recorded in this capture · PID
ui-key-fingerprint = Fingerprint
ui-key-algorithm = SSH algorithm
ui-key-public-file = Public key file
ui-key-show-in-finder = Show public key in Finder
ui-path-show-in-finder = Show in Finder
gallery-capture-open = Open capture…
gallery-capture-clear = Back to examples
gallery-capture-replay = Captured request · preview only
ui-capture-error-format = Unsupported request capture format or version.
ui-capture-error-size = Request captures must be no larger than 64 MiB.
ui-capture-error-directory = The capture directory must be a private directory with permissions 0700.
header-git-title = { $operation ->
    [push] Authorize Git push?
    [pull] Authorize Git pull?
    [fetch] Authorize Git fetch?
    [clone] Authorize Git clone?
    [ls-remote] Authorize Git remote access?
    [commit] Sign Git commit?
    [tag] Sign Git tag?
   *[sign] Sign Git data?
    }

notification-key = seccy: key used
notification-secret = seccy: secret decrypted
notification-error-bundle = Native notifications require the Seccy.app bundle. Run the signed bundled executable.
notification-error-denied = Notifications are disabled. Enable notifications for this app in System Settings → Notifications.
notification-error-system = macOS could not authorize or submit the notification.
notification-error-timeout = Notification permission or submission timed out.

request-sign-title = Approve this signing request?
request-git-title = Approve the { $operation }?
request-ssh-title = Approve this SSH authentication?
request-secret-title = Decrypt a secret?
request-named-secret-title = Decrypt secret { $names }?
request-secrets-title = Decrypt secrets { $names }?
notification-sign-title = Data signed.
notification-ssh-title = SSH authentication request signed.
notification-secret-title = Secret decrypted.
notification-named-secret-title = Secret { $names } decrypted.
notification-secrets-title = Secrets { $names } decrypted.

## Fluent message references keep common sentence structure in the catalog. Each body is a
## complete translation unit, allowing translations to reorder all its parts.
actor = The process chain { $chain }{ $location ->
    [none] { "" }
   *[directory] { " " }running at { $directory }
    }
use-key = { $mode ->
    [notify] used
   *[prompt] wants to use
    } the { $key } key
request-unknown-body = { actor } { use-key } to sign data whose purpose could not be identified.
request-commit-body = { actor } { use-key } to sign a Git commit.
request-tag-body = { actor } { use-key } to sign a Git tag.
request-git-body = { actor } { use-key } to sign Git data.
request-signature-body = { actor } { use-key } to create an SSH signature in the { $namespace } namespace.
request-ssh-body = { actor } { use-key } to authenticate over SSH as { $username }.
request-ssh-host-body = { actor } { use-key } to access { $username }@{ $host }{ $port-present ->
    [no] { "" }
   *[yes] { " " }(port { $port })
    }.
request-secret-body = { actor } { use-key } to decrypt a secret.
request-named-secret-body = { actor } { use-key } to decrypt secret { $names }.
request-secrets-body = { actor } { use-key } to decrypt secrets { $names }.
warning-revoked = [REVOKED] Server key matches a revoked known_hosts entry
warning-unknown-host = No matching key in searched known_hosts files
warning-missing-host = No server host key included

gallery-auth-reason = Preview Seccy's Touch ID animation. No keys will be accessed.
gallery-notification-submitting = Submitting notification…
gallery-notification-submitted = Submitted as Seccy UI Gallery. macOS notification settings and Focus control banner visibility.
gallery-title = Seccy Preview Controls
gallery-description = The separate prompt uses the production window and layout. All requests here are samples; no keys are accessed.
gallery-request = Action
gallery-hosting = Git hosting
gallery-key = Key name
gallery-directory = Directory
gallery-directory-choose = Choose…
gallery-directory-panel = Choose a directory to preview
gallery-hosting-github = GitHub
gallery-hosting-gitlab = GitLab
gallery-hosting-bitbucket = Bitbucket
gallery-hosting-generic = Other / unknown
gallery-scenario-push = Git push
gallery-scenario-pull = Git pull
gallery-scenario-fetch = Git fetch
gallery-scenario-clone = Git clone
gallery-scenario-ls-remote = Git ls-remote
gallery-scenario-tag = Git tag signing
gallery-live = Live Touch ID
gallery-state = State
gallery-appearance = Prompt appearance
gallery-show = Show prompt
gallery-start = Start Touch ID demo
gallery-notifications = Notifications
gallery-notification-description = Uses native macOS notifications with the Seccy icon. macOS may ask for notification permission for the gallery.
gallery-notification-send = Send test notification
gallery-scenario-signing = Git commit signing
gallery-scenario-secrets = Secrets batch
gallery-scenario-revoked = Revoked host
gallery-scenario-long = Long / untrusted text
gallery-scenario-github = GitHub push
gallery-scenario-gitlab = GitLab fetch
gallery-scenario-bitbucket = Bitbucket pull
gallery-scenario-generic = Other Git host
gallery-appearance-system = System
gallery-appearance-light = Light
gallery-appearance-dark = Dark
