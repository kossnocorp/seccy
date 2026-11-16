## Shared product copy. Keep legacy system prompts in core/src/prompt.rs unchanged.
## Variables are literal display values, never Markdown or UI markup.

ui-window-title = Seccy · Authorize request
ui-key = Key
ui-process = REQUESTING PROCESS
ui-process-chain = Process chain
ui-request-only = Approval applies to this request only.
ui-host-warning = Server identity needs attention
ui-cancel = Cancel
ui-touch-id = Use Touch ID
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
gallery-request = Request
gallery-live = Live Touch ID
gallery-state = State
gallery-appearance = Prompt appearance
gallery-show = Show prompt
gallery-start = Start Touch ID demo
gallery-notifications = Notifications
gallery-notification-description = Uses native macOS notifications with the Seccy icon. macOS may ask for notification permission for the gallery.
gallery-notification-send = Send test notification
gallery-scenario-signing = Git signing
gallery-scenario-secrets = Secrets batch
gallery-scenario-revoked = Revoked host
gallery-scenario-long = Long / untrusted text
gallery-appearance-system = System
gallery-appearance-light = Light
gallery-appearance-dark = Dark
