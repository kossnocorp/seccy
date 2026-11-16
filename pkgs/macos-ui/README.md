# Seccy macOS UI

SwiftUI presentation with a small C ABI bridge to the Rust agent. Requires macOS
12+ and a full Xcode installation to build. Linux builds skip Swift entirely.

## Enable the experimental prompt

The default remains Apple's built-in authentication window and the original
plain-text reason. To opt in, add this to `~/.config/seccy/config.toml` (or the
corresponding `$XDG_CONFIG_HOME/seccy/config.toml`), then restart the agent:

```toml
[experimental]
macos_ui = true
```

Omitting the setting or setting it to false preserves the old prompt and CLI
execution path. The setting is read at process startup. Previewing the gallery
does not change it.

## Development

- `mise run macos:ui`: build and run the gallery in the foreground, with live JSON event logs on stdout. Quit any older gallery first; Ctrl+C stops this process.
- `mise run macos:ui:check`: build the gallery and run Swift tests.
- Open `SeccyUI.xcodeproj`, choose **Gallery**, and Run. The gallery uses ad-hoc bundle signing;
  no Developer ID profile is needed. `AuthorizationView_Previews` also opens in Canvas.
- The **SeccyUI** scheme builds the static UI library independently.
- `python3 pkgs/macos-ui/generate-project.py` regenerates the checked-in project
  and shared schemes using only Python's standard library.

The gallery opens two windows: **Seccy Preview Controls** and the standalone
**Seccy · Authorize request** prompt. The latter uses the same window factory,
size, title bar, and SwiftUI content as production, without a preview badge.
Settings update that window live; **Show prompt** reopens it after cancellation.
Both app bundles use `assets/icon-macos.png` through the shared icon build script.

**Send test notification** submits sample text through the same
native UserNotifications service as production. The sender uses the bundle's
Seccy icon: **Seccy** in production and **Seccy UI Gallery** in the preview.
Each bundle has its own macOS notification permission. The first send asks for
permission; denied permission and submission failures appear in controls.
Settings and Focus may hide banners; submission does not guarantee visibility.
No AppleScript, shell, Finder-opening action, or custom action button is involved.

The gallery defaults to **Live Touch ID**, displaying the same native fingerprint
component as the real prompt. Click **Start Touch ID demo** to evaluate biometrics
and see the sensor-driven animation. The demo uses its own context, never returns
it to Rust, and never accesses keys or signs anything. Cancel, leaving the gallery,
or disabling live mode invalidates that context. Retry starts with a fresh context.

Disable **Live Touch ID** for simulated request/state pickers. Both modes offer
System/Light/Dark appearance.
Scenarios cover signing, a secrets batch, a revoked host key, long process chains,
Unicode and spoofing controls. States cover ready, Touch ID, approved, failed,
unavailable, cancelled and host warning. These selectable states are simulations; no biometric evaluation runs in simulated
mode. No key operation is available in either gallery mode.

## Live editing

For automatic updates while editing SwiftUI, open `SeccyUI.xcodeproj`, select
**Gallery** and the **My Mac** destination, and open
`Sources/AuthorizationView.swift`. Show Xcode's Canvas and resume the
`AuthorizationView_Previews` preview. Canvas updates the view as its code changes;
it previews the prompt content, not the separate controls/window lifecycle.

`mise run macos:ui` runs a compiled standalone app. It does not watch source files
or hot-reload code: stop it with Ctrl+C and rerun the task to rebuild and restart.
Use the gallery for live Touch ID, window behavior, notifications and stdout logs.

## Diagnose rendering / authentication events

```sh
mise run macos:ui | tee target/gallery-events.jsonl
```

Each line has a timestamp, elapsed milliseconds, PID, thread, event name and
fields. The trace includes SwiftUI body updates, native fingerprint creation,
updates, teardown, layout/frame changes, attachment, appearance, window focus,
settings changes, and authentication start/result/cancellation. Object IDs let
you distinguish updating an existing view from creating a replacement. There is
no polling timer: logs are emitted only by the observed callbacks.

A blink accompanied by `fingerprint.created`/`dismantle` indicates replacement;
`fingerprint.layout`/`frame` shows layout activity. If there are no corresponding
events, these logs do not explain the blink; Apple's internal rendering callbacks
are outside this trace. The logger is enabled only in the gallery and never logs
request text, keys, process paths or biometric data. Production CLI stdout remains
unchanged.

## Framework decision (2026-11-13)

Rust can build native AppKit interfaces through `objc2`, including attributed
text and `LAAuthenticationView`. Its [generated bindings](https://docs.rs/objc2-local-authentication-embedded-ui/latest/objc2_local_authentication_embedded_ui/)
expose Apple's fingerprint status view. However, the requested framework is
**SwiftUI**, not AppKit. `objc2` exposes Objective-C APIs, not SwiftUI's Swift view
protocol and result-builder authoring model. A SwiftUI layer with a narrow C ABI
is the practical choice here; the agent and security backend stay in Rust.

Apple documents attaching an [`LAAuthenticationView` to an `LAContext`](https://developer.apple.com/documentation/localauthenticationembeddedui/laauthenticationview/init(context:))
before evaluating a policy. We embed it using [`NSViewRepresentable`](https://developer.apple.com/documentation/swiftui/nsviewrepresentable).
This preserves the macOS 12 baseline and uses the explicit biometric-only policy
required by existing keys. Apple's newer [SwiftUI LocalAuthenticationView](https://developer.apple.com/documentation/localauthentication/localauthenticationview)
is another option for a future deployment-target upgrade.

## Request lifecycle and security

When experimental UI is enabled, the CLI owns the AppKit event loop on its main thread and runs Rust command work
on a worker. Rust serializes authorization through completion of the associated
key operation, so concurrent socket requests cannot overlap modal panels.
Request JSON contains display metadata only, never secret values or private keys.
SwiftUI uses literal Text values, not Markdown parsed from caller-controlled data.
Executable control/bidirectional characters are escaped. Long detail text scrolls.

Swift creates a fresh LAContext with reuse duration zero and no password fallback.
The live fingerprint view is bound to it. Only a successful biometric callback
transfers a retained context to Rust. Cancel, close, a 120-second timeout, malformed
input, and unavailable biometrics cannot return an authorized context. Stale and
duplicate callbacks are ignored. Rust attaches the context to Security.framework
key lookup and still checks the key identity; the existing Secure Enclave ACL
remains the final authority. An RAII guard invalidates the context on success and
all error paths. The only context sharing is within an explicit secrets batch.

The new controls support cancel and retry. Persistent “allow this process” policy
is intentionally not introduced by this UI foundation: it cannot silently remove
the existing per-operation biometric ACL requirement.

## Packaging and release

`cargo build -p seccy_cli` invokes `build.rs`, which compiles the Swift sources into
a static archive and links it into the CLI. The build locates the SDK and Swift
compatibility libraries through `xcrun`; no extra dylib/helper bundle is deployed.
`.cargo/config.toml` sets the matching macOS 12 deployment target.

`mise run package` retains the existing app ID, keychain group, provisioning
profile, hardened runtime, and Developer ID signing. The bundle uses LSUIElement
rather than LSBackgroundOnly to permit windows. `mise run build:archive` retains
the existing notarize, staple, Gatekeeper validation and release archive pipeline.
The installer still deploys the complete bundle and refreshes the login service.
The macOS QA job builds the gallery and runs Swift lifecycle tests in addition to
the Rust suite; release jobs build the linked SwiftUI library through Cargo.

A hardware smoke test remains necessary: run the signed bundled agent, initiate a
real signing/decryption request, cancel it and verify denial, then initiate another
and use Touch ID. Confirm exactly one embedded biometric prompt, successful key
use, and a fresh prompt on the next request. Also check window-close cancellation
and light/dark changes. Automated tests do not claim to validate Secure Enclave
or biometric hardware behavior.

## Native notifications

Notifications are enabled independently of `experimental.macos_ui`. The Rust
backend calls the shared Swift UserNotifications service, preserving the existing
notification text. The gallery calls that same service. It installs a retained
notification delegate before launch, registers the bundle for direct terminal
launches, requests alert permission only when sending, and presents banners/list
entries even while the gallery is foregrounded. Notifications remain silent.

The CLI waits for the system's submission callback, with a 120-second timeout;
denial/errors propagate to its caller. A late permission grant after timeout does
not schedule the cancelled submission. Unbundled binaries return an actionable
error instead of calling UserNotifications with an invalid bundle identity.

Clicking a notification is acknowledged by Seccy and never runs a key operation,
opens a file, or launches Script Editor. There are currently no custom categories
or buttons. The OS may still display its own Open/Show or dismissal controls.

Apple's standard notification API supports title/subtitle/body, grouping,
attachments, sound, badge counts and registered action buttons (including text
input). Appearance, truncation, placement, and the presentation of actions remain
system controlled. Notifications cannot render our arbitrary SwiftUI layout or
Markdown. A custom action could open our own details window for longer copy.
Critical alerts require Apple's special entitlement and user permission.

## Shared copy

Experimental prompt and notification wording lives in
[`../copy/locales/en-US/seccy.ftl`](../copy/locales/en-US/seccy.ftl), formatted by
Rust's Fluent implementation. The legacy builtin prompt copy remains unchanged.
The gallery's labels, requests, and notification examples are generated from the
same catalog and presenter. Xcode and Cargo builds regenerate the copy; for
standalone Swift tests or Canvas after editing the catalog, run:

```sh
cargo run -p seccy_copy --example generate-swift
```

See [`../copy/README.md`](../copy/README.md) for the shared-copy boundary. English
is the only locale currently bundled.
