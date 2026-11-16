import SwiftUI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

struct AuthorizationRequest: Codable {
    let details: String
    let key: String
    let fingerprint: String
    let executable: String
    let pid: Int32

    var title: String { details.components(separatedBy: "\n").first ?? "Authorize key use?" }
    var body: String { details.components(separatedBy: "\n").dropFirst().joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines) }

    // Literal Text, not Markdown: process names and remote values are untrusted.
    static func display(_ value: String) -> String {
        String(value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar) || (0x2028...0x202e).contains(scalar.value) || (0x2066...0x2069).contains(scalar.value) {
                return String(format: "\\u{%x}", scalar.value)
            }
            return String(scalar)
        }.joined().prefix(8192))
    }
}

enum AuthorizationState: String, CaseIterable, Identifiable {
    case ready = "Ready", authenticating = "Touch ID", success = "Approved"
    case failure = "Failed", unavailable = "Unavailable", cancelled = "Cancelled", warning = "Host warning"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .success: return "checkmark.circle.fill"
        case .failure, .unavailable, .warning: return "exclamationmark.triangle.fill"
        case .cancelled: return "xmark.circle"
        default: return "touchid"
        }
    }
    var color: Color {
        switch self {
        case .success: return .green
        case .failure, .unavailable, .warning: return .orange
        default: return .accentColor
        }
    }
    var message: String {
        switch self {
        case .ready: return "Use Touch ID to approve this request."
        case .authenticating: return "Place your finger on Touch ID."
        case .success: return "Identity verified."
        case .failure: return "Authentication failed. Try again or cancel."
        case .unavailable: return "Touch ID is unavailable. No access was granted."
        case .cancelled: return "Request cancelled. No access was granted."
        case .warning: return "Review the server key warning before approving."
        }
    }
}

// Keep SwiftUI's sizing passes outside the animated native control. The host
// has a constant size; its child and constraints live for the entire attempt.
final class FingerprintHostView: NSView {
    let authenticationView: LAAuthenticationView

    init(context: LAContext) {
        authenticationView = LAAuthenticationView(context: context, controlSize: .small)
        super.init(frame: NSRect(x: 0, y: 0, width: 64, height: 64))
        UITrace.event("fingerprint.created", ["host": UITrace.id(self), "native": UITrace.id(authenticationView), "context": UITrace.id(context)])
        let nativeSize = authenticationView.fittingSize
        authenticationView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(authenticationView)
        NSLayoutConstraint.activate([
            authenticationView.centerXAnchor.constraint(equalTo: centerXAnchor),
            authenticationView.centerYAnchor.constraint(equalTo: centerYAnchor),
            authenticationView.widthAnchor.constraint(equalToConstant: nativeSize.width),
            authenticationView.heightAnchor.constraint(equalToConstant: nativeSize.height),
        ])
    }

    override func layout() {
        super.layout()
        UITrace.event("fingerprint.layout", ["host": UITrace.id(self), "frame": NSStringFromRect(frame), "native_frame": NSStringFromRect(authenticationView.frame)])
    }
    override func setFrameSize(_ newSize: NSSize) {
        UITrace.event("fingerprint.frame", ["host": UITrace.id(self), "old": NSStringFromSize(frame.size), "new": NSStringFromSize(newSize)])
        super.setFrameSize(newSize)
    }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        UITrace.event("fingerprint.window", ["host": UITrace.id(self), "window": UITrace.id(window)])
    }
    override func viewDidMoveToSuperview() {
        super.viewDidMoveToSuperview()
        UITrace.event("fingerprint.superview", ["host": UITrace.id(self), "superview": UITrace.id(superview)])
    }
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        UITrace.event("fingerprint.appearance", ["host": UITrace.id(self), "appearance": effectiveAppearance.name.rawValue])
    }
    deinit { UITrace.event("fingerprint.destroyed", ["host": UITrace.id(self)]) }
    required init?(coder: NSCoder) { nil }
    override var intrinsicContentSize: NSSize { NSSize(width: 64, height: 64) }
}

struct FingerprintView: NSViewRepresentable {
    let context: LAContext
    func makeNSView(context: Context) -> FingerprintHostView {
        FingerprintHostView(context: self.context)
    }
    func updateNSView(_ view: FingerprintHostView, context: Context) {
        UITrace.event("fingerprint.update", ["host": UITrace.id(view), "context": UITrace.id(self.context)])
    }
    static func dismantleNSView(_ view: FingerprintHostView, coordinator: ()) {
        UITrace.event("fingerprint.dismantle", ["host": UITrace.id(view)])
    }
}

struct AuthorizationView: View {
    let request: AuthorizationRequest
    let state: AuthorizationState
    var context: LAContext? = nil
    var fingerprintAppeared: () -> Void = {}
    var retry: () -> Void = {}
    var cancel: () -> Void = {}

    private var warning: Bool { request.body.contains("[REVOKED]") || request.body.contains("No matching key") || request.body.contains("No server host key") }

    var body: some View {
        let _ = UITrace.event("prompt.body", ["state": state.rawValue, "context": UITrace.id(context)])
        VStack(spacing: 18) {
            if let context = context {
                FingerprintView(context: context).frame(width: 64, height: 64)
                    .onAppear {
                        UITrace.event("fingerprint.appear", ["context": UITrace.id(context)])
                        fingerprintAppeared()
                    }
                    .onDisappear { UITrace.event("fingerprint.disappear", ["context": UITrace.id(context)]) }
                    .id(ObjectIdentifier(context))
                    .accessibilityLabel("Touch ID authentication")
            } else {
                Image(systemName: state.symbol).font(.system(size: 52)).foregroundStyle(state.color)
                    .frame(height: 64).accessibilityLabel(state.rawValue)
            }
            Text(AuthorizationRequest.display(request.title))
                .font(.title2.bold()).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Separate semantic emphasis from literal values; no parsing of caller Markdown.
                    (Text("Key ").foregroundColor(.secondary) + Text(AuthorizationRequest.display(request.key)).bold())
                    VStack(alignment: .leading, spacing: 4) {
                        Text("REQUESTING PROCESS").font(.caption.bold()).foregroundStyle(.secondary)
                        Text(AuthorizationRequest.display(request.executable)).font(.system(.body, design: .monospaced).bold())
                        Text("PID \(request.pid)").font(.caption).foregroundStyle(.secondary)
                    }
                    Text(request.body).fixedSize(horizontal: false, vertical: true)
                    if warning {
                        Label("Server identity needs attention", systemImage: "exclamationmark.triangle.fill")
                            .font(.headline).foregroundStyle(.orange)
                    }
                    Divider()
                    Text(AuthorizationRequest.display(request.fingerprint)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    Text("Approval applies to this request only.").font(.callout.bold())
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding(14)
            }
            .frame(maxHeight: 300)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            Text(state.message).font(.callout.weight(.medium)).foregroundStyle(state.color)
                .multilineTextAlignment(.center).accessibilityAddTraits(.updatesFrequently)
            HStack {
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                Spacer()
                if state == .failure || state == .unavailable || state == .ready || state == .warning {
                    Button("Use Touch ID", action: retry).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(28)
        .frame(width: 480)
        .frame(minHeight: 480, maxHeight: 660)
    }
}

extension AuthorizationRequest {
    static let signing = AuthorizationRequest(details: "Approve the git commit?\n\nThe process chain Terminal → zsh → git commit wants to use the work key to sign a Git commit.", key: "work", fingerprint: "SHA256:KvdQ3vU2Tji0YtGYnGQeG79n6Cj4n94JUu6cN0aR1wk", executable: "/usr/bin/git", pid: 4217)
    static let secrets = AuthorizationRequest(details: "Decrypt secrets GITHUB_TOKEN, DATABASE_URL?\n\nThe process chain Terminal → fnox wants to decrypt the named secrets using the work key.", key: "work", fingerprint: signing.fingerprint, executable: "/opt/homebrew/bin/fnox", pid: 4218)
    static let revoked = AuthorizationRequest(details: "Approve the git push?\n\nThe process chain Terminal → git push → ssh wants to use the work key to access git@example.com.\n\n[REVOKED] Server key matches a revoked known_hosts entry", key: "work", fingerprint: signing.fingerprint, executable: "/usr/bin/ssh", pid: 4219)
    static let long = AuthorizationRequest(details: "Approve this signing request?\n\n" + String(repeating: "Terminal → very-long-process-name → ", count: 24) + "wants to sign data whose purpose could not be identified.", key: "work_🔐_e\u{301}", fingerprint: signing.fingerprint, executable: "/tmp/untrusted/**not bold**/\u{202e}process", pid: 4220)
}

// A separate context for a hardware demo; it is never returned to Rust or used
// for keychain access. Each attempt starts fresh, including after cancellation.
final class GalleryAuthentication: ObservableObject {
    @Published private(set) var context = LAContext()
    @Published private(set) var state: AuthorizationState = .ready {
        didSet { UITrace.event("auth.state", ["old": oldValue.rawValue, "new": state.rawValue, "context": UITrace.id(context)]) }
    }
    private var pending = false
    private var attempt = UUID()

    func start() {
        UITrace.event("auth.start", ["old_context": UITrace.id(context)])
        context.invalidate()
        attempt = UUID()
        let fresh = LAContext()
        fresh.touchIDAuthenticationAllowableReuseDuration = 0
        fresh.localizedFallbackTitle = ""
        pending = true
        state = .ready
        context = fresh
        UITrace.event("auth.context", ["context": UITrace.id(context), "attempt": attempt.uuidString])
    }

    func appeared() {
        // Wait until SwiftUI has mounted the LAAuthenticationView before evaluation.
        UITrace.event("auth.appeared", ["pending": String(pending), "attempt": attempt.uuidString])
        guard pending else { return }
        pending = false
        let current = attempt
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.attempt == current else {
                UITrace.event("auth.stale_start", ["attempt": current.uuidString])
                return
            }
            var error: NSError?
            guard self.context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                UITrace.event("auth.unavailable", ["domain": error?.domain ?? "", "code": String(error?.code ?? 0)])
                self.state = .unavailable
                return
            }
            self.state = .authenticating
            UITrace.event("auth.evaluate", ["context": UITrace.id(self.context), "attempt": current.uuidString])
            self.context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        localizedReason: "Preview Seccy's Touch ID animation. No keys will be accessed.") { [weak self] success, error in
                let failure = error as NSError?
                UITrace.event("auth.reply", ["attempt": current.uuidString, "success": String(success), "domain": failure?.domain ?? "", "code": String(failure?.code ?? 0)])
                DispatchQueue.main.async {
                    guard let self = self, self.attempt == current else {
                        UITrace.event("auth.stale_reply", ["attempt": current.uuidString])
                        return
                    }
                    self.state = success ? .success : .failure
                }
            }
        }
    }

    func cancel() {
        UITrace.event("auth.cancel", ["context": UITrace.id(context), "attempt": attempt.uuidString])
        attempt = UUID()
        pending = false
        context.invalidate()
        state = .cancelled
    }

    deinit {
        UITrace.event("auth.destroyed", ["context": UITrace.id(context)])
        context.invalidate()
    }
}

final class GalleryModel: NSObject, ObservableObject, NSWindowDelegate {
    @Published var state: AuthorizationState = .authenticating {
        didSet { UITrace.event("controls.state", ["value": state.rawValue]) }
    }
    @Published var scenario = "Git signing" {
        didSet { UITrace.event("controls.scenario", ["value": scenario]) }
    }
    @Published var appearance = "System" { didSet { UITrace.event("controls.appearance", ["value": appearance]); applyAppearance() } }
    @Published var live = true { didSet { UITrace.event("controls.live", ["value": String(live)]); authentication.cancel() } }
    @Published var notificationStatus = ""
    let authentication = GalleryAuthentication()
    private var previewWindow: NSWindow?

    var request: AuthorizationRequest {
        switch scenario {
        case "Secrets batch": return .secrets
        case "Revoked host": return .revoked
        case "Long / untrusted text": return .long
        default: return .signing
        }
    }

    func show() {
        UITrace.event("window.show", ["existing": UITrace.id(previewWindow)])
        if previewWindow == nil {
            let window = makeAuthorizationWindow(GalleryPrompt(model: self, authentication: authentication))
            window.delegate = self
            previewWindow = window
            if let controls = NSApp.windows.first(where: { $0.title == "Seccy Preview Controls" }),
               let screen = controls.screen {
                let visible = screen.visibleFrame
                let total = controls.frame.width + window.frame.width + 16
                if total <= visible.width {
                    let left = visible.midX - total / 2
                    controls.setFrameOrigin(NSPoint(x: left, y: visible.midY - controls.frame.height / 2))
                    window.setFrameOrigin(NSPoint(x: left + controls.frame.width + 16,
                                                  y: visible.midY - window.frame.height / 2))
                }
            }
            applyAppearance()
        }
        previewWindow?.makeKeyAndOrderFront(nil)
    }

    func start() {
        show()
        if live { authentication.start() } else { state = .authenticating }
    }

    func close() {
        UITrace.event("window.close_requested")
        previewWindow?.close()
    }

    func windowDidBecomeKey(_ notification: Notification) { UITrace.event("window.key") }
    func windowDidResignKey(_ notification: Notification) { UITrace.event("window.resigned_key") }
    func windowDidResize(_ notification: Notification) { UITrace.event("window.resize") }
    func windowDidMove(_ notification: Notification) { UITrace.event("window.move") }
    func windowDidExpose(_ notification: Notification) { UITrace.event("window.expose") }

    func windowWillClose(_ notification: Notification) {
        UITrace.event("window.closed")
        authentication.cancel()
        previewWindow?.contentViewController = nil
        previewWindow = nil
    }

    private func applyAppearance() {
        previewWindow?.appearance = appearance == "System" ? nil : NSAppearance(named: appearance == "Dark" ? .darkAqua : .aqua)
    }

    func notify() {
        UITrace.event("notification.submit")
        let title = scenario == "Secrets batch" ? "seccy: secret decrypted" : "seccy: key used"
        let message = scenario == "Secrets batch"
            ? "Secret GITHUB_TOKEN decrypted.\n\nThe process chain Terminal → fnox used the work key to decrypt secret GITHUB_TOKEN."
            : (scenario == "Revoked host" ? "SSH authentication request signed.\n\n" : "Data signed.\n\n") + request.body.replacingOccurrences(of: "wants to use", with: "used")
        notificationStatus = "Submitting notification…"
        let submission = NativeNotifications.shared.send(title: title, body: message) { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self?.notificationStatus = "Submitted as Seccy UI Gallery. macOS notification settings and Focus control banner visibility."
                case .failure(let error): self?.notificationStatus = error.message
                }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { submission.cancel() }
    }
}

private struct GalleryPrompt: View {
    @ObservedObject var model: GalleryModel
    @ObservedObject var authentication: GalleryAuthentication
    var body: some View {
        let _ = UITrace.event("preview.body")
        AuthorizationView(request: model.request,
                          state: model.live ? authentication.state : model.state,
                          context: model.live ? authentication.context : nil,
                          fingerprintAppeared: { if model.live { authentication.appeared() } },
                          retry: { model.start() }, cancel: { model.close() })
    }
}

struct GalleryView: View {
    @StateObject private var model = GalleryModel()
    var body: some View {
        let _ = UITrace.event("controls.body")
        VStack(alignment: .leading, spacing: 18) {
            Text("Seccy Preview Controls").font(.title2.bold())
            Text("The separate prompt uses the production window and layout. All requests here are samples; no keys are accessed.")
                .font(.callout).foregroundStyle(.secondary)
            Picker("Request", selection: $model.scenario) {
                ForEach(["Git signing", "Secrets batch", "Revoked host", "Long / untrusted text"], id: \.self) { Text($0) }
            }
            Toggle("Live Touch ID", isOn: $model.live)
            if !model.live {
                Picker("State", selection: $model.state) {
                    ForEach(AuthorizationState.allCases) { Text($0.rawValue).tag($0) }
                }
            }
            Picker("Prompt appearance", selection: $model.appearance) {
                ForEach(["System", "Light", "Dark"], id: \.self) { Text($0) }
            }
            HStack {
                Button("Show prompt") { model.show() }
                Button("Start Touch ID demo") { model.start() }.disabled(!model.live)
            }
            Divider()
            Text("Notifications").font(.headline)
            Text("Uses native macOS notifications with the Seccy icon. macOS may ask for notification permission for the gallery.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Send test notification") { model.notify() }
            Text(model.notificationStatus).font(.caption).foregroundStyle(.secondary)
        }
        .padding(24).frame(width: 360)
        .onAppear { model.show() }
        .onDisappear { model.close() }
    }
}

struct AuthorizationView_Previews: PreviewProvider {
    static var previews: some View {
        AuthorizationView(request: .signing, state: .ready)
    }
}
