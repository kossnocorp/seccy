import SwiftUI
import UniformTypeIdentifiers
import Darwin
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

struct AuthorizationRequest: Codable {
    let content: AuthorizationContent
    let notification: NotificationContent?
    let pidLabel: String
    let key: String
    let fingerprint: String
    let executable: String
    let pid: Int32
    var processes: [ProcessPresentation]? = nil

    var title: String { content.title }
    var body: String { content.body }

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

struct ProcessPresentation: Codable, Identifiable {
    let pid: Int32
    let pidLabel: String
    let name: String
    let executable: String?
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    let bundlePaths: [String]

    var id: String { "\(pid):\(startSeconds):\(startMicroseconds)" }
}

enum ProcessIconResolver {
    static var fallback: NSImage { NSWorkspace.shared.icon(for: .unixExecutable) }

    // PID reuse must not attach another application's icon to this snapshot.
    private static func matches(_ process: ProcessPresentation) -> Bool {
        guard process.pid > 0, process.startSeconds > 0 else { return false }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(process.pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_start_tvsec == process.startSeconds,
              info.pbi_start_tvusec == process.startMicroseconds else { return false }
        // PROC_PIDPATHINFO_MAXSIZE is a compound C macro Swift cannot import.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(process.pid, &path, UInt32(path.count)) > 0 else { return false }
        return String(cString: path) == process.executable
    }

    static func resolve(_ process: ProcessPresentation) -> NSImage {
        if matches(process),
           let icon = NSRunningApplication(processIdentifier: process.pid)?.icon,
           matches(process) {
            return icon
        }
        for path in process.bundlePaths where FileManager.default.fileExists(atPath: path) {
            return NSWorkspace.shared.icon(forFile: path)
        }
        return fileIcon(process.executable)
    }

    static func fileIcon(_ path: String?) -> NSImage {
        guard let path = path, FileManager.default.fileExists(atPath: path) else { return fallback }
        return NSWorkspace.shared.icon(forFile: path)
    }
}

// Resolve once per request identity, rather than during SwiftUI body updates.
private struct ProcessIdentityView: View {
    let process: ProcessPresentation
    var prominent = false
    @State private var icon: NSImage?

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(nsImage: icon ?? ProcessIconResolver.fallback)
                .resizable().scaledToFit()
                .frame(width: prominent ? 48 : 28, height: prominent ? 48 : 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(AuthorizationRequest.display(process.name))
                    .font(prominent ? .headline : .body)
                Text(process.pidLabel).font(.caption).foregroundStyle(.secondary)
                if let path = process.executable {
                    Text(AuthorizationRequest.display(path))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2).help(AuthorizationRequest.display(path))
                }
            }
            Spacer(minLength: 0)
        }
        .task(id: process.id) { icon = ProcessIconResolver.resolve(process) }
    }
}

enum AuthorizationState: String, CaseIterable, Identifiable {
    case ready, authenticating, success, failure, unavailable, cancelled, warning
    var label: String { Copy.text("ui-state-" + rawValue) }
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
    var message: String { Copy.text("ui-status-" + rawValue) }
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

    private var warning: Bool { request.content.warning }
    private var requester: ProcessPresentation {
        request.processes?.first(where: { $0.pid == request.pid }) ??
            ProcessPresentation(pid: request.pid, pidLabel: request.pidLabel,
                                name: URL(fileURLWithPath: request.executable).lastPathComponent,
                                executable: request.executable, startSeconds: 0,
                                startMicroseconds: 0, bundlePaths: [])
    }

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
                    .accessibilityLabel(Copy.text("ui-touch-id-accessibility"))
            } else {
                Image(systemName: state.symbol).font(.system(size: 52)).foregroundStyle(state.color)
                    .frame(height: 64).accessibilityLabel(state.label)
            }
            Text(AuthorizationRequest.display(request.title))
                .font(.title2.bold()).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Separate semantic emphasis from literal values; no parsing of caller Markdown.
                    (Text(Copy.text("ui-key") + " ").foregroundColor(.secondary) + Text(AuthorizationRequest.display(request.key)).bold())
                    VStack(alignment: .leading, spacing: 4) {
                        Text(Copy.text("ui-process")).font(.caption.bold()).foregroundStyle(.secondary)
                        ProcessIdentityView(process: requester, prominent: true)
                    }
                    if let processes = request.processes, processes.count > 1 {
                        DisclosureGroup(Copy.text("ui-process-chain")) {
                            VStack(alignment: .leading, spacing: 12) {
                                ForEach(Array(processes.reversed())) { process in
                                    ProcessIdentityView(process: process)
                                }
                            }
                            .padding(.top, 10)
                        }
                    }
                    Text(request.body).fixedSize(horizontal: false, vertical: true)
                    if warning {
                        Label(Copy.text("ui-host-warning"), systemImage: "exclamationmark.triangle.fill")
                            .font(.headline).foregroundStyle(.orange)
                    }
                    Divider()
                    Text(AuthorizationRequest.display(request.fingerprint)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    Text(Copy.text("ui-request-only")).font(.callout.bold())
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
                Button(Copy.text("ui-cancel"), action: cancel).keyboardShortcut(.cancelAction)
                Spacer()
                if state == .failure || state == .unavailable || state == .ready || state == .warning {
                    Button(Copy.text("ui-touch-id"), action: retry).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(28)
        .frame(width: 480)
        .frame(minHeight: 480, maxHeight: 660)
    }
}

extension AuthorizationRequest {
    static let signing = Copy.fixture("signing")
    static let secrets = Copy.fixture("secrets")
    static let revoked = Copy.fixture("revoked")
    static let long = Copy.fixture("long")
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
                                        localizedReason: Copy.text("gallery-auth-reason")) { [weak self] success, error in
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
    @Published var scenario = "signing" {
        didSet { UITrace.event("controls.scenario", ["value": scenario]) }
    }
    @Published var appearance = "system" { didSet { UITrace.event("controls.appearance", ["value": appearance]); applyAppearance() } }
    @Published var live = true { didSet { UITrace.event("controls.live", ["value": String(live)]); authentication.cancel() } }
    @Published var notificationStatus = ""
    let authentication = GalleryAuthentication()
    private var previewWindow: NSWindow?

    var request: AuthorizationRequest {
        switch scenario {
        case "secrets": return .secrets
        case "revoked": return .revoked
        case "long": return .long
        default: return .signing
        }
    }

    func show() {
        UITrace.event("window.show", ["existing": UITrace.id(previewWindow)])
        if previewWindow == nil {
            let window = makeAuthorizationWindow(GalleryPrompt(model: self, authentication: authentication))
            window.delegate = self
            previewWindow = window
            if let controls = NSApp.windows.first(where: { $0.title == Copy.text("gallery-title") }),
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
        previewWindow?.appearance = appearance == "system" ? nil : NSAppearance(named: appearance == "dark" ? .darkAqua : .aqua)
    }

    func notify() {
        UITrace.event("notification.submit")
        guard let notification = request.notification else { return }
        notificationStatus = Copy.text("gallery-notification-submitting")
        let submission = NativeNotifications.shared.send(title: notification.title, body: notification.body) { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self?.notificationStatus = Copy.text("gallery-notification-submitted")
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
            Text(Copy.text("gallery-title")).font(.title2.bold())
            Text(Copy.text("gallery-description"))
                .font(.callout).foregroundStyle(.secondary)
            Picker(Copy.text("gallery-request"), selection: $model.scenario) {
                ForEach(["signing", "secrets", "revoked", "long"], id: \.self) { Text(Copy.text("gallery-scenario-" + $0)).tag($0) }
            }
            Toggle(Copy.text("gallery-live"), isOn: $model.live)
            if !model.live {
                Picker(Copy.text("gallery-state"), selection: $model.state) {
                    ForEach(AuthorizationState.allCases) { Text($0.label).tag($0) }
                }
            }
            Picker(Copy.text("gallery-appearance"), selection: $model.appearance) {
                ForEach(["system", "light", "dark"], id: \.self) { Text(Copy.text("gallery-appearance-" + $0)).tag($0) }
            }
            HStack {
                Button(Copy.text("gallery-show")) { model.show() }
                Button(Copy.text("gallery-start")) { model.start() }.disabled(!model.live)
            }
            Divider()
            Text(Copy.text("gallery-notifications")).font(.headline)
            Text(Copy.text("gallery-notification-description"))
                .font(.caption).foregroundStyle(.secondary)
            Button(Copy.text("gallery-notification-send")) { model.notify() }
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
