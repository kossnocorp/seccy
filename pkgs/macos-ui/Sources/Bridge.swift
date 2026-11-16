import AppKit
import SwiftUI
import LocalAuthentication

// Main-thread state machine. Stale callbacks cannot approve a cancelled request
// or stop a newer modal session.
struct AuthorizationSession {
    private(set) var finished = false
    private(set) var approved = false
    private var attempt: UUID?

    mutating func beginAttempt() -> UUID? {
        guard !finished else { return nil }
        let id = UUID()
        attempt = id
        return id
    }
    mutating func acceptResult(_ id: UUID, success: Bool) -> Bool {
        guard !finished, attempt == id else { return false }
        attempt = nil
        if success { finished = true; approved = true }
        return true
    }
    mutating func cancel() {
        guard !finished else { return }
        finished = true
        attempt = nil
    }
}

// The production prompt and gallery use the same window factory, including
// title bar, style, sizing, and content. Preview controls live in a separate window.
func makeAuthorizationWindow<Content: View>(_ content: Content) -> NSWindow {
    let window = NSWindow(contentViewController: NSHostingController(rootView: content))
    window.title = "Seccy · Authorize request"
    window.styleMask = [.titled, .closable]
    window.isReleasedWhenClosed = false
    window.center()
    return window
}

private final class PromptController: NSObject, ObservableObject, NSWindowDelegate {
    @Published var state: AuthorizationState = .ready
    let request: AuthorizationRequest
    let context = LAContext()
    private var window: NSWindow!
    private var session = AuthorizationSession()

    init(request: AuthorizationRequest) {
        self.request = request
        super.init()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
    }

    func run() -> LAContext? {
        let content = PromptContent(controller: self)
        window = makeAuthorizationWindow(content)
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { [weak self] in self?.authenticate() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { [weak self] in self?.cancel() }
        NSApp.runModal(for: window)
        session.cancel()
        window.orderOut(nil)
        window.close()
        window.contentViewController = nil
        if !session.approved { context.invalidate() }
        return session.approved ? context : nil
    }

    func authenticate() {
        guard !session.finished, state != .authenticating else { return }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            state = .unavailable
            return
        }
        state = .authenticating
        guard let current = session.beginAttempt() else { return }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: request.title) { [weak self] success, _ in
            DispatchQueue.main.async {
                guard let self = self, self.session.acceptResult(current, success: success) else { return }
                if success { self.endModal() } else { self.state = .failure }
            }
        }
    }

    func cancel() {
        guard !session.finished else { return }
        session.cancel()
        context.invalidate()
        endModal()
    }

    private func endModal() {
        NSApp.stopModal()
        // A dispatch callback is not an NSEvent. Wake the modal event loop so
        // cancellation, timeout and biometric completion return immediately.
        if let event = NSEvent.otherEvent(with: .applicationDefined, location: .zero,
            modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
            subtype: 0, data1: 0, data2: 0) {
            NSApp.postEvent(event, atStart: true)
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { cancel(); return false }
}

private struct PromptContent: View {
    @ObservedObject var controller: PromptController
    var body: some View {
        AuthorizationView(request: controller.request, state: controller.state,
                          context: controller.context, retry: { controller.authenticate() },
                          cancel: { controller.cancel() })
    }
}

@_cdecl("seccy_ui_run")
public func seccyUIRun(_ entry: @escaping @convention(c) () -> Void) {
    precondition(Thread.isMainThread)
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    DispatchQueue.main.async { DispatchQueue.global(qos: .userInitiated).async { entry() } }
    app.run()
}

@_cdecl("seccy_ui_authenticate")
public func seccyUIAuthenticate(_ json: UnsafePointer<CChar>) -> UnsafeMutableRawPointer? {
    guard !Thread.isMainThread,
          let data = String(cString: json).data(using: .utf8),
          let request = try? JSONDecoder().decode(AuthorizationRequest.self, from: data) else { return nil }
    return DispatchQueue.main.sync {
        autoreleasepool {
            guard let context = PromptController(request: request).run() else { return nil }
            return Unmanaged.passRetained(context).toOpaque()
        }
    }
}
