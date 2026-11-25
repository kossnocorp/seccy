import AppKit
import SwiftUI
import LocalAuthentication

// Main-thread state machine. Stale callbacks cannot approve a cancelled request
// or complete a newer prompt.
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

// SwiftUI controls don't consistently expose mouseDownCanMoveWindow to AppKit.
// Explicit exclusion regions keep clicks, selection and scrolling native while
// allowing the rest of the borderless prompt to initiate a window drag.
final class AuthorizationWindow: NSWindow {
    var denyAction: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }

    func canDrag(at point: NSPoint) -> Bool {
        guard let content = contentView,
              content.bounds.contains(content.convert(point, from: nil)) else { return false }
        func excludesDrag(_ view: NSView) -> Bool {
            guard !view.isHidden else { return false }
            if view is WindowDragExclusionView,
               view.bounds.contains(view.convert(point, from: nil)) { return true }
            return view.subviews.contains(where: excludesDrag)
        }
        return !excludesDrag(content)
    }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .keyDown, event.keyCode == 53, let denyAction {
            denyAction()
        } else if event.type == .leftMouseDown, canDrag(at: event.locationInWindow) {
            performDrag(with: event)
        } else {
            super.sendEvent(event)
        }
    }
}

// Explicit sizing is needed for borderless windows as nested disclosures expand.
struct AuthorizationWindowLayout: NSViewRepresentable {
    static let maximumHeight: CGFloat = 900
    static func heightLimit(for visibleHeight: CGFloat) -> CGFloat {
        floor(min(maximumHeight, visibleHeight * 0.85))
    }
    let size: CGSize
    let cancel: () -> Void
    let heightLimitChanged: (CGFloat) -> Void

    final class Host: NSView {
        var configuration: AuthorizationWindowLayout?
        private var updateScheduled = false
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            scheduleUpdate()
        }
        func scheduleUpdate() {
            guard !updateScheduled else { return }
            updateScheduled = true
            DispatchQueue.main.async { [weak self] in
                self?.updateScheduled = false
                guard let self, let configuration,
                      let window = window as? AuthorizationWindow else { return }
                window.denyAction = { [weak self] in self?.configuration?.cancel() }
                let visible = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
                let limit = AuthorizationWindowLayout.heightLimit(for: visible?.height ?? 800)
                configuration.heightLimitChanged(limit)
                let height = min(limit, ceil(configuration.size.height))
                guard height > 0, abs(window.frame.height - height) > 0.5 else { return }
                var frame = window.frame
                frame.origin.y = frame.midY - height / 2
                frame.size = CGSize(width: configuration.size.width, height: height)
                if let visible {
                    frame.origin.y = max(visible.minY, min(frame.origin.y, visible.maxY - height))
                }
                window.setFrame(frame, display: true)
            }
        }
    }
    func makeNSView(context: Context) -> Host { Host() }
    func updateNSView(_ view: Host, context: Context) {
        view.configuration = self
        view.scheduleUpdate()
    }
}

final class WindowDragExclusionView: NSView {
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

struct WindowDragExclusion: NSViewRepresentable {
    func makeNSView(context: Context) -> WindowDragExclusionView {
        let view = WindowDragExclusionView()
        view.setAccessibilityElement(false)
        return view
    }
    func updateNSView(_ view: WindowDragExclusionView, context: Context) {}
}

// Production and gallery share the borderless window and interaction regions.
func makeAuthorizationWindow<Content: View>(_ content: Content) -> NSWindow {
    let window = AuthorizationWindow(contentViewController: NSHostingController(
        rootView: content
            .frame(maxHeight: .infinity, alignment: .top)
            .clipShape(RoundedRectangle(cornerRadius: 20))))
    window.title = Copy.text("ui-window-title")
    window.styleMask = [.borderless]
    window.isOpaque = false
    window.backgroundColor = UIPalette.transparentWindow
    window.hasShadow = true
    window.isReleasedWhenClosed = false
    window.level = .modalPanel
    window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
    return window
}

func showAuthorizationWindow(_ window: NSWindow) {
    // Pick the user's current display before activating Seccy. NSWindow.center()
    // uses AppKit's placement rules rather than the visible frame's true center.
    let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) }
        ?? NSScreen.main
    func center() {
        window.contentView?.layoutSubtreeIfNeeded()
        guard let visible = screen?.visibleFrame else { return }
        window.setFrameOrigin(NSPoint(x: visible.midX - window.frame.width / 2,
                                      y: visible.midY - window.frame.height / 2))
    }
    center()
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
    // Hosting views can finalize their size only after joining a visible window.
    DispatchQueue.main.async { [weak window] in
        guard let window = window, window.isVisible else { return }
        window.contentView?.layoutSubtreeIfNeeded()
        guard let visible = screen?.visibleFrame else { return }
        window.setFrameOrigin(NSPoint(x: visible.midX - window.frame.width / 2,
                                      y: visible.midY - window.frame.height / 2))
    }
}

final class PromptController: NSObject, ObservableObject, NSWindowDelegate {
    @Published private(set) var state: AuthorizationState = .ready
    let request: AuthorizationRequest
    @Published private(set) var context: LAContext?
    private var window: NSWindow!
    private var session = AuthorizationSession()
    private var pending = false
    private var mountedContext: ObjectIdentifier?
    private let makeContext: () -> LAContext
    private let focused: (() -> Bool)?
    private var activationObserver: NSObjectProtocol?
    private var completion: ((LAContext?) -> Void)?
    private var previousApplication: NSRunningApplication?

    init(request: AuthorizationRequest, makeContext: @escaping () -> LAContext = { LAContext() },
         focused: (() -> Bool)? = nil) {
        self.request = request
        self.makeContext = makeContext
        self.focused = focused
        super.init()
        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.scheduleAuthentication() }
    }

    deinit {
        if let activationObserver = activationObserver {
            NotificationCenter.default.removeObserver(activationObserver)
        }
    }

    private var isFocused: Bool { focused?() ?? (window?.isKeyWindow == true && NSApp.isActive) }

    func start(completion: @escaping (LAContext?) -> Void) {
        guard window == nil, !session.finished else { return }
        self.completion = completion
        let frontmost = NSWorkspace.shared.frontmostApplication
        if frontmost?.processIdentifier != ProcessInfo.processInfo.processIdentifier {
            previousApplication = frontmost
        }
        let content = PromptContent(controller: self)
        window = makeAuthorizationWindow(content)
        window.delegate = self
        authenticate()
        showAuthorizationWindow(window)
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { [weak self] in self?.cancel() }
    }

    func authenticate() {
        guard !session.finished, state != .authenticating else { return }
        context?.invalidate()
        let fresh = makeContext()
        fresh.touchIDAuthenticationAllowableReuseDuration = 0
        fresh.localizedFallbackTitle = ""
        pending = true
        mountedContext = nil
        // Mount the visible native widget before starting evaluation.
        state = .authenticating
        context = fresh
        UITrace.event("prompt.prepared", ["context": UITrace.id(fresh)])
    }

    func fingerprintAppeared(_ appearedContext: LAContext) {
        guard appearedContext === context, !session.finished else { return }
        mountedContext = ObjectIdentifier(appearedContext)
        scheduleAuthentication()
    }

    func windowDidBecomeKey(_ notification: Notification) { scheduleAuthentication() }

    private func scheduleAuthentication() {
        DispatchQueue.main.async { [weak self] in self?.evaluatePendingAuthentication() }
    }

    private func evaluatePendingAuthentication() {
        guard pending, !session.finished, isFocused, let context = context,
              mountedContext == ObjectIdentifier(context) else { return }
        pending = false
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            UITrace.event("prompt.unavailable", ["code": String(error?.code ?? 0)])
            state = .unavailable
            return
        }
        guard let current = session.beginAttempt() else { return }
        UITrace.event("prompt.evaluate", ["context": UITrace.id(context)])
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: request.title) { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self = self, self.session.acceptResult(current, success: success) else { return }
                UITrace.event("prompt.reply", ["success": String(success), "code": String((error as NSError?)?.code ?? 0)])
                if success { self.finish() } else { self.state = .failure }
            }
        }
    }

    func cancel() {
        guard !session.finished else { return }
        session.cancel()
        pending = false
        context?.invalidate()
        finish()
    }

    private func finish() {
        let callback = completion
        completion = nil
        let result = session.approved ? context : nil
        window?.delegate = nil
        window?.orderOut(nil)
        window?.contentViewController = nil
        window?.close()
        window = nil
        // Closing our last prompt doesn't relinquish application activation.
        // Return to the app the user was typing in, but don't steal focus back
        // if they switched apps while the authorization was pending.
        if NSApp.isActive,
           !NSApp.windows.contains(where: { $0 is AuthorizationWindow && $0.isVisible }),
           let previousApplication = previousApplication, !previousApplication.isTerminated {
            previousApplication.activate(options: [])
        }
        previousApplication = nil
        callback?(result)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { cancel(); return false }
}

private struct PromptContent: View {
    @ObservedObject var controller: PromptController
    var body: some View {
        AuthorizationView(request: controller.request, state: controller.state,
                           context: controller.context,
                           fingerprintAppeared: { controller.fingerprintAppeared($0) },
                           retry: { controller.authenticate() },
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
    // Only the Rust worker waits. A nested runModal inside main.sync prevents
    // main-queue authentication/SwiftUI callbacks from being reliably serviced.
    let finished = DispatchSemaphore(value: 0)
    var result: LAContext?
    DispatchQueue.main.async {
        autoreleasepool {
            let controller = PromptController(request: request)
            controller.start { context in
                result = context
                finished.signal()
            }
        }
    }
    finished.wait()
    guard let result = result else { return nil }
    return Unmanaged.passRetained(result).toOpaque()
}

// The raw Rust request is retained verbatim as a JSON object, including fields
// Swift doesn't render. Icons are resolved now, never against live PIDs on replay.
struct RequestCapture: Decodable {
    let format: String
    let version: Int
    let capturedAt: String
    let mode: String
    let homeDirectory: String?
    let request: AuthorizationRequest
    let icons: [String: Data]

    static let formatName = "seccy.request-capture"
    static let maximumBytes = 64 * 1024 * 1024

    enum Failure: Error, LocalizedError {
        case unsupported, tooLarge, invalidDirectory
        var errorDescription: String? {
            switch self {
            case .unsupported: return Copy.text("ui-capture-error-format")
            case .tooLarge: return Copy.text("ui-capture-error-size")
            case .invalidDirectory: return Copy.text("ui-capture-error-directory")
            }
        }
    }

    static func read(from url: URL) throws -> RequestCapture {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else { throw Failure.tooLarge }
        let capture = try JSONDecoder().decode(Self.self, from: data)
        guard capture.format == formatName, capture.version == 1 else { throw Failure.unsupported }
        return capture
    }

    var replayRequest: AuthorizationRequest {
        var result = request
        result.isReplay = true
        if var model = result.presentation, model.version == 1,
           let index = model.rows.firstIndex(where: { $0.contains(where: \.isLocation) }) {
            let location = model.rows.remove(at: index)
            model.rows.append(location)
            result.presentation = model
        }
        // Legacy captures preserve the last PPID, but not why inspection ended.
        if result.ancestryInterruption == nil,
           let raw = request.processes?.last?.diagnostics,
           let record = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
           let parent = record["parent_pid"] as? Int, parent > 1 {
            result.ancestryInterruption = "\(Copy.text("ui-chain-unrecorded")) \(parent)"
        }
        result.previewCopy = nil
        if let homeDirectory = homeDirectory, let directory = result.workingDirectory {
            result.originalDirectory = directory
            result.workingDirectory = AuthorizationRequest.abbreviatedDirectory(directory, home: homeDirectory)
        }
        result.processes = request.captureProcesses.map { process in
            var process = process
            process.isReplay = true
            process.capturedIconPNG = icons[process.id]
            return process
        }
        // Older captures used the containing app's name even for its bundled Git tool.
        if let header = result.header, ["commit", "sell", "cloud_upload", "cloud_download"].contains(header.action),
           let git = request.processes?.first(where: { $0.isGit }) {
            result.appPid = git.pid
            result.header = AuthorizationHeader(requestTitle: header.requestTitle, keyAction: header.keyAction, title: header.title, target: header.target, action: header.action,
                permission: header.permission.map { $0.kind == "app" ? PermissionPart(kind: "app", value: "git") : $0 })
        }
        return result
    }

    static func png(_ image: NSImage) -> Data? {
        guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 144,
            pixelsHigh: 144, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
            isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
            let context = NSGraphicsContext(bitmapImageRep: bitmap) else { return nil }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        image.draw(in: NSRect(x: 0, y: 0, width: 144, height: 144))
        NSGraphicsContext.restoreGraphicsState()
        return bitmap.representation(using: .png, properties: [:])
    }

    @discardableResult
    static func write(requestData: Data, directory: URL, mode: String) throws -> URL {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        let attributes = try manager.attributesOfItem(atPath: directory.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory,
              let permissions = attributes[.posixPermissions] as? NSNumber,
              permissions.intValue & 0o077 == 0 else { throw Failure.invalidDirectory }
        let request = try JSONDecoder().decode(AuthorizationRequest.self, from: requestData)
        var icons: [String: String] = [:]
        for process in request.captureProcesses {
            icons[process.id] = png(ProcessIconResolver.resolve(process))?.base64EncodedString()
        }
        let object: [String: Any] = [
            "format": formatName, "version": 1,
            "capturedAt": ISO8601DateFormatter().string(from: Date()),
            "homeDirectory": NSHomeDirectory(),
            "mode": mode, "request": try JSONSerialization.jsonObject(with: requestData),
            "icons": icons
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        guard data.count <= maximumBytes else { throw Failure.tooLarge }
        let url = directory.appendingPathComponent("request-\(UUID().uuidString).json")
        try data.write(to: url, options: .atomic)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return url
    }
}

extension AuthorizationRequest {
    var captureProcesses: [ProcessPresentation] {
        var result = processes ?? []
        if !result.contains(where: { $0.pid == pid }) {
            result.append(ProcessPresentation(pid: pid, pidLabel: pidLabel,
                name: URL(fileURLWithPath: executable).lastPathComponent,
                executable: executable, startSeconds: 0, startMicroseconds: 0, bundlePaths: []))
        }
        return result
    }
}

@_cdecl("seccy_ui_capture")
public func seccyUICapture(_ json: UnsafePointer<CChar>, _ directory: UnsafePointer<CChar>,
                          _ mode: UnsafePointer<CChar>) -> Int32 {
    let data = Data(String(cString: json).utf8)
    let url = URL(fileURLWithPath: String(cString: directory), isDirectory: true)
    let mode = String(cString: mode)
    let save: () -> Int32 = {
        do {
            let file = try RequestCapture.write(requestData: data, directory: url, mode: mode)
            fputs("Seccy request captured: \(file.path)\n", stderr)
            return 0
        } catch {
            fputs("Seccy request capture: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
    return Thread.isMainThread ? save() : DispatchQueue.main.sync(execute: save)
}
