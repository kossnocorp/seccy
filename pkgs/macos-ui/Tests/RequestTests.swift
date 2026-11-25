import XCTest
import SwiftUI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
@testable import SeccyUI

private final class TestBiometricContext: LAContext {
    var evaluations = 0
    var invalidated = false
    var reply: ((Bool, Error?) -> Void)?
    var onEvaluate: (() -> Void)?
    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool { true }
    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String,
                                 reply: @escaping (Bool, Error?) -> Void) {
        evaluations += 1
        self.reply = reply
        onEvaluate?()
    }
    override func invalidate() { invalidated = true }
}

final class PromptActivationTests: XCTestCase {
    func testFullPromptStartsAndCompletesFromMainQueueWithoutClicks() {
        let context = TestBiometricContext()
        context.onEvaluate = { [weak context] in context?.reply?(true, nil) }
        let completed = expectation(description: "Prompt completed")
        weak var activeController: PromptController?
        var completions = 0
        DispatchQueue.main.async {
            let controller = PromptController(request: .signing,
                makeContext: { context }, focused: { true })
            activeController = controller
            controller.start { result in
                XCTAssertTrue(result === context)
                XCTAssertNil(NSApp.modalWindow)
                completions += 1
                completed.fulfill()
            }
        }
        wait(for: [completed], timeout: 5)
        activeController?.cancel()
        flushMainQueue()
        XCTAssertEqual(context.evaluations, 1)
        XCTAssertEqual(completions, 1)
        XCTAssertFalse(context.invalidated, "Approved context must remain usable by Rust")
        XCTAssertNil(activeController, "Closing the prompt must release its controller")
    }

    func testFullPromptCancellationCompletesOnceAndRejectsLateSuccess() {
        let context = TestBiometricContext()
        let evaluated = expectation(description: "Evaluation started")
        context.onEvaluate = { evaluated.fulfill() }
        let controller = PromptController(request: .signing,
            makeContext: { context }, focused: { true })
        var completions = 0
        controller.start { result in
            XCTAssertNil(result)
            completions += 1
        }
        wait(for: [evaluated], timeout: 5)
        controller.cancel()
        context.reply?(true, nil)
        controller.cancel()
        flushMainQueue()
        XCTAssertEqual(completions, 1)
        XCTAssertTrue(context.invalidated)
    }

    private func flushMainQueue() {
        let drained = expectation(description: "Main queue")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 2)
    }

    func testTouchIDAutomaticallyStartsOnceAfterWidgetAttachmentAndFocus() throws {
        var focused = false
        var contexts: [TestBiometricContext] = []
        let controller = PromptController(request: .signing, makeContext: {
            let context = TestBiometricContext()
            contexts.append(context)
            return context
        }, focused: { focused })
        defer { controller.cancel() }
        controller.authenticate()
        let first = try XCTUnwrap(contexts.first)
        XCTAssertEqual(first.evaluations, 0)
        controller.fingerprintAppeared(first)
        flushMainQueue()
        XCTAssertEqual(first.evaluations, 0, "An unfocused prompt must wait")
        focused = true
        controller.windowDidBecomeKey(Notification(name: NSWindow.didBecomeKeyNotification))
        flushMainQueue()
        XCTAssertEqual(first.evaluations, 1, "Focus must start Touch ID without another click")
        controller.fingerprintAppeared(first)
        controller.windowDidBecomeKey(Notification(name: NSWindow.didBecomeKeyNotification))
        controller.authenticate()
        flushMainQueue()
        XCTAssertEqual(first.evaluations, 1)
        XCTAssertEqual(contexts.count, 1)

        first.reply?(false, nil)
        flushMainQueue()
        XCTAssertEqual(controller.state, .failure)
        controller.authenticate()
        XCTAssertEqual(contexts.count, 2)
        let retry = contexts[1]
        XCTAssertTrue(first.invalidated)
        controller.fingerprintAppeared(first)
        flushMainQueue()
        XCTAssertEqual(retry.evaluations, 0, "Stale attachment cannot start a fresh attempt")
        controller.fingerprintAppeared(retry)
        flushMainQueue()
        XCTAssertEqual(retry.evaluations, 1)
    }

    func testFocusedPromptWaitsForWidgetAndCancellationPreventsPendingStart() {
        let context = TestBiometricContext()
        let controller = PromptController(request: .signing, makeContext: { context }, focused: { true })
        controller.authenticate()
        controller.windowDidBecomeKey(Notification(name: NSWindow.didBecomeKeyNotification))
        flushMainQueue()
        XCTAssertEqual(context.evaluations, 0, "Focus alone isn't enough before attachment")
        controller.fingerprintAppeared(context)
        controller.cancel()
        flushMainQueue()
        XCTAssertTrue(context.invalidated)
        XCTAssertEqual(context.evaluations, 0)
    }

    func testFingerprintReadinessRequiresAnAttachedNativeView() {
        let context = LAContext()
        defer { context.invalidate() }
        let host = FingerprintHostView(context: context)
        var attached = 0
        host.appeared = { attached += 1 }
        host.reportAttachment()
        flushMainQueue()
        XCTAssertEqual(attached, 0)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 100, height: 100),
                              styleMask: .borderless, backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.close() }
        window.contentView?.addSubview(host)
        flushMainQueue()
        XCTAssertGreaterThan(attached, 0)
        let previous = attached
        host.reportAttachment()
        host.removeFromSuperview()
        flushMainQueue()
        XCTAssertEqual(attached, previous)
    }
}

final class RequestTests: XCTestCase {
    func testFinderTargetSelectsFilesAndOpensDirectories() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("work.pub")
        try Data().write(to: file)
        XCTAssertEqual(FinderTarget.resolve(file.path, directoryOnly: false), .file(file))
        XCTAssertEqual(FinderTarget.resolve(folder.path, directoryOnly: true), .directory(folder))
        try FileManager.default.removeItem(at: file)
        XCTAssertEqual(FinderTarget.resolve(file.path, directoryOnly: false), .directory(folder))
        XCTAssertNil(FinderTarget.resolve(file.path, directoryOnly: true))
        XCTAssertNil(FinderTarget.resolve("relative/path", directoryOnly: false))
    }
    func testRustGalleryPromptDecodesAndRetainsSecretNamesAcrossCaptureEncoding() throws {
        let request = Copy.fixture("secrets").preview(key: "demo", directory: "/example")
        let replay = try JSONDecoder().decode(AuthorizationRequest.self, from: JSONEncoder().encode(request))
        let prompt = try XCTUnwrap(replay.presentation)
        XCTAssertEqual(prompt.version, 1)
        XCTAssertEqual(prompt.title, "Decrypt secrets?")
        let nodes = prompt.rows.flatMap { $0 }
        XCTAssertTrue(nodes.contains { if case .secrets(let names) = $0 { return names == ["GITHUB_TOKEN", "DATABASE_URL"] }; return false })
        XCTAssertTrue(nodes.contains { if case .keys(let names) = $0 { return names == ["demo"] }; return false })
        XCTAssertTrue(nodes.contains { if case .directory(let path) = $0 { return path == "/example" }; return false })
    }
    func testCaptureRoundTripPreservesRawRequestIconsAndPreventsLiveReplay() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        var request = Copy.fixture("signing")
        request.workingDirectory = NSHomeDirectory() + "/capture-test"
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any])
        object["extraFutureField"] = "keep the original Rust request"
        let data = try JSONSerialization.data(withJSONObject: object)
        let file = try RequestCapture.write(requestData: data, directory: directory, mode: "prompt")
        let second = try RequestCapture.write(requestData: data, directory: directory, mode: "notify")
        XCTAssertNotEqual(file, second)
        let stored = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        XCTAssertEqual((stored["request"] as? [String: Any])?["extraFutureField"] as? String,
                       "keep the original Rust request")
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
        let capture = try RequestCapture.read(from: file)
        XCTAssertEqual(capture.version, 1)
        XCTAssertEqual(capture.mode, "prompt")
        let replay = capture.replayRequest
        XCTAssertEqual(replay.workingDirectory, "~/capture-test")
        XCTAssertTrue(replay.isReplay == true)
        XCTAssertEqual(replay.processes?.count, request.captureProcesses.count)
        for process in try XCTUnwrap(replay.processes) {
            XCTAssertTrue(process.isReplay == true)
            XCTAssertNotNil(process.capturedIconPNG)
            XCTAssertEqual(ProcessIconResolver.resolve(process).size, NSSize(width: 144, height: 144))
        }
        let suite = "seccy.capture.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = GalleryModel(defaults: defaults)
        model.live = true
        try model.loadCapture(from: file)
        XCTAssertFalse(model.usesLiveAuthentication)
        XCTAssertEqual(model.request.key, request.key)
        model.keyName = "must not replace captured key"
        XCTAssertEqual(model.request.key, request.key)
        let context = model.authentication.context
        model.start()
        XCTAssertTrue(model.authentication.context === context)
        XCTAssertEqual(model.authentication.state, .cancelled)
        model.close()
        model.clearCapture()
        XCTAssertTrue(model.usesLiveAuthentication)
    }

    func testCaptureRejectsUnknownVersionAndReplayNeverUsesLiveIconFallbacks() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = try RequestCapture.write(
            requestData: JSONEncoder().encode(Copy.fixture("signing")), directory: directory, mode: "prompt")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        object["version"] = 99
        try JSONSerialization.data(withJSONObject: object).write(to: file)
        XCTAssertThrowsError(try RequestCapture.read(from: file))
        var process = Copy.fixture("signing").captureProcesses[0]
        process.isReplay = true
        process.capturedIconPNG = Data("not an image".utf8)
        XCTAssertEqual(RequestCapture.png(ProcessIconResolver.resolve(process)),
                       RequestCapture.png(ProcessIconResolver.fallback))
    }

    func testDiagnosticSnapshotsSurviveDecoding() throws {
        let request = Copy.fixture("signing")
        let diagnostics = try XCTUnwrap(request.diagnostics)
        XCTAssertTrue(diagnostics.contains("digest_base64"))
        XCTAssertTrue(try XCTUnwrap(request.processes?.first?.diagnostics).contains("arguments"))
        let roundTrip = try JSONDecoder().decode(AuthorizationRequest.self, from: JSONEncoder().encode(request))
        XCTAssertEqual(roundTrip.diagnostics, diagnostics)
        let longValue = String(repeating: "a", count: 10000) + "\u{202e}"
        XCTAssertEqual(AuthorizationRequest.display(longValue, limit: Int.max),
                       String(repeating: "a", count: 10000) + "\\u{202e}")
    }

    func testCallerControlCharactersCannotReorderIdentity() {
        XCTAssertEqual(AuthorizationRequest.display("git\u{202e}ssh\nPID: 1"), "git\\u{202e}ssh\\u{a}PID: 1")
        XCTAssertEqual(AuthorizationRequest.display("**git**"), "**git**")
    }
    func testUnicodeAndLongIdentityRemainBounded() {
        XCTAssertEqual(AuthorizationRequest.display("clé🔐"), "clé🔐")
        XCTAssertEqual(AuthorizationRequest.display(String(repeating: "a", count: 10000)).count, 8192)
    }
    func testHomeAbbreviationRequiresAPathBoundary() {
        XCTAssertEqual(AuthorizationRequest.abbreviatedDirectory("/Users/me/code/seccy", home: "/Users/me"), "~/code/seccy")
        XCTAssertEqual(AuthorizationRequest.abbreviatedDirectory("/Users/me", home: "/Users/me"), "~")
        XCTAssertEqual(AuthorizationRequest.abbreviatedDirectory("/Users/me-other/code", home: "/Users/me"), "/Users/me-other/code")
    }

    func testVendoredArtworkDecodesAndRendersWithoutExternalResources() throws {
        for name in ["github", "gitlab", "bitbucket", "git", "cloud_upload", "cloud_download", "commit", "sell", "key", "password", "lock_open", "data_object"] {
            let image = Copy.icon(name)
            XCTAssertFalse(image.representations.isEmpty)
            XCTAssertNotNil(image.tiffRepresentation, name)
        }
        for (scenario, target) in [("github", "github"), ("gitlab", "gitlab"), ("bitbucket", "bitbucket"), ("generic", "git")] {
            let request = Copy.fixture(scenario)
            XCTAssertEqual(request.header?.target, target)
            XCTAssertEqual(request.appPid, 4000)
        }
    }
    func testSecurityWarningsSurvivePresentation() {
        XCTAssertTrue(AuthorizationRequest.revoked.body.contains("[REVOKED]"))
        XCTAssertEqual(AuthorizationRequest.revoked.title, "Approve the git push?")
        XCTAssertTrue(AuthorizationRequest.secrets.body.contains("to decrypt secrets GITHUB_TOKEN, DATABASE_URL"))
    }
}

final class GallerySettingsTests: XCTestCase {
    func testSettingsRoundTripAndCustomKeyUpdatesAllPresentationCopy() throws {
        let suite = "seccy.gallery.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = GalleryModel(defaults: defaults)
        model.scenario = "fetch"
        model.hosting = "gitlab"
        model.appearance = "dark"
        model.live = false
        model.state = .failure
        model.keyName = "Personal **key**\n\u{202e}"
        model.directory = "~/projects/custom"

        let restored = GalleryModel(defaults: defaults)
        XCTAssertEqual(restored.scenario, "fetch")
        XCTAssertEqual(restored.hosting, "gitlab")
        XCTAssertEqual(restored.appearance, "dark")
        XCTAssertFalse(restored.live)
        XCTAssertEqual(restored.state, .failure)
        XCTAssertEqual(restored.keyName, model.keyName)
        XCTAssertEqual(restored.directory, model.directory)
        let request = restored.request
        let escaped = AuthorizationRequest.display(model.keyName)
        XCTAssertEqual(request.key, model.keyName)
        XCTAssertTrue(request.body.contains(escaped))
        XCTAssertTrue(try XCTUnwrap(request.notification).body.contains(escaped))
        XCTAssertEqual(request.header?.permission.first(where: { $0.kind == "key" })?.value, escaped)
        XCTAssertEqual(request.header?.target, "gitlab")
        XCTAssertEqual(request.workingDirectory, NSHomeDirectory() + "/projects/custom")

        restored.scenario = "secrets"
        XCTAssertFalse(restored.supportsHosting)
        XCTAssertEqual(restored.request.header?.target, "data_object")
        restored.directory = ""
        XCTAssertNil(restored.request.workingDirectory)
    }
}

final class AuthorizationSessionTests: XCTestCase {
    func testLateSuccessCannotAuthorizeCancelledRequest() {
        var session = AuthorizationSession()
        let attempt = session.beginAttempt()!
        session.cancel()
        XCTAssertFalse(session.acceptResult(attempt, success: true))
        XCTAssertFalse(session.approved)
        XCTAssertNil(session.beginAttempt())
    }
    func testOnlyCurrentAttemptCanAuthorizeAndCompletionIsFinal() {
        var session = AuthorizationSession()
        let old = session.beginAttempt()!
        let current = session.beginAttempt()!
        XCTAssertFalse(session.acceptResult(old, success: true))
        XCTAssertTrue(session.acceptResult(current, success: true))
        XCTAssertTrue(session.approved)
        XCTAssertTrue(session.finished)
        XCTAssertFalse(session.acceptResult(current, success: true))
    }
    func testFailedAttemptDoesNotAuthorizeAndCanBeRetried() {
        var session = AuthorizationSession()
        let failed = session.beginAttempt()!
        XCTAssertTrue(session.acceptResult(failed, success: false))
        XCTAssertFalse(session.approved)
        XCTAssertFalse(session.acceptResult(failed, success: true))
        XCTAssertNotNil(session.beginAttempt())
    }
}

final class GalleryAuthenticationTests: XCTestCase {
    func testRetryUsesFreshContextAndWaitsForViewBeforeAuthentication() {
        let demo = GalleryAuthentication()
        let initial = demo.context
        demo.start()
        XCTAssertFalse(initial === demo.context)
        XCTAssertEqual(demo.state, .ready)
        let firstAttempt = demo.context
        demo.cancel()
        demo.start()
        XCTAssertFalse(firstAttempt === demo.context)
        XCTAssertEqual(demo.state, .ready)
        demo.cancel()
    }

    func testCancelledDemoCannotStartWhenItsViewAppearsLater() {
        let demo = GalleryAuthentication()
        demo.start()
        demo.cancel()
        demo.appeared()
        XCTAssertEqual(demo.state, .cancelled)
    }
}

final class NativeLayoutTests: XCTestCase {
    func testEscapeDeniesBorderlessWindow() throws {
        let window = makeAuthorizationWindow(Text("Prompt")) as! AuthorizationWindow
        defer { window.close() }
        var denied = 0
        window.denyAction = { denied += 1 }
        let event = try XCTUnwrap(NSEvent.keyEvent(
            with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil,
            characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}",
            isARepeat: false, keyCode: 53))
        window.sendEvent(event)
        XCTAssertEqual(denied, 1)
    }

    func testWindowLayoutGrowsAndShrinksKeepingCenter() {
        let window = AuthorizationWindow(contentRect: NSRect(x: 100, y: 200, width: 540, height: 460),
                                         styleMask: .borderless, backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.close() }
        let visible = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
        let expectedLimit = floor(min(900, (visible?.height ?? 800) * 0.85))
        // Stay below the cap and away from screen edges when testing centered resizes.
        let compact = 2 * floor(expectedLimit / 4)
        let expanded = 2 * floor(expectedLimit / 3)
        window.setFrame(NSRect(x: (visible?.midX ?? 400) - 270,
                               y: floor(visible?.midY ?? 400) - compact / 2,
                               width: 540, height: compact), display: false)
        let center = window.frame.midY
        let host = AuthorizationWindowLayout.Host()
        window.contentView = host
        var limit: CGFloat = 0
        func resize(_ height: CGFloat) {
            host.configuration = AuthorizationWindowLayout(
                size: CGSize(width: 540, height: height), cancel: {},
                heightLimitChanged: { limit = $0 })
            host.scheduleUpdate()
            let updated = expectation(description: "Window resized")
            DispatchQueue.main.async { updated.fulfill() }
            wait(for: [updated], timeout: 2)
        }
        resize(expanded)
        XCTAssertEqual(window.frame.height, expanded)
        XCTAssertEqual(window.frame.midY, center)
        XCTAssertEqual(limit, expectedLimit)
        resize(compact)
        XCTAssertEqual(window.frame.height, compact)
        XCTAssertEqual(window.frame.midY, center)
        resize(2000)
        XCTAssertEqual(window.frame.height, expectedLimit)
    }

    func testBorderlessPromptDragExcludesInteractiveRegions() throws {
        let window = try XCTUnwrap(makeAuthorizationWindow(
            AuthorizationView(request: .signing, state: .ready)) as? AuthorizationWindow)
        defer {
            window.orderOut(nil)
            window.contentViewController = nil
            window.close()
        }
        window.setContentSize(NSSize(width: 540, height: 560))
        let content = try XCTUnwrap(window.contentView)
        content.layoutSubtreeIfNeeded()
        XCTAssertFalse(window.styleMask.contains(.titled))
        XCTAssertTrue(window.canBecomeKey)
        XCTAssertTrue(window.canBecomeMain)
        XCTAssertTrue(window.canDrag(at: NSPoint(x: 270, y: 540)))
        func exclusions(_ view: NSView) -> [WindowDragExclusionView] {
            (view as? WindowDragExclusionView).map { [$0] } ??
                view.subviews.flatMap(exclusions)
        }
        let regions = exclusions(content)
        // Three process chips, full list, directory, repo link, action, key, Deny and Touch ID.
        XCTAssertEqual(regions.count, 10)
        for region in regions {
            XCTAssertGreaterThan(region.bounds.width, 0)
            XCTAssertGreaterThan(region.bounds.height, 0)
            let center = region.convert(NSPoint(x: region.bounds.midX, y: region.bounds.midY), to: nil)
            XCTAssertFalse(window.canDrag(at: center))
            XCTAssertNil(region.hitTest(.zero), "Markers must not intercept control events")
        }
    }

    func testSmallFingerprintFitsItsReservedSpace() {
        let view = LAAuthenticationView(context: LAContext(), controlSize: .small)
        let size = view.fittingSize
        XCTAssertGreaterThan(size.width, 0)
        XCTAssertGreaterThan(size.height, 0)
        XCTAssertLessThanOrEqual(size.width, 64)
        XCTAssertLessThanOrEqual(size.height, 64)
    }
}

final class FingerprintIdentityTests: XCTestCase {
    func testStatusAndCopyUpdatesKeepTheSameNativeFingerprintView() throws {
        // No biometric evaluation: inspect the mounted native view across the
        // same SwiftUI state transitions the production prompt receives.
        let context = LAContext()
        let host = NSHostingView(rootView: AuthorizationView(request: .signing, state: .ready, context: context))
        host.frame = NSRect(x: 0, y: 0, width: 480, height: 600)
        func fingerprint(in view: NSView) -> LAAuthenticationView? {
            if let match = view as? LAAuthenticationView { return match }
            for child in view.subviews {
                if let match = fingerprint(in: child) { return match }
            }
            return nil
        }
        host.layoutSubtreeIfNeeded()
        let original = try XCTUnwrap(fingerprint(in: host))
        for state in [AuthorizationState.authenticating, .failure, .ready, .success] {
            host.rootView = AuthorizationView(request: .secrets, state: state, context: context)
            host.layoutSubtreeIfNeeded()
            let updated = try XCTUnwrap(fingerprint(in: host))
            XCTAssertTrue(updated === original, "Native fingerprint recreated for \(state)")
            XCTAssertTrue(updated.context === context)
        }
        // Positive control: an explicit retry's fresh context must replace it.
        let retryContext = LAContext()
        host.rootView = AuthorizationView(request: .signing, state: .ready, context: retryContext)
        host.layoutSubtreeIfNeeded()
        let replacement = try XCTUnwrap(fingerprint(in: host))
        XCTAssertFalse(replacement === original)
        XCTAssertTrue(replacement.context === retryContext)
        retryContext.invalidate()
        context.invalidate()
    }
}

final class FingerprintHostTests: XCTestCase {
    func testMountedFingerprintPreservesNativeDimensionsInWindowCoordinates() throws {
        let context = LAContext()
        let window = makeAuthorizationWindow(
            AuthorizationView(request: .signing, state: .authenticating, context: context))
        defer {
            context.invalidate()
            window.close()
        }
        showAuthorizationWindow(window)
        let laidOut = expectation(description: "Window laid out")
        DispatchQueue.main.async { laidOut.fulfill() }
        wait(for: [laidOut], timeout: 2)
        window.contentView?.layoutSubtreeIfNeeded()
        func fingerprint(in view: NSView) -> LAAuthenticationView? {
            if let native = view as? LAAuthenticationView { return native }
            return view.subviews.lazy.compactMap { fingerprint(in: $0) }.first
        }
        let native = try XCTUnwrap(fingerprint(in: XCTUnwrap(window.contentView)))
        let displayed = native.convert(native.bounds, to: nil)
        let required = native.fittingSize
        XCTAssertEqual(displayed.width, required.width, accuracy: 0.01,
                       "Scaling the native view causes LocalAuthentication to cancel")
        XCTAssertEqual(displayed.height, required.height, accuracy: 0.01)
    }

    func testNativeInvalidationKeepsHostAndChildGeometryStable() {
        let context = LAContext()
        let host = FingerprintHostView(context: context)
        host.layoutSubtreeIfNeeded()
        let originalFrame = host.authenticationView.frame
        XCTAssertEqual(host.intrinsicContentSize, NSSize(width: 32, height: 32))
        XCTAssertTrue(host.bounds.contains(originalFrame))
        XCTAssertGreaterThan(originalFrame.width, 0)
        XCTAssertGreaterThan(originalFrame.height, 0)
        for _ in 0..<10 {
            host.authenticationView.invalidateIntrinsicContentSize()
            host.needsLayout = true
            host.layoutSubtreeIfNeeded()
            XCTAssertEqual(host.authenticationView.frame, originalFrame)
            XCTAssertEqual(host.intrinsicContentSize, NSSize(width: 32, height: 32))
        }
        context.invalidate()
    }
}

final class SharedCopyTests: XCTestCase {
    func testEveryNativeAuthenticationStateHasCatalogCopy() {
        for state in AuthorizationState.allCases {
            XCTAssertFalse(state.label.isEmpty)
            XCTAssertFalse(state.message.isEmpty)
        }
    }

    func testProductionShapeDecodesWithoutGalleryNotificationOrLegacyDetails() throws {
        let json = #"{"content":{"title":"Authorize?","body":"Literal **value**","warning":true},"key":"work","fingerprint":"sample","executable":"/usr/bin/git","pid":42,"pidLabel":"PID 42"}"#
        let request = try JSONDecoder().decode(AuthorizationRequest.self, from: Data(json.utf8))
        XCTAssertNil(request.notification)
        XCTAssertEqual(request.title, "Authorize?")
        XCTAssertEqual(request.body, "Literal **value**")
        XCTAssertTrue(request.content.warning)
    }

    func testGalleryNotificationsUseCompletedActionCopyAndPreserveWarnings() throws {
        let signing = try XCTUnwrap(AuthorizationRequest.signing.notification)
        XCTAssertEqual(signing.title, "seccy: key used")
        XCTAssertTrue(signing.body.contains("used the work key"))
        XCTAssertFalse(signing.body.contains("wants to use"))
        XCTAssertTrue(try XCTUnwrap(AuthorizationRequest.revoked.notification).body.contains("[REVOKED]"))
        XCTAssertTrue(AuthorizationRequest.revoked.content.warning)
        XCTAssertFalse(AuthorizationRequest.signing.content.warning)
    }
}
