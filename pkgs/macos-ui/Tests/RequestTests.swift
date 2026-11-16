import XCTest
import SwiftUI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
@testable import SeccyUI

final class RequestTests: XCTestCase {
    func testCallerControlCharactersCannotReorderIdentity() {
        XCTAssertEqual(AuthorizationRequest.display("git\u{202e}ssh\nPID: 1"), "git\\u{202e}ssh\\u{a}PID: 1")
        XCTAssertEqual(AuthorizationRequest.display("**git**"), "**git**")
    }
    func testUnicodeAndLongIdentityRemainBounded() {
        XCTAssertEqual(AuthorizationRequest.display("clé🔐"), "clé🔐")
        XCTAssertEqual(AuthorizationRequest.display(String(repeating: "a", count: 10000)).count, 8192)
    }
    func testSecurityWarningsSurvivePresentation() {
        XCTAssertTrue(AuthorizationRequest.revoked.body.contains("[REVOKED]"))
        XCTAssertEqual(AuthorizationRequest.revoked.title, "Approve the git push?")
        XCTAssertTrue(AuthorizationRequest.secrets.body.contains("named secrets"))
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
    func testNativeInvalidationKeepsHostAndChildGeometryStable() {
        let context = LAContext()
        let host = FingerprintHostView(context: context)
        host.layoutSubtreeIfNeeded()
        let originalFrame = host.authenticationView.frame
        XCTAssertEqual(host.intrinsicContentSize, NSSize(width: 64, height: 64))
        XCTAssertTrue(host.bounds.contains(originalFrame))
        XCTAssertGreaterThan(originalFrame.width, 0)
        XCTAssertGreaterThan(originalFrame.height, 0)
        for _ in 0..<10 {
            host.authenticationView.invalidateIntrinsicContentSize()
            host.needsLayout = true
            host.layoutSubtreeIfNeeded()
            XCTAssertEqual(host.authenticationView.frame, originalFrame)
            XCTAssertEqual(host.intrinsicContentSize, NSSize(width: 64, height: 64))
        }
        context.invalidate()
    }
}
