import XCTest
import UserNotifications
@testable import SeccyUI

private final class TestNotificationTransport: NotificationTransport {
    var currentPermission: NotificationPermission = .allowed
    var permissionRequests = 0
    var pendingPermission: ((Result<Bool, Error>) -> Void)?
    var requests: [UNNotificationRequest] = []
    var addError: Error?
    func permission(_ completion: @escaping (NotificationPermission) -> Void) { completion(currentPermission) }
    func authorize(_ completion: @escaping (Result<Bool, Error>) -> Void) {
        permissionRequests += 1
        pendingPermission = completion
    }
    func add(_ request: UNNotificationRequest, completion: @escaping (Error?) -> Void) {
        requests.append(request)
        completion(addError)
    }
}

final class NotificationTests: XCTestCase {
    func testAuthorizedSubmissionPreservesLiteralContentAndHasNoPrivilegedActions() throws {
        let transport = TestNotificationTransport()
        var succeeded = false
        _ = NativeNotifications.submit(title: "seccy: key used", body: "**literal**\n$(not a command)", transport: transport) {
            if case .success = $0 { succeeded = true }
        }
        XCTAssertTrue(succeeded)
        XCTAssertEqual(transport.permissionRequests, 0)
        let content = try XCTUnwrap(transport.requests.first).content
        XCTAssertEqual(content.title, "seccy: key used")
        XCTAssertEqual(content.body, "**literal**\n$(not a command)")
        XCTAssertEqual(content.categoryIdentifier, "")
        XCTAssertTrue(content.userInfo.isEmpty)
        XCTAssertNil(content.sound)
        XCTAssertNil(content.badge)
        XCTAssertEqual(transport.requests.count, 1)
        XCTAssertNil(transport.requests[0].trigger)
    }

    func testDeniedPermissionDoesNotScheduleOrPromptAgain() {
        let transport = TestNotificationTransport()
        transport.currentPermission = .denied
        var failure: NotificationFailure?
        _ = NativeNotifications.submit(title: "title", body: "body", transport: transport) {
            if case .failure(let error) = $0 { failure = error }
        }
        XCTAssertEqual(failure, .denied)
        XCTAssertEqual(transport.permissionRequests, 0)
        XCTAssertTrue(transport.requests.isEmpty)
    }

    func testInitialAuthorizationSchedulesExactlyOnce() {
        let transport = TestNotificationTransport()
        transport.currentPermission = .undetermined
        var completions = 0
        _ = NativeNotifications.submit(title: "title", body: "body", transport: transport) { _ in completions += 1 }
        XCTAssertTrue(transport.requests.isEmpty)
        XCTAssertEqual(transport.permissionRequests, 1)
        transport.pendingPermission?(.success(true))
        transport.pendingPermission?(.success(true))
        XCTAssertEqual(transport.requests.count, 1)
        XCTAssertEqual(completions, 1)
    }

    func testTimeoutPreventsLatePermissionFromDelivering() {
        let transport = TestNotificationTransport()
        transport.currentPermission = .undetermined
        var failure: NotificationFailure?
        let submission = NativeNotifications.submit(title: "title", body: "body", transport: transport) {
            if case .failure(let error) = $0 { failure = error }
        }
        submission.cancel()
        transport.pendingPermission?(.success(true))
        XCTAssertEqual(failure, .timedOut)
        XCTAssertTrue(transport.requests.isEmpty)
    }

    func testAuthorizationAndSubmissionFailuresAreReported() {
        for granted in [false, true] {
            let transport = TestNotificationTransport()
            transport.currentPermission = .undetermined
            transport.addError = NSError(domain: "test", code: 1)
            var failure: NotificationFailure?
            _ = NativeNotifications.submit(title: "title", body: "body", transport: transport) {
                if case .failure(let error) = $0 { failure = error }
            }
            transport.pendingPermission?(.success(granted))
            XCTAssertEqual(failure, granted ? .system : .denied)
        }
    }
}
