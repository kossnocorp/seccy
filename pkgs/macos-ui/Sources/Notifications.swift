import Foundation
import CoreServices
import UserNotifications

// Notification text is literal and informational; no response can authorize key use.
enum NotificationPermission { case undetermined, allowed, denied }
enum NotificationFailure: Int32, Error {
    case unavailableBundle = 1, denied = 2, system = 3, timedOut = 4
    var message: String {
        switch self {
        case .unavailableBundle: return Copy.text("notification-error-bundle")
        case .denied: return Copy.text("notification-error-denied")
        case .system: return Copy.text("notification-error-system")
        case .timedOut: return Copy.text("notification-error-timeout")
        }
    }
}

protocol NotificationTransport {
    func permission(_ completion: @escaping (NotificationPermission) -> Void)
    func authorize(_ completion: @escaping (Result<Bool, Error>) -> Void)
    func add(_ request: UNNotificationRequest, completion: @escaping (Error?) -> Void)
}

final class SystemNotificationTransport: NotificationTransport {
    let center: UNUserNotificationCenter
    init(center: UNUserNotificationCenter) { self.center = center }
    func permission(_ completion: @escaping (NotificationPermission) -> Void) {
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined: completion(.undetermined)
            case .authorized, .provisional:
                completion(settings.alertSetting == .disabled ? .denied : .allowed)
            default: completion(.denied)
            }
        }
    }
    func authorize(_ completion: @escaping (Result<Bool, Error>) -> Void) {
        center.requestAuthorization(options: [.alert]) { granted, error in
            if let error = error { completion(.failure(error)) }
            else { completion(.success(granted)) }
        }
    }
    func add(_ request: UNNotificationRequest, completion: @escaping (Error?) -> Void) {
        center.add(request, withCompletionHandler: completion)
    }
}

// Owns a single async submission. Cancelling while permission is pending prevents
// a later permission response from scheduling a notification after the caller exits.
final class NotificationSubmission {
    private let lock = NSLock()
    private var finished = false
    private var scheduled = false
    private let completion: (Result<Void, NotificationFailure>) -> Void
    init(completion: @escaping (Result<Void, NotificationFailure>) -> Void) { self.completion = completion }

    func finish(_ result: Result<Void, NotificationFailure>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        completion(result)
    }
    func cancel() { finish(.failure(.timedOut)) }
    func schedule(_ request: UNNotificationRequest, transport: NotificationTransport) {
        lock.lock()
        guard !finished, !scheduled else { lock.unlock(); return }
        scheduled = true
        lock.unlock()
        UITrace.event("notification.enqueue", ["id": request.identifier])
        transport.add(request) { error in
            UITrace.event("notification.result", ["success": String(error == nil), "code": String((error as NSError?)?.code ?? 0)])
            self.finish(error == nil ? .success(()) : .failure(.system))
        }
    }
}

final class NativeNotifications: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NativeNotifications()
    // Lazy access: UNUserNotificationCenter.current() can raise an Objective-C
    // exception in an unbundled CLI/test host. Check bundle identity first.
    private lazy var center = UNUserNotificationCenter.current()
    private let configurationLock = NSLock()
    private var configured = false
    private static var hasBundle: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
    }

    func configure() {
        guard Self.hasBundle else { return }
        configurationLock.lock()
        defer { configurationLock.unlock() }
        guard !configured else { return }
        // The gallery and CLI are launched directly from a terminal, not always
        // through Finder/open. Register the real bundle so its icon and identity
        // are available to Notification Center in either launch path.
        let status = LSRegisterURL(Bundle.main.bundleURL as CFURL, true)
        UITrace.event("notification.configure", ["bundle": Bundle.main.bundleIdentifier ?? "", "registration_status": String(status)])
        center.delegate = self
        configured = true
        // No category/actions yet: clicking can only activate this app. No Finder,
        // Script Editor, URL, shell command, or key operation is invoked.
    }

    static func content(title: String, body: String) -> UNMutableNotificationContent {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.threadIdentifier = "seccy.key-activity"
        // Preserve silent informational notifications. Focus and display style
        // remain user choices; do not request critical/time-sensitive treatment.
        return content
    }

    static func submit(title: String, body: String, transport: NotificationTransport,
                       completion: @escaping (Result<Void, NotificationFailure>) -> Void) -> NotificationSubmission {
        let submission = NotificationSubmission(completion: completion)
        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content(title: title, body: body), trigger: nil)
        transport.permission { permission in
            switch permission {
            case .allowed: submission.schedule(request, transport: transport)
            case .denied: submission.finish(.failure(.denied))
            case .undetermined:
                UITrace.event("notification.request_permission")
                transport.authorize { result in
                    switch result {
                    case .success(true): submission.schedule(request, transport: transport)
                    case .success(false): submission.finish(.failure(.denied))
                    case .failure: submission.finish(.failure(.system))
                    }
                }
            }
        }
        return submission
    }

    func send(title: String, body: String,
              completion: @escaping (Result<Void, NotificationFailure>) -> Void) -> NotificationSubmission {
        guard Self.hasBundle else {
            let submission = NotificationSubmission(completion: completion)
            submission.finish(.failure(.unavailableBundle))
            return submission
        }
        configure()
        UITrace.event("notification.submit", ["bundle": Bundle.main.bundleIdentifier ?? ""])
        return Self.submit(title: title, body: body, transport: SystemNotificationTransport(center: center), completion: completion)
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completion: @escaping (UNNotificationPresentationOptions) -> Void) {
        UITrace.event("notification.present", ["id": notification.request.identifier])
        completion([.banner, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completion: @escaping () -> Void) {
        UITrace.event("notification.response", ["action": response.actionIdentifier])
        completion()
    }
}

@_cdecl("seccy_notifications_configure")
public func seccyNotificationsConfigure() { NativeNotifications.shared.configure() }

@_cdecl("seccy_notify")
public func seccyNotify(_ title: UnsafePointer<CChar>, _ body: UnsafePointer<CChar>) -> Int32 {
    // UN callbacks arrive on the framework's queue; do not dispatch them to the
    // Rust agent's main thread, which may be serving sockets without an app loop.
    let signal = DispatchSemaphore(value: 0)
    let resultLock = NSLock()
    var code: Int32 = NotificationFailure.system.rawValue
    let submission = NativeNotifications.shared.send(title: String(cString: title), body: String(cString: body)) { result in
        resultLock.lock()
        switch result {
        case .success: code = 0
        case .failure(let error): code = error.rawValue
        }
        resultLock.unlock()
        signal.signal()
    }
    if signal.wait(timeout: .now() + 120) == .timedOut {
        submission.cancel()
        return NotificationFailure.timedOut.rawValue
    }
    resultLock.lock()
    defer { resultLock.unlock() }
    return code
}
