import Foundation

// Enabled only by the gallery. Production CLI stdout remains protocol/output data.
// No request text, executable paths, secret names, or biometric data are logged.
enum UITrace {
    private static let lock = NSLock()
    private static var enabled = false
    private static var started = ProcessInfo.processInfo.systemUptime
    private static let timestamp = ISO8601DateFormatter()

    static func enable() {
        lock.lock()
        started = ProcessInfo.processInfo.systemUptime
        timestamp.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        enabled = true
        lock.unlock()
        event("trace.started")
    }

    static func id(_ object: AnyObject?) -> String {
        object.map { String(describing: ObjectIdentifier($0)) } ?? "nil"
    }

    static func event(_ name: String, _ fields: @autoclosure () -> [String: String] = [:]) {
        lock.lock()
        defer { lock.unlock() }
        guard enabled else { return }
        let record: [String: Any] = [
            "time": timestamp.string(from: Date()),
            "elapsed_ms": Int((ProcessInfo.processInfo.systemUptime - started) * 1000),
            "pid": ProcessInfo.processInfo.processIdentifier,
            "thread": Thread.isMainThread ? "main" : "background",
            "event": name,
            "fields": fields(),
        ]
        guard var bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else { return }
        bytes.append(0x0a)
        // FileHandle writes immediately, even when stdout is piped through tee.
        FileHandle.standardOutput.write(bytes)
    }
}
