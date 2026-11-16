import Foundation

// Fluent runs in Rust. This build-time projection keeps standalone previews and
// native-only authentication states on the same catalog as production requests.
enum Copy {
    private struct Catalog: Decodable {
        let labels: [String: String]
        let fixtures: [String: AuthorizationRequest]
    }
    private static let catalog = try! JSONDecoder().decode(Catalog.self, from: Data(sharedCopyJSON.utf8))
    static func text(_ id: String) -> String {
        guard let text = catalog.labels[id] else { preconditionFailure("Missing Fluent label: \(id)") }
        return text
    }
    static func fixture(_ id: String) -> AuthorizationRequest {
        guard let request = catalog.fixtures[id] else { preconditionFailure("Missing Fluent fixture: \(id)") }
        return request
    }
}

struct AuthorizationContent: Codable {
    let title: String
    let body: String
    let warning: Bool
}

struct NotificationContent: Codable {
    let title: String
    let body: String
}
