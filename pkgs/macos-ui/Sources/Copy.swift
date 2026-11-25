import Foundation
import AppKit

// Fluent runs in Rust. This build-time projection keeps standalone previews and
// native-only authentication states on the same catalog as production requests.
enum Copy {
    private struct Catalog: Decodable {
        let labels: [String: String]
        let fixtures: [String: AuthorizationRequest]
        let icons: [String: String]
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
    private static let images: [String: NSImage] = catalog.icons.mapValues { svg in
        guard let image = NSImage(data: Data(svg.utf8)) else {
            preconditionFailure("Invalid vendored SVG")
        }
        return image
    }
    static func icon(_ id: String, size: CGFloat = 64) -> NSImage {
        guard let source = images[id], let image = source.copy() as? NSImage else {
            preconditionFailure("Missing vendored icon: \(id)")
        }
        image.size = NSSize(width: size, height: size)
        image.isTemplate = ["github", "cloud_upload", "cloud_download", "commit", "sell", "key", "password", "lock_open", "data_object"].contains(id)
        return image
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

struct AuthorizationHeader: Codable {
    var requestTitle: String? = nil
    var keyAction: String? = nil
    let title: String
    let target: String
    let action: String
    let permission: [PermissionPart]
}

struct PermissionPart: Codable {
    let kind: String
    let value: String
}

struct GalleryCopy: Codable {
    let content: AuthorizationContent
    let notification: NotificationContent
    let header: AuthorizationHeader
}
