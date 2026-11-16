// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SeccyUI",
    platforms: [.macOS(.v12)],
    products: [.library(name: "SeccyUI", type: .static, targets: ["SeccyUI"])],
    targets: [
        .target(name: "SeccyUI", path: "Sources"),
        .testTarget(name: "SeccyUITests", dependencies: ["SeccyUI"], path: "Tests")
    ]
)
