// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "CyberBus",
    platforms: [.macOS(.v11), .iOS(.v13)],
    products: [.library(name: "CyberBus", targets: ["CyberBus"])],
    targets: [
        .binaryTarget(name: "CCyberBus", path: "CyberBus.xcframework"),
        .target(name: "CyberBus", dependencies: ["CCyberBus"], linkerSettings: [
            .linkedFramework("Security"), .linkedFramework("SystemConfiguration"),
            .linkedFramework("CoreFoundation"), .linkedLibrary("resolv"), .linkedLibrary("iconv")
        ]),
        .testTarget(name: "CyberBusTests", dependencies: ["CyberBus", "CCyberBus"])
    ])
