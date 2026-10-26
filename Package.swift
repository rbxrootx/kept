// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Kept",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Kept", targets: ["Kept"]),
        .library(name: "KDBXKit", targets: ["KDBXKit"]),
    ],
    targets: [
        .target(
            name: "KDBXKit",
            swiftSettings: [.unsafeFlags(["-Ounchecked"], .when(configuration: .release))]
        ),
        .executableTarget(
            name: "Kept",
            dependencies: ["KDBXKit"]
        ),
        .testTarget(
            name: "KDBXKitTests",
            dependencies: ["KDBXKit"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
