// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "DockerVisionSDK",
    platforms: [
        .iOS(.v17), .macOS(.v13), .visionOS(.v1)
    ],
    products: [
        .library(name: "DockerVisionSDK", targets: ["DockerVisionSDK"])
    ],
    targets: [
        .target(name: "DockerVisionSDK"),
        .testTarget(name: "DockerVisionSDKTests", dependencies: ["DockerVisionSDK"])
    ]
)
