// swift-tools-version:6.0
import Foundation
import PackageDescription

// On a Mac with only the Command Line Tools (no Xcode) the toolchain ships neither XCTest nor the
// Testing module. Setting KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 adds Apple's swift-testing package as
// a test-only dependency so `swift test --build-system native` works there (see README.md). With
// Xcode installed the toolchain's own Testing module is used and nothing is downloaded. The library
// product itself has no dependencies.
let testingFromSource = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_TESTING_FROM_SOURCE"] == "1"

let package = Package(
  name: "KeycloakNative",
  platforms: [.iOS(.v17), .macOS(.v14)],
  products: [
    .library(name: "KeycloakNativeCore", targets: ["KeycloakNativeCore"])
    // Later phases: KeycloakNativeUI (default screens), KeycloakNativePush (spec/05 §1).
  ],
  dependencies: testingFromSource
    ? [.package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4")]
    : [],
  targets: [
    .target(name: "KeycloakNativeCore"),
    .testTarget(
      name: "KeycloakNativeCoreTests",
      dependencies: ["KeycloakNativeCore"]
        + (testingFromSource ? [.product(name: "Testing", package: "swift-testing")] : [])
    ),
  ],
  swiftLanguageModes: [.v6]
)
