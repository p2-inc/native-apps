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
    .library(name: "KeycloakNativeCore", targets: ["KeycloakNativeCore"]),
    // Default SwiftUI screens driving a flow end to end; every screen is replaceable (spec/05 §4).
    .library(name: "KeycloakNativeUI", targets: ["KeycloakNativeUI"]),
    // Later: KeycloakNativePush (spec/05 §5).
  ],
  dependencies: testingFromSource
    ? [.package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4")]
    : [],
  targets: [
    .target(name: "KeycloakNativeCore"),
    // Localizable.xcstrings (spec/05 §4): English source, German; apps override with .nativeLoginStrings(bundle:).
    .target(name: "KeycloakNativeUI", dependencies: ["KeycloakNativeCore"], resources: [.process("Resources")]),
    .testTarget(
      name: "KeycloakNativeCoreTests",
      dependencies: ["KeycloakNativeCore"]
        + (testingFromSource ? [.product(name: "Testing", package: "swift-testing")] : [])
    ),
    .testTarget(
      name: "KeycloakNativeUITests",
      dependencies: ["KeycloakNativeUI", "KeycloakNativeCore"]
        + (testingFromSource ? [.product(name: "Testing", package: "swift-testing")] : [])
    ),
  ],
  swiftLanguageModes: [.v6]
)
