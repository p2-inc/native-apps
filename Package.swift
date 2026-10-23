// swift-tools-version:6.0
import Foundation
import PackageDescription

// The iOS SDK (sources and tests under ios/KeycloakNative/). The manifest sits at the repository root
// so SwiftPM can consume the repository by URL: `.package(url: "<repo>", from: "<version>")` with
// products from package "native-apps".
//
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
    // Push MFA device side (spec/05 §5): enrolment, approvals, APNs token sync, key rotation.
    .library(name: "KeycloakNativePush", targets: ["KeycloakNativePush"]),
  ],
  dependencies: testingFromSource
    ? [.package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4")]
    : [],
  targets: [
    .target(name: "KeycloakNativeCore", path: "ios/KeycloakNative/Sources/KeycloakNativeCore"),
    .target(name: "KeycloakNativePush", dependencies: ["KeycloakNativeCore"], path: "ios/KeycloakNative/Sources/KeycloakNativePush"),
    // Localizable.xcstrings (spec/05 §4): English source, German; apps override with .nativeLoginStrings(bundle:).
    // Depends on the push module for the push / push_enrollment screens and the approvals list.
    .target(
      name: "KeycloakNativeUI", dependencies: ["KeycloakNativeCore", "KeycloakNativePush"], path: "ios/KeycloakNative/Sources/KeycloakNativeUI",
      resources: [.process("Resources")]),
    .testTarget(
      name: "KeycloakNativeCoreTests",
      dependencies: ["KeycloakNativeCore", "KeycloakNativePush"]
        + (testingFromSource ? [.product(name: "Testing", package: "swift-testing")] : []),
      path: "ios/KeycloakNative/Tests/KeycloakNativeCoreTests"
    ),
    .testTarget(
      name: "KeycloakNativeUITests",
      dependencies: ["KeycloakNativeUI", "KeycloakNativeCore", "KeycloakNativePush"]
        + (testingFromSource ? [.product(name: "Testing", package: "swift-testing")] : []),
      path: "ios/KeycloakNative/Tests/KeycloakNativeUITests"
    ),
  ],
  swiftLanguageModes: [.v6]
)
