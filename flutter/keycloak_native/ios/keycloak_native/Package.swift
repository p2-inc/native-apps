// swift-tools-version: 5.9
// The iOS half of the Flutter plugin (spec/18 §3): a bridge from the Pigeon host API to the iOS SDK
// (products KeycloakNativeCore of the Swift package at the root of p2-inc/native-apps).
//
// Inside the repository the SDK is the local package four directories up, so a change there is
// picked up without a release (spec/18 §8). Flutter reaches this manifest through a symlink, so the
// path is resolved from the real location. A copy outside the repository (pub.dev) resolves the SDK
// by URL at the plugin's version.

import Foundation
import PackageDescription

let pluginDirectory = URL(fileURLWithPath: #filePath).resolvingSymlinksInPath().deletingLastPathComponent()
let repositoryRoot = pluginDirectory.appendingPathComponent("../../../..").standardizedFileURL
let inRepository = FileManager.default.fileExists(atPath: repositoryRoot.appendingPathComponent("ios/KeycloakNative").path)

/// The SDK version a published plugin is built against (one version line for the server, the SDKs and the plugin).
let sdkVersion = "0.3.0"

let sdk: Package.Dependency = inRepository
  ? .package(path: repositoryRoot.path)
  : .package(url: "https://github.com/p2-inc/native-apps.git", exact: Version(stringLiteral: sdkVersion))

/// A path dependency's identity is its directory name (the worktree's name inside the repository).
let sdkIdentity = inRepository ? repositoryRoot.lastPathComponent.lowercased() : "native-apps"

let package = Package(
  name: "keycloak_native",
  platforms: [
    // The iOS SDK's minimum.
    .iOS("17.0")
  ],
  products: [
    .library(name: "keycloak-native", targets: ["keycloak_native"])
  ],
  dependencies: [
    .package(name: "FlutterFramework", path: "../FlutterFramework"),
    sdk,
  ],
  targets: [
    .target(
      name: "keycloak_native",
      dependencies: [
        .product(name: "FlutterFramework", package: "FlutterFramework"),
        .product(name: "KeycloakNativeCore", package: sdkIdentity),
      ],
      resources: [
        .process("PrivacyInfo.xcprivacy")
      ]
    )
  ]
)
