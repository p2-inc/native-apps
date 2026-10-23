// swift-tools-version:6.0
import PackageDescription

// The example app's code lives in a library target so it type-checks with `swift build` on macOS too;
// the iOS app target (project.yml → KeycloakNativeDemo.xcodeproj via XcodeGen) wraps it with App/.
let package = Package(
  name: "KeycloakNativeDemo",
  platforms: [.iOS(.v17), .macOS(.v14)],
  products: [.library(name: "KeycloakNativeDemoApp", targets: ["KeycloakNativeDemoApp"])],
  dependencies: [.package(path: "../..")],  // the repository-root manifest (package "native-apps")
  targets: [
    .target(
      name: "KeycloakNativeDemoApp",
      dependencies: [
        .product(name: "KeycloakNativeCore", package: "native-apps"),
        .product(name: "KeycloakNativeUI", package: "native-apps"),
        .product(name: "KeycloakNativePush", package: "native-apps"),
      ])
  ],
  swiftLanguageModes: [.v6]
)
