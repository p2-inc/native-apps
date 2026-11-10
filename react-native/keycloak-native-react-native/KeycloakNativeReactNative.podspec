require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

# The iOS half of the React Native module (spec/19 §8). It wraps the Swift package's KeycloakNativeCore and
# KeycloakNativePush products, which it consumes through React Native's spm_dependency rather than as a pod:
# inside this repository the package is the local one at the repository root (Package.swift), so the
# module and the SDK change together; from npm it is this repository at the matching tag.
repo_root = File.expand_path("../..", __dir__)
local_package = File.exist?(File.join(repo_root, "Package.swift")) && ENV["KEYCLOAK_NATIVE_SPM_REMOTE"] != "1"
sdk_version = ENV["KEYCLOAK_NATIVE_SDK_VERSION"] || package["keycloakNativeSdkVersion"]

Pod::Spec.new do |s|
  s.name         = "KeycloakNativeReactNative"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  # The SDK supports iOS 17 and later.
  s.platforms    = { :ios => "17.0" }
  s.source       = { :git => "https://github.com/p2-inc/native-apps.git", :tag => s.version.to_s }

  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.private_header_files = "ios/**/*.h"
  s.swift_version = "5.9"

  spm_dependency(s,
    url: local_package ? repo_root : "https://github.com/p2-inc/native-apps.git",
    requirement: { kind: "exactVersion", version: sdk_version },
    products: ["KeycloakNativeCore", "KeycloakNativePush"]
  )

  install_modules_dependencies(s)
end
