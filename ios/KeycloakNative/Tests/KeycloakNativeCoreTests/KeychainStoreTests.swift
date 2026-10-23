import Foundation
import Security
import Testing
@testable import KeycloakNativeCore

/// `KeychainStore` access control and the separate credentials store (spec/05 §6). The Keychain
/// itself is not exercised (a test host has no entitlements); the attributes the store would write
/// are.
@Suite struct KeychainStoreTests {
  @Test func withoutAccessControlItemsCarryOnlyTheAccessibilityClass() throws {
    let store = KeychainStore(service: "s")
    let attributes = try store.protectionAttributes()
    #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    #expect(attributes[kSecAttrAccessControl as String] == nil)
  }

  @Test func withAccessControlItemsCarryASecAccessControlInstead() throws {
    let store = KeychainStore(service: "s", accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, accessControl: .biometryCurrentSet)
    let attributes = try store.protectionAttributes()
    #expect(attributes[kSecAttrAccessControl as String] != nil)
    #expect(attributes[kSecAttrAccessible as String] == nil, "kSecAttrAccessible and kSecAttrAccessControl are mutually exclusive")
    #if os(macOS)
      #expect(store.query("k")[kSecUseDataProtectionKeychain as String] as? Bool == true)
    #endif
  }

  @Test func authenticationFailuresHaveTheirOwnCode() {
    for status in [errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed] {
      #expect(KeychainStore.error(status, "read").code == NativeAuthError.Code.keychainAuthenticationFailed)
    }
    #expect(KeychainStore.error(errSecMissingEntitlement, "read").code == NativeAuthError.Code.keychainError)
  }

  @Test func credentialsGoToTheCredentialsStoreAndEverythingElseStaysInTheSecureStore() async throws {
    let main = InMemorySecureStore()
    let credentialsOnly = InMemorySecureStore()
    var options = KeycloakNative.Options()
    options.secureStore = main
    options.credentialsStore = credentialsOnly
    options.dpop = .software
    let kc = KeycloakNative.configure(issuer: URL(string: "https://idp.example.com/realms/demo")!, clientId: "app", options: options)
    let credentials = Credentials(accessToken: "a", refreshToken: "r", idToken: nil, scope: nil, expiresAt: Date().addingTimeInterval(300), refreshExpiresAt: nil, authSession: nil)
    try await kc.credentialsManager().store(credentials)
    #expect(credentialsOnly.keys.contains { $0.hasSuffix("|credentials") })
    #expect(!main.keys.contains { $0.hasSuffix("|credentials") })
    #expect(try await kc.credentialsManager().stored()?.refreshToken == "r")
  }
}
