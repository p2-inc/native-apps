import Foundation
import LocalAuthentication
import Security

/// Byte storage for credentials and the DPoP key reference. Production: `KeychainStore`.
public protocol SecureStore: Sendable {
  func data(forKey key: String) throws -> Data?
  func set(_ data: Data, forKey key: String) throws
  func removeData(forKey key: String) throws
}

/// Generic-password Keychain items keyed by `service` + account (spec/05 §6). Default accessibility
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: never synced, never migrated to another device.
///
/// With `accessControl` (e.g. `.biometryCurrentSet` and `accessible:
/// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) every item is written with a `SecAccessControl`
/// and every read needs user authentication. Use such a store for credentials only
/// (`KeycloakNative.Options.credentialsStore`), not for the DPoP key reference the SDK reads on every
/// signed request. To avoid one prompt per read, return the same `LAContext` from
/// `authenticationContext` after evaluating it once (`touchIDAuthenticationAllowableReuseDuration`
/// bounds the reuse); give it a `localizedReason` for the system prompt.
public struct KeychainStore: SecureStore {
  public let service: String
  public let accessGroup: String?
  public let accessControl: SecAccessControlCreateFlags?
  private let accessible: String
  private let authenticationContext: (@Sendable () -> LAContext?)?

  public init(
    service: String,
    accessGroup: String? = nil,
    accessible: CFString = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    accessControl: SecAccessControlCreateFlags? = nil,
    authenticationContext: (@Sendable () -> LAContext?)? = nil
  ) {
    self.service = service
    self.accessGroup = accessGroup
    self.accessible = accessible as String
    self.accessControl = accessControl
    self.authenticationContext = authenticationContext
  }

  func query(_ key: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
    if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
    #if os(macOS)
      // Access control needs the data-protection keychain on macOS (it is the only one on iOS).
      if accessControl != nil { query[kSecUseDataProtectionKeychain as String] = true }
    #endif
    return query
  }

  /// The protection attributes of a new item: `kSecAttrAccessControl` when access control is set
  /// (it carries the accessibility class), else `kSecAttrAccessible`.
  func protectionAttributes() throws -> [String: Any] {
    guard let flags = accessControl else { return [kSecAttrAccessible as String: accessible] }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(nil, accessible as CFString, flags, &error) else {
      let message = error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String } ?? "unknown error"
      throw NativeAuthError(code: NativeAuthError.Code.keychainError, description: "Keychain access control could not be created: \(message)")
    }
    return [kSecAttrAccessControl as String: control]
  }

  public func data(forKey key: String) throws -> Data? {
    var query = query(key)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    if let context = authenticationContext?() { query[kSecUseAuthenticationContext as String] = context }
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess: return result as? Data
    case errSecItemNotFound: return nil
    default: throw KeychainStore.error(status, "read")
    }
  }

  public func set(_ data: Data, forKey key: String) throws {
    if accessControl != nil {
      // Updating a protected item would itself need authentication; replace it instead.
      try removeData(forKey: key)
    } else {
      let update = SecItemUpdate(query(key) as CFDictionary, [kSecValueData as String: data, kSecAttrAccessible as String: accessible] as CFDictionary)
      if update == errSecSuccess { return }
      guard update == errSecItemNotFound else { throw KeychainStore.error(update, "update") }
    }
    var add = query(key)
    add[kSecValueData as String] = data
    add.merge(try protectionAttributes()) { _, new in new }
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainStore.error(status, "add") }
  }

  public func removeData(forKey key: String) throws {
    let status = SecItemDelete(query(key) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainStore.error(status, "delete") }
  }

  static func error(_ status: OSStatus, _ operation: String) -> NativeAuthError {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
    // The user cancelled or failed the authentication an access-controlled item asked for.
    let authentication = [errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed].contains(status)
    return NativeAuthError(
      code: authentication ? NativeAuthError.Code.keychainAuthenticationFailed : NativeAuthError.Code.keychainError,
      description: "Keychain \(operation) failed: \(message) (\(status))")
  }
}

/// Process-local store for tests, previews and SwiftUI canvases.
public final class InMemorySecureStore: SecureStore, @unchecked Sendable {
  private let lock = NSLock()
  private var items: [String: Data] = [:]

  public init() {}

  public func data(forKey key: String) throws -> Data? {
    lock.withLock { items[key] }
  }

  public func set(_ data: Data, forKey key: String) throws {
    lock.withLock { items[key] = data }
  }

  public func removeData(forKey key: String) throws {
    _ = lock.withLock { items.removeValue(forKey: key) }
  }

  public var keys: [String] { lock.withLock { Array(items.keys) } }
}
