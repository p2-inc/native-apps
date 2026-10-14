import Foundation
import Security

/// Byte storage for credentials and the DPoP key reference. Production: `KeychainStore`.
public protocol SecureStore: Sendable {
  func data(forKey key: String) throws -> Data?
  func set(_ data: Data, forKey key: String) throws
  func removeData(forKey key: String) throws
}

/// Generic-password Keychain items keyed by `service` + account (spec/05 §6). Default accessibility
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: never synced, never migrated to another device.
public struct KeychainStore: SecureStore {
  public let service: String
  public let accessGroup: String?
  private let accessible: String

  public init(service: String, accessGroup: String? = nil, accessible: CFString = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) {
    self.service = service
    self.accessGroup = accessGroup
    self.accessible = accessible as String
  }

  private func query(_ key: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
    if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
    return query
  }

  public func data(forKey key: String) throws -> Data? {
    var query = query(key)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess: return result as? Data
    case errSecItemNotFound: return nil
    default: throw KeychainStore.error(status, "read")
    }
  }

  public func set(_ data: Data, forKey key: String) throws {
    let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: accessible]
    let update = SecItemUpdate(query(key) as CFDictionary, attributes as CFDictionary)
    if update == errSecSuccess { return }
    guard update == errSecItemNotFound else { throw KeychainStore.error(update, "update") }
    var add = query(key)
    add.merge(attributes) { _, new in new }
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainStore.error(status, "add") }
  }

  public func removeData(forKey key: String) throws {
    let status = SecItemDelete(query(key) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainStore.error(status, "delete") }
  }

  private static func error(_ status: OSStatus, _ operation: String) -> NativeAuthError {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
    return NativeAuthError(code: NativeAuthError.Code.keychainError, description: "Keychain \(operation) failed: \(message) (\(status))")
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
