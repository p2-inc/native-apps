import CryptoKit
import Foundation

/// A signing key for DPoP proofs (RFC 9449). ES256 only for now (spec/03 §8 prefers it).
public protocol DPoPKey: Sendable {
  /// JWS `alg`.
  var algorithm: String { get }
  var publicJWK: ECPublicJWK { get }
  /// ECDSA over SHA-256, returned as the JWS raw `r || s` (64 bytes).
  func sign(_ message: Data) throws -> Data
}

/// CryptoKit P-256 key in process memory. Used on simulators, in tests and when the Secure Enclave is
/// unavailable; persisted (as its raw representation) by `DPoPSigner` through the `SecureStore`.
public struct SoftwareDPoPKey: DPoPKey, @unchecked Sendable {
  private let privateKey: P256.Signing.PrivateKey

  public init() {
    privateKey = P256.Signing.PrivateKey()
  }

  public init(rawRepresentation: Data) throws {
    privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
  }

  public var rawRepresentation: Data { privateKey.rawRepresentation }
  public var algorithm: String { "ES256" }
  public var publicJWK: ECPublicJWK { ECPublicJWK(publicKey: privateKey.publicKey) }

  public func sign(_ message: Data) throws -> Data {
    try privateKey.signature(for: message).rawRepresentation
  }
}

/// P-256 key whose private part never leaves the Secure Enclave. `dataRepresentation` is an opaque,
/// device-bound blob that only restores the key on the same device.
public struct SecureEnclaveDPoPKey: DPoPKey, @unchecked Sendable {
  private let privateKey: SecureEnclave.P256.Signing.PrivateKey

  public static var isAvailable: Bool { SecureEnclave.isAvailable }

  public init() throws {
    privateKey = try SecureEnclave.P256.Signing.PrivateKey()
  }

  public init(dataRepresentation: Data) throws {
    privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
  }

  public var dataRepresentation: Data { privateKey.dataRepresentation }
  public var algorithm: String { "ES256" }
  public var publicJWK: ECPublicJWK { ECPublicJWK(publicKey: privateKey.publicKey) }

  public func sign(_ message: Data) throws -> Data {
    try privateKey.signature(for: message).rawRepresentation
  }
}

/// Which key the SDK uses for DPoP proofs (spec/05 §3.1).
public enum DPoPMode: Sendable, Equatable {
  /// No `DPoP` headers at all.
  case disabled
  case software
  case secureEnclave
  /// Secure Enclave when available (device), software otherwise (simulator, CI).
  case automatic
}

/// Owns the DPoP key (created on first use, persisted through the `SecureStore`), builds proofs and
/// remembers server nonces per origin. Proofs are sent on challenge and token requests from day one
/// even though the server advertises `dpop_signing_alg_values_supported: []` and does not bind yet
/// (spec/10 Phase 1b); absence of binding is normal.
actor DPoPSigner {
  private struct Persisted: Codable {
    var kind: String  // "software" | "secure_enclave"
    var key: Data
  }

  private let mode: DPoPMode
  private let store: any SecureStore
  private let storeKey: String
  private let logger: any NativeAuthLogger
  private var key: (any DPoPKey)?
  private var nonces: [String: String] = [:]

  init(mode: DPoPMode, store: any SecureStore, storeKey: String, logger: any NativeAuthLogger) {
    self.mode = mode
    self.store = store
    self.storeKey = storeKey
    self.logger = logger
  }

  /// `nil` when DPoP is disabled.
  func proof(method: String, url: URL, accessToken: String?) throws -> String? {
    guard mode != .disabled else { return nil }
    let key = try loadOrCreateKey()
    let builder = DPoPProofBuilder(key: key)
    return try builder.proof(method: method, url: url, accessToken: accessToken, nonce: nonces[DPoPProofBuilder.origin(of: url)])
  }

  func publicJWK() throws -> ECPublicJWK? {
    guard mode != .disabled else { return nil }
    return try loadOrCreateKey().publicJWK
  }

  func setNonce(_ nonce: String, for url: URL) {
    nonces[DPoPProofBuilder.origin(of: url)] = nonce
  }

  /// RFC 9449 §8: `400 use_dpop_nonce` + `DPoP-Nonce` header (also `401` on resource servers).
  nonisolated static func nonceChallenge(in response: HTTPResponse) -> String? {
    guard response.statusCode == 400 || response.statusCode == 401,
      response.json?["error"]?.stringValue == "use_dpop_nonce",
      let nonce = response.header("DPoP-Nonce")
    else { return nil }
    return nonce
  }

  func reset() throws {
    key = nil
    try store.removeData(forKey: storeKey)
  }

  private func loadOrCreateKey() throws -> any DPoPKey {
    if let key { return key }
    if let data = try store.data(forKey: storeKey), let persisted = try? JSONDecoder().decode(Persisted.self, from: data) {
      do {
        let restored: any DPoPKey
        switch persisted.kind {
        case "secure_enclave": restored = try SecureEnclaveDPoPKey(dataRepresentation: persisted.key)
        default: restored = try SoftwareDPoPKey(rawRepresentation: persisted.key)
        }
        key = restored
        return restored
      } catch {
        logger.log(.warning, "Stored DPoP key could not be restored (\(persisted.kind)); creating a new one")
      }
    }
    let created: any DPoPKey
    let persisted: Persisted
    switch mode {
    case .disabled:
      throw NativeAuthError(code: NativeAuthError.Code.dpopKeyError, description: "DPoP is disabled")
    case .software:
      let k = SoftwareDPoPKey()
      created = k
      persisted = Persisted(kind: "software", key: k.rawRepresentation)
    case .secureEnclave:
      let k = try SecureEnclaveDPoPKey()
      created = k
      persisted = Persisted(kind: "secure_enclave", key: k.dataRepresentation)
    case .automatic:
      if SecureEnclaveDPoPKey.isAvailable, let k = try? SecureEnclaveDPoPKey() {
        created = k
        persisted = Persisted(kind: "secure_enclave", key: k.dataRepresentation)
      } else {
        let k = SoftwareDPoPKey()
        created = k
        persisted = Persisted(kind: "software", key: k.rawRepresentation)
      }
    }
    try store.set(try JSONEncoder().encode(persisted), forKey: storeKey)
    logger.log(.info, "Created DPoP key (\(persisted.kind)), jkt=\(created.publicJWK.thumbprint)")
    key = created
    return created
  }
}
