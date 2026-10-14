import CryptoKit
import Foundation

/// A P-256 public key as a JWK (RFC 7518 §6.2) with its RFC 7638 thumbprint.
public struct ECPublicJWK: Sendable, Equatable, Codable {
  public let kty: String
  public let crv: String
  public let x: String
  public let y: String

  public init(x: String, y: String) {
    self.kty = "EC"
    self.crv = "P-256"
    self.x = x
    self.y = y
  }

  public init(publicKey: P256.Signing.PublicKey) {
    let raw = publicKey.rawRepresentation  // x || y, 32 bytes each
    self.init(x: Base64URL.encode(raw.prefix(32)), y: Base64URL.encode(raw.suffix(32)))
  }

  /// RFC 7638: SHA-256 over the canonical JSON `{"crv","kty","x","y"}` (lexicographic keys, no
  /// whitespace), base64url.
  public var thumbprint: String {
    let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"\(kty)\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
    return Base64URL.encode(Data(SHA256.hash(data: Data(canonical.utf8))))
  }

  public var jsonValue: JSONValue {
    .object(["kty": .string(kty), "crv": .string(crv), "x": .string(x), "y": .string(y)])
  }
}

/// Unverified JWT payload access for display and expiry bookkeeping. The SDK never relies on these
/// claims for a security decision; tokens are validated by the server that issued them.
public enum JWT {
  public static func decodePayload(_ jwt: String) -> JSONValue? {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, let data = Base64URL.decode(String(parts[1])) else { return nil }
    return JSONValue(jsonData: data)
  }

  public static func decodeHeader(_ jwt: String) -> JSONValue? {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, let data = Base64URL.decode(String(parts[0])) else { return nil }
    return JSONValue(jsonData: data)
  }
}
