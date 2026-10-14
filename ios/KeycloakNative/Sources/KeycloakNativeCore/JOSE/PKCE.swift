import CryptoKit
import Foundation

/// PKCE S256 pair (RFC 7636). One per login flow.
public struct PKCE: Sendable, Equatable {
  public static let method = "S256"

  public let verifier: String
  public let challenge: String

  /// 32 random bytes, base64url → a 43-character verifier.
  public static func generate() -> PKCE {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes.withUnsafeMutableBytes { buffer in
      _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    return PKCE(verifier: Base64URL.encode(Data(bytes)))
  }

  /// Derives the S256 challenge for a given verifier (RFC 7636 §4.2).
  public init(verifier: String) {
    self.verifier = verifier
    self.challenge = Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8))))
  }
}
