import CryptoKit
import Foundation

/// Builds RFC 9449 proof JWTs: header `{typ: dpop+jwt, alg, jwk}`, payload `{jti, htm, htu, iat,
/// ath?, nonce?}` (spec/03 §8).
public struct DPoPProofBuilder: Sendable {
  public let key: any DPoPKey

  public init(key: any DPoPKey) {
    self.key = key
  }

  public func proof(
    method: String,
    url: URL,
    accessToken: String? = nil,
    nonce: String? = nil,
    issuedAt: Date = Date(),
    jti: String = UUID().uuidString.lowercased()
  ) throws -> String {
    let header: JSONValue = .object([
      "typ": "dpop+jwt",
      "alg": .string(key.algorithm),
      "jwk": key.publicJWK.jsonValue,
    ])
    var payload: [String: JSONValue] = [
      "jti": .string(jti),
      "htm": .string(method.uppercased()),
      "htu": .string(DPoPProofBuilder.htu(url)),
      "iat": .number(Double(Int(issuedAt.timeIntervalSince1970))),
    ]
    if let accessToken {
      payload["ath"] = .string(Base64URL.encode(Data(SHA256.hash(data: Data(accessToken.utf8)))))
    }
    if let nonce {
      payload["nonce"] = .string(nonce)
    }
    let signingInput = Base64URL.encode(header.serialized()) + "." + Base64URL.encode(JSONValue.object(payload).serialized())
    let signature = try key.sign(Data(signingInput.utf8))
    return signingInput + "." + Base64URL.encode(signature)
  }

  /// `htu`: scheme, host, port and path only — no query or fragment (RFC 9449 §4.2).
  public static func htu(_ url: URL) -> String {
    var components = URLComponents()
    components.scheme = url.scheme
    components.host = url.host
    components.port = url.port
    components.path = url.path
    return components.string ?? url.absoluteString
  }

  static func origin(of url: URL) -> String {
    "\(url.scheme ?? "")://\(url.host ?? "")\(url.port.map { ":\($0)" } ?? "")"
  }
}
