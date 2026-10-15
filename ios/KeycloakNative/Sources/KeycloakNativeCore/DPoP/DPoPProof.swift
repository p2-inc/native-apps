import CryptoKit
import Foundation

/// Builds RFC 9449 proof JWTs: header `{typ: dpop+jwt, alg, jwk}`, payload `{jti, htm, htu, iat,
/// ath?, nonce?}` (spec/03 §8) plus any extra claims a profile wants (`sub`, `deviceId` for the
/// push device API, spec/03 §7.1).
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
    jti: String = UUID().uuidString.lowercased(),
    extraClaims: [String: JSONValue] = [:]
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
    for (claim, value) in extraClaims where payload[claim] == nil {
      payload[claim] = value
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


/// Signs an arbitrary JWS with a `DPoPKey` (`typ: JWT`): the device-signed enrolment and login
/// JWTs of the push device API (spec/03 §7) use the same key as the proofs (spec/14 D9).
public enum DeviceJWT {
  public static func sign(_ claims: [String: JSONValue], with key: any DPoPKey) throws -> String {
    let header: JSONValue = .object(["typ": "JWT", "alg": .string(key.algorithm)])
    let signingInput = Base64URL.encode(header.serialized()) + "." + Base64URL.encode(JSONValue.object(claims).serialized())
    let signature = try key.sign(Data(signingInput.utf8))
    return signingInput + "." + Base64URL.encode(signature)
  }
}