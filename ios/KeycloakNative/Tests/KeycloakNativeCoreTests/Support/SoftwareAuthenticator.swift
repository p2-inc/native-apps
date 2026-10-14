import CryptoKit
import Foundation
@testable import KeycloakNativeCore

/// Swift port of the integration tests' `SoftwareAuthenticator.java` (spec/11 D6): one P-256 key per
/// instance, resident credential, `none` attestation, UP+UV, counter 0, DER signatures. Lets the live
/// tests complete WebAuthn ceremonies against a real Keycloak on macOS without a device.
final class SoftwareAuthenticator: PasskeyPlatform, @unchecked Sendable {
  private let key = P256.Signing.PrivateKey()
  private let credentialId: Data
  private let origin: String
  private var userHandle: String?
  private let wrongKey: Bool

  init(origin: String, wrongKey: Bool = false) {
    self.origin = origin
    self.wrongKey = wrongKey
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
    credentialId = Data(bytes)
  }

  var credentialIdBase64URL: String { Base64URL.encode(credentialId) }

  func register(_ params: PasskeyRegistrationParams) async throws -> PasskeyAttestation {
    userHandle = params.user.id
    let clientData = clientDataJSON(type: "webauthn.create", challenge: params.challenge)
    var authData = Data(SHA256.hash(data: Data(params.rp.id.utf8)))
    authData.append(0x45)  // UP | UV | AT
    authData.append(contentsOf: [0, 0, 0, 0])
    authData.append(Data(repeating: 0, count: 16))  // AAGUID
    authData.append(contentsOf: [UInt8(credentialId.count >> 8), UInt8(credentialId.count & 0xff)])
    authData.append(credentialId)
    authData.append(coseKey())
    let attestation = CBOR.map([
      (.string("fmt"), .string("none")),
      (.string("attStmt"), .map([])),
      (.string("authData"), .bytes(authData)),
    ])
    return PasskeyAttestation(credentialId: credentialId, clientDataJSON: clientData, attestationObject: CBOR.encode(attestation), transports: ["internal", "hybrid"])
  }

  func assert(_ params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Bool) async throws -> PasskeyAssertion {
    let clientData = clientDataJSON(type: "webauthn.get", challenge: params.challenge)
    var authData = Data(SHA256.hash(data: Data(params.rpId.utf8)))
    authData.append(0x05)  // UP | UV
    authData.append(contentsOf: [0, 0, 0, 0])
    let signingKey = wrongKey ? P256.Signing.PrivateKey() : key
    let signature = try signingKey.signature(for: authData + Data(SHA256.hash(data: clientData))).derRepresentation
    return PasskeyAssertion(credentialId: credentialId, clientDataJSON: clientData, authenticatorData: authData, signature: signature, userHandle: userHandle.flatMap(Base64URL.decode))
  }

  private func clientDataJSON(type: String, challenge: String) -> Data {
    Data("{\"type\":\"\(type)\",\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\",\"crossOrigin\":false}".utf8)
  }

  private func coseKey() -> Data {
    let raw = key.publicKey.rawRepresentation
    return CBOR.encode(.map([
      (.int(1), .int(2)), (.int(3), .int(-7)), (.int(-1), .int(1)),
      (.int(-2), .bytes(raw.prefix(32))), (.int(-3), .bytes(raw.suffix(32))),
    ]))
  }
}

/// Minimal RFC 8949 encoder (ints, byte strings, text strings, maps) — enough for `none` attestations.
indirect enum CBOR {
  case int(Int)
  case bytes(Data)
  case string(String)
  case map([(CBOR, CBOR)])

  static func encode(_ value: CBOR) -> Data {
    var out = Data()
    append(value, to: &out)
    return out
  }

  private static func append(_ value: CBOR, to out: inout Data) {
    switch value {
    case .int(let n):
      if n >= 0 { head(0, UInt64(n), &out) } else { head(1, UInt64(-1 - n), &out) }
    case .bytes(let data):
      head(2, UInt64(data.count), &out)
      out.append(data)
    case .string(let s):
      let data = Data(s.utf8)
      head(3, UInt64(data.count), &out)
      out.append(data)
    case .map(let pairs):
      head(5, UInt64(pairs.count), &out)
      for (k, v) in pairs {
        append(k, to: &out)
        append(v, to: &out)
      }
    }
  }

  private static func head(_ major: UInt8, _ value: UInt64, _ out: inout Data) {
    let m = major << 5
    switch value {
    case 0..<24: out.append(m | UInt8(value))
    case 24..<256: out.append(contentsOf: [m | 24, UInt8(value)])
    case 256..<65536: out.append(contentsOf: [m | 25, UInt8(value >> 8), UInt8(value & 0xff)])
    default:
      out.append(m | 26)
      out.append(contentsOf: (0..<4).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xff) })
    }
  }
}

/// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) over the raw UTF-8 secret, like `TimeBasedOTP` in the ITs.
enum TOTP {
  static func code(secret: String, at date: Date = Date()) -> String {
    var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
    let message = Data(bytes: &counter, count: 8)
    let mac = HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: Data(secret.utf8)))
    let bytes = Array(mac)
    let offset = Int(bytes[19] & 0x0f)
    let binary = (Int(bytes[offset] & 0x7f) << 24) | (Int(bytes[offset + 1]) << 16) | (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
    return String(format: "%06d", binary % 1_000_000)
  }
}
