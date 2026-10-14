import Foundation
@testable import KeycloakNativeCore

/// A recorded integration-test transcript (`keycloak-native-auth/demo/transcripts/*.json`, written by
/// `TranscriptRecorder.java`). These are the contract fixtures: the SDK must produce the recorded
/// requests and understand the recorded responses.
struct Transcript: Decodable {
  struct Exchange: Decodable {
    let seq: Int
    let request: Request
    let response: Response
  }

  struct Request: Decodable {
    let method: String
    let path: String
    let headers: [String: String]?
    let form: [String: String]?
    let json: JSONValue?
    let body: String?
  }

  struct Response: Decodable {
    let status: Int
    let headers: [String: String]?
    let json: JSONValue?
    let body: String?

    var httpResponse: HTTPResponse {
      let data: Data
      if let json {
        data = Data(json.serialized().utf8)
      } else {
        data = Data((body ?? "").utf8)
      }
      return HTTPResponse(statusCode: status, headers: headers ?? [:], body: data)
    }
  }

  let test: String
  let baseUrl: String
  let keycloakImage: String?
  let exchanges: [Exchange]

  enum CodingKeys: String, CodingKey {
    case test
    case baseUrl = "base_url"
    case keycloakImage = "keycloak_image"
    case exchanges
  }

  /// `KEYCLOAK_NATIVE_TRANSCRIPTS` or `<repo>/keycloak-native-auth/demo/transcripts`.
  static var directory: URL {
    if let env = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_TRANSCRIPTS"] {
      return URL(filePath: env)
    }
    var url = URL(filePath: #filePath)
    for _ in 0..<6 { url.deleteLastPathComponent() }
    return url.appending(path: "keycloak-native-auth/demo/transcripts")
  }

  static func load(_ name: String) throws -> Transcript {
    let url = directory.appending(path: name + ".json")
    let data = try Data(contentsOf: url)
    return try JSONDecoder().decode(Transcript.self, from: data)
  }

  var issuer: URL { URL(string: baseUrl + "/realms/demo")! }

  func exchange(_ seq: Int) -> Exchange {
    exchanges.first { $0.seq == seq }!
  }

  func exchanges(_ range: ClosedRange<Int>) -> [Exchange] {
    exchanges.filter { range.contains($0.seq) }
  }

  /// The form of request `seq` (secrets are `***`).
  func form(_ seq: Int) -> [String: String] {
    exchange(seq).request.form ?? [:]
  }
}

extension PasskeyAssertion {
  /// Rebuilds the assertion the integration test sent (so the mock platform can replay it exactly).
  init(form: [String: String]) {
    self.init(
      credentialId: form["credential_id"]!,
      clientDataJSON: form["client_data_json"]!,
      authenticatorData: form["authenticator_data"]!,
      signature: form["signature"]!,
      userHandle: form["user_handle"])
  }
}

extension PasskeyAttestation {
  init(form: [String: String]) {
    self.init(
      credentialId: form["credential_id"]!,
      clientDataJSON: form["client_data_json"]!,
      attestationObject: form["attestation_object"]!,
      transports: (form["transports"] ?? "").split(separator: ",").map(String.init))
  }

  init(json: JSONValue) {
    let transports: [String]
    if let s = json["transports"]?.stringValue {
      transports = s.split(separator: ",").map(String.init)
    } else {
      transports = json["transports"]?.stringArray ?? []
    }
    self.init(
      credentialId: json["credential_id"]!.stringValue!,
      clientDataJSON: json["client_data_json"]!.stringValue!,
      attestationObject: json["attestation_object"]!.stringValue!,
      transports: transports)
  }
}
