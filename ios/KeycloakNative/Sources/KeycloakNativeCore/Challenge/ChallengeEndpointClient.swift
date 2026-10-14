import Foundation

/// A parsed `403 insufficient_authorization` body (spec/03 §3.2).
struct ChallengeSet: Sendable {
  let authSession: String
  let expiresIn: Int?
  let protocolVersion: String?
  let challenges: [Challenge]
  let context: FlowContext
  let raw: JSONValue
}

enum ChallengeOutcome: Sendable {
  case authorizationCode(String, authSession: String?)
  case challenges(ChallengeSet)
  case redirectToWeb(RedirectToWebRequest)
}

/// Form-encoded transport to `POST /native-auth/challenge` (spec/05 §3.1): attaches a DPoP proof when
/// configured, retries once on `use_dpop_nonce`, parses 200 / 403 / 400 and maps everything else to
/// `NativeAuthError`.
struct ChallengeEndpointClient: Sendable {
  let endpoint: URL
  let transport: any Transport
  let dpop: DPoPSigner?
  let logger: any NativeAuthLogger

  func post(_ fields: [(name: String, value: String)]) async throws -> ChallengeOutcome {
    let response = try await send(fields)
    return try ChallengeEndpointClient.parse(response)
  }

  /// Sends and returns the raw response (used by `cancel`, whose expected answer is an error).
  func send(_ fields: [(name: String, value: String)]) async throws -> HTTPResponse {
    var response = try await transport.send(request(fields))
    if let dpop, let nonce = DPoPSigner.nonceChallenge(in: response) {
      await dpop.setNonce(nonce, for: endpoint)
      response = try await transport.send(request(fields))
    }
    return response
  }

  private func request(_ fields: [(name: String, value: String)]) async throws -> HTTPRequest {
    var headers = ["Accept": "application/json", "Content-Type": FormEncoding.contentType]
    if let dpop, let proof = try await dpop.proof(method: "POST", url: endpoint, accessToken: nil) {
      headers["DPoP"] = proof
    }
    return HTTPRequest(method: "POST", url: endpoint, headers: headers, body: FormEncoding.encode(fields))
  }

  static func parse(_ response: HTTPResponse) throws -> ChallengeOutcome {
    guard let json = response.json else {
      throw NativeAuthError(
        code: NativeAuthError.Code.invalidResponse,
        statusCode: response.statusCode,
        description: "Challenge endpoint answered HTTP \(response.statusCode) without a JSON body")
    }
    if response.statusCode == 200 {
      guard let code = json["authorization_code"]?.stringValue else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: 200, description: "200 without authorization_code", details: json)
      }
      return .authorizationCode(code, authSession: json["auth_session"]?.stringValue)
    }
    let error = json["error"]?.stringValue
    // 403 per draft-04; 400 tolerated for older servers (spec/03 §3.2).
    if error == NativeAuthError.Code.insufficientAuthorization, response.statusCode == 403 || response.statusCode == 400,
      let challengesJSON = json["challenges"]?.arrayValue
    {
      guard let authSession = json["auth_session"]?.stringValue else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: response.statusCode, description: "Challenge response without auth_session", details: json)
      }
      let challenges = challengesJSON.compactMap(Challenge.init(json:))
      return .challenges(
        ChallengeSet(
          authSession: authSession,
          expiresIn: json["expires_in"]?.intValue,
          protocolVersion: json["protocol_version"]?.stringValue,
          challenges: challenges,
          context: FlowContext(json: json["context"]),
          raw: json))
    }
    if error == NativeAuthError.Code.redirectToWeb, let request = RedirectToWebRequest(json: json) {
      return .redirectToWeb(request)
    }
    throw NativeAuthError.from(response: response)
  }
}
