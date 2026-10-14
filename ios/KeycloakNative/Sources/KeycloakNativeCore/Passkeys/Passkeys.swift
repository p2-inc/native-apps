import Foundation

/// Passkey operations (spec/05 §2.2): platform assertion/registration for challenge params, and the
/// §6 authenticated "add a passkey after login" sequence.
public struct Passkeys: Sendable {
  private let platform: any PasskeyPlatform
  private let issuerHost: String
  private let allowRpIdMismatch: Bool
  private let registration: PasskeyRegistrationClient
  private let logger: any NativeAuthLogger

  init(platform: any PasskeyPlatform, issuerHost: String, allowRpIdMismatch: Bool, registration: PasskeyRegistrationClient, logger: any NativeAuthLogger) {
    self.platform = platform
    self.issuerHost = issuerHost
    self.allowRpIdMismatch = allowRpIdMismatch
    self.registration = registration
    self.logger = logger
  }

  /// Runs the platform assertion for a `passkey` challenge (allow-list or discoverable).
  public func assert(_ params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Bool = false) async throws -> PasskeyAssertion {
    try checkRpId(params.rpId)
    return try await platform.assert(params, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
  }

  /// Runs the platform registration for a `passkey_registration` challenge or §6 options.
  public func register(_ params: PasskeyRegistrationParams) async throws -> PasskeyAttestation {
    try checkRpId(params.rp.id)
    return try await platform.register(params)
  }

  /// spec/03 §6: options → platform registration → finish. Errors: `invalid_token` (401),
  /// `insufficient_authorization` (403: the login is older than the realm's registration max age, a
  /// new login is required until step-up exists), `invalid_request` (400), `passkey_cancelled`.
  public func registerNewPasskey(label: String?, credentials: Credentials) async throws -> RegisteredPasskey {
    let options = try await registration.options(credentials: credentials)
    let attestation = try await register(options.params)
    return try await registration.finish(credentials: credentials, registrationId: options.registrationId, attestation: attestation, label: label)
  }

  /// The RP ID must be the issuer host or a registrable suffix of it (`example.com` for
  /// `idp.example.com`), otherwise the OS would refuse the Associated Domain anyway. Overridable for
  /// development only (spec/12).
  func checkRpId(_ rpId: String) throws {
    let host = issuerHost.lowercased()
    let rp = rpId.lowercased()
    guard !host.isEmpty, host != rp, !host.hasSuffix("." + rp) else { return }
    if allowRpIdMismatch {
      logger.log(.warning, "Passkey rp_id '\(rpId)' does not match issuer host '\(issuerHost)' (allowed by allowRpIdMismatch)")
      return
    }
    throw NativeAuthError(
      code: NativeAuthError.Code.rpIdMismatch,
      description: "Passkey rp_id '\(rpId)' is not the issuer host '\(issuerHost)' or a parent domain of it; set allowRpIdMismatch for development setups")
  }
}

/// `POST /native-auth/passkey/register/options` and `/finish` with the user's access token.
struct PasskeyRegistrationClient: Sendable {
  struct Options: Sendable {
    let registrationId: String
    let params: PasskeyRegistrationParams
    let raw: JSONValue
  }

  let issuer: URL
  let metadata: MetadataClient
  let transport: any Transport
  let dpop: DPoPSigner?

  func options(credentials: Credentials) async throws -> Options {
    let url = try await metadata.metadata().passkey?.registerOptionsEndpoint ?? issuer.appending(path: "native-auth/passkey/register/options")
    let response = try await send(method: "POST", url: url, body: nil, contentType: nil, credentials: credentials)
    guard response.statusCode == 200, let json = response.json else {
      throw PasskeyRegistrationClient.error(response)
    }
    guard let registrationId = json["registration_id"]?.stringValue, let params = PasskeyRegistrationParams(json: json) else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: 200, description: "Registration options are incomplete", details: json)
    }
    return Options(registrationId: registrationId, params: params, raw: json)
  }

  func finish(credentials: Credentials, registrationId: String, attestation: PasskeyAttestation, label: String?) async throws -> RegisteredPasskey {
    let url = try await metadata.metadata().passkey?.registerFinishEndpoint ?? issuer.appending(path: "native-auth/passkey/register/finish")
    var body = attestation.jsonFields
    body["registration_id"] = .string(registrationId)
    if let label, !label.isEmpty { body["label"] = .string(label) }
    let data = Data(JSONValue.object(body).serialized().utf8)
    let response = try await send(method: "POST", url: url, body: data, contentType: "application/json", credentials: credentials)
    guard response.statusCode == 201 || response.statusCode == 200, let json = response.json else {
      throw PasskeyRegistrationClient.error(response)
    }
    guard let credentialId = json["credential_id"]?.stringValue else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: response.statusCode, description: "finish response without credential_id", details: json)
    }
    return RegisteredPasskey(credentialId: credentialId, label: json["label"]?.stringValue)
  }

  private func send(method: String, url: URL, body: Data?, contentType: String?, credentials: Credentials) async throws -> HTTPResponse {
    var response = try await transport.send(try await request(method: method, url: url, body: body, contentType: contentType, credentials: credentials))
    if let dpop, credentials.isDPoPBound, let nonce = DPoPSigner.nonceChallenge(in: response) {
      await dpop.setNonce(nonce, for: url)
      response = try await transport.send(try await request(method: method, url: url, body: body, contentType: contentType, credentials: credentials))
    }
    return response
  }

  private func request(method: String, url: URL, body: Data?, contentType: String?, credentials: Credentials) async throws -> HTTPRequest {
    var headers = ["Accept": "application/json"]
    if let contentType { headers["Content-Type"] = contentType }
    headers["Authorization"] = "\(credentials.authorizationScheme) \(credentials.accessToken)"
    if credentials.isDPoPBound, let dpop, let proof = try await dpop.proof(method: method, url: url, accessToken: credentials.accessToken) {
      headers["DPoP"] = proof
    }
    return HTTPRequest(method: method, url: url, headers: headers, body: body)
  }

  private static func error(_ response: HTTPResponse) -> NativeAuthError {
    switch response.statusCode {
    case 401: return NativeAuthError.from(response: response, fallbackCode: NativeAuthError.Code.invalidToken)
    case 403: return NativeAuthError.from(response: response, fallbackCode: NativeAuthError.Code.insufficientAuthorization)
    default: return NativeAuthError.from(response: response)
    }
  }
}
