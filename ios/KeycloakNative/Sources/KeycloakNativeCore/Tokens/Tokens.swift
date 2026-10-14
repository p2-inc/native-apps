import Foundation

/// Tokens obtained from the realm's token endpoint plus the post-login `auth_session` (spec/05 §6).
public struct Credentials: Sendable, Equatable, Codable {
  public let accessToken: String
  /// `Bearer`, or `DPoP` when the server bound the token to the SDK's key.
  public let tokenType: String
  public let refreshToken: String?
  public let idToken: String?
  public let scope: String?
  public let expiresAt: Date
  public let refreshExpiresAt: Date?
  public let issuedAt: Date
  /// Post-login value from the success body (spec/03 §3.1). Stored for step-up (Phase 2); the SDK
  /// never presents it to the challenge endpoint today (spec/11 D4).
  public let authSession: String?

  public init(
    accessToken: String,
    tokenType: String = "Bearer",
    refreshToken: String?,
    idToken: String?,
    scope: String?,
    expiresAt: Date,
    refreshExpiresAt: Date?,
    issuedAt: Date = Date(),
    authSession: String?
  ) {
    self.accessToken = accessToken
    self.tokenType = tokenType
    self.refreshToken = refreshToken
    self.idToken = idToken
    self.scope = scope
    // Whole seconds: the Keychain encoding uses secondsSince1970, so a stored copy compares equal.
    self.expiresAt = Credentials.wholeSeconds(expiresAt)
    self.refreshExpiresAt = refreshExpiresAt.map(Credentials.wholeSeconds)
    self.issuedAt = Credentials.wholeSeconds(issuedAt)
    self.authSession = authSession
  }

  private static func wholeSeconds(_ date: Date) -> Date {
    date == .distantFuture ? date : Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.down))
  }

  public func isExpired(at date: Date = Date(), leeway: TimeInterval = 0) -> Bool {
    date.addingTimeInterval(leeway) >= expiresAt
  }

  /// Scheme for the `Authorization` header of resource requests.
  public var authorizationScheme: String {
    tokenType.caseInsensitiveCompare("DPoP") == .orderedSame ? "DPoP" : "Bearer"
  }

  public var isDPoPBound: Bool { authorizationScheme == "DPoP" }

  /// Unverified claims, for display only.
  public var idTokenClaims: JSONValue? { idToken.flatMap(JWT.decodePayload) }
  public var accessTokenClaims: JSONValue? { JWT.decodePayload(accessToken) }

  public func withAuthSession(_ authSession: String?) -> Credentials {
    Credentials(
      accessToken: accessToken, tokenType: tokenType, refreshToken: refreshToken, idToken: idToken, scope: scope,
      expiresAt: expiresAt, refreshExpiresAt: refreshExpiresAt, issuedAt: issuedAt, authSession: authSession)
  }
}

/// The standard Keycloak token endpoints (spec/05 §2.2): exchange, refresh, revoke, logout. DPoP
/// proofs are attached when the SDK has a key; whether the server binds is read from `token_type`.
public struct Tokens: Sendable {
  private let clientId: String
  private let issuer: URL
  private let metadata: MetadataClient
  private let transport: any Transport
  private let dpop: DPoPSigner?
  private let logger: any NativeAuthLogger

  init(clientId: String, issuer: URL, metadata: MetadataClient, transport: any Transport, dpop: DPoPSigner?, logger: any NativeAuthLogger) {
    self.clientId = clientId
    self.issuer = issuer
    self.metadata = metadata
    self.transport = transport
    self.dpop = dpop
    self.logger = logger
  }

  /// `grant_type=authorization_code` without `redirect_uri` unless metadata says otherwise (spec/03
  /// §3.1, spec/09 Q1).
  public func exchange(code: String, codeVerifier: String, authSession: String? = nil) async throws -> Credentials {
    let document = try await metadata.metadata()
    var fields: [(name: String, value: String)] = [
      ("grant_type", "authorization_code"),
      ("client_id", clientId),
      ("code", code),
      ("code_verifier", codeVerifier),
    ]
    if document.codeExchange.redirectUriRequired {
      guard let redirectUri = document.codeExchange.redirectUri else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Metadata requires redirect_uri but names none")
      }
      fields.append(("redirect_uri", redirectUri))
    }
    let response = try await post(document.tokenEndpoint, fields)
    return try Tokens.parseTokenResponse(response, authSession: authSession)
  }

  /// `grant_type=refresh_token`; keeps the stored `auth_session`.
  public func refresh(_ credentials: Credentials) async throws -> Credentials {
    guard let refreshToken = credentials.refreshToken else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidGrant, description: "No refresh token")
    }
    let document = try await metadata.metadata()
    let response = try await post(
      document.tokenEndpoint,
      [("grant_type", "refresh_token"), ("client_id", clientId), ("refresh_token", refreshToken)])
    return try Tokens.parseTokenResponse(response, authSession: credentials.authSession)
  }

  /// RFC 7009 revocation (`/protocol/openid-connect/revoke`).
  public func revoke(token: String, tokenTypeHint: String? = "refresh_token") async throws {
    var fields: [(name: String, value: String)] = [("client_id", clientId), ("token", token)]
    if let tokenTypeHint { fields.append(("token_type_hint", tokenTypeHint)) }
    let response = try await post(oidcEndpoint("revoke"), fields, withProof: false)
    guard (200..<300).contains(response.statusCode) else { throw NativeAuthError.from(response: response) }
  }

  /// RP-initiated logout with the refresh token (`/protocol/openid-connect/logout`).
  public func logout(refreshToken: String) async throws {
    let response = try await post(oidcEndpoint("logout"), [("client_id", clientId), ("refresh_token", refreshToken)], withProof: false)
    guard (200..<300).contains(response.statusCode) else { throw NativeAuthError.from(response: response) }
  }

  func oidcEndpoint(_ name: String) -> URL {
    issuer.appending(path: "protocol/openid-connect/\(name)")
  }

  // MARK: -

  private func post(_ url: URL, _ fields: [(name: String, value: String)], withProof: Bool = true) async throws -> HTTPResponse {
    var response = try await transport.send(try await request(url, fields, withProof: withProof))
    if withProof, let dpop, let nonce = DPoPSigner.nonceChallenge(in: response) {
      await dpop.setNonce(nonce, for: url)
      response = try await transport.send(try await request(url, fields, withProof: true))
    }
    return response
  }

  private func request(_ url: URL, _ fields: [(name: String, value: String)], withProof: Bool) async throws -> HTTPRequest {
    var headers = ["Accept": "application/json", "Content-Type": FormEncoding.contentType]
    if withProof, let dpop, let proof = try await dpop.proof(method: "POST", url: url, accessToken: nil) {
      headers["DPoP"] = proof
    }
    return HTTPRequest(method: "POST", url: url, headers: headers, body: FormEncoding.encode(fields))
  }

  static func parseTokenResponse(_ response: HTTPResponse, authSession: String?, now: Date = Date()) throws -> Credentials {
    guard response.statusCode == 200, let json = response.json else {
      throw NativeAuthError.from(response: response, fallbackCode: NativeAuthError.Code.invalidGrant)
    }
    guard let accessToken = json["access_token"]?.stringValue else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: 200, description: "Token response without access_token", details: json)
    }
    let expiresIn = json["expires_in"]?.doubleValue ?? 300
    let refreshExpiresIn = json["refresh_expires_in"]?.doubleValue
    return Credentials(
      accessToken: accessToken,
      tokenType: json["token_type"]?.stringValue ?? "Bearer",
      refreshToken: json["refresh_token"]?.stringValue,
      idToken: json["id_token"]?.stringValue,
      scope: json["scope"]?.stringValue,
      expiresAt: now.addingTimeInterval(expiresIn),
      refreshExpiresAt: refreshExpiresIn.map { $0 > 0 ? now.addingTimeInterval($0) : Date.distantFuture },
      issuedAt: now,
      authSession: authSession)
  }
}
