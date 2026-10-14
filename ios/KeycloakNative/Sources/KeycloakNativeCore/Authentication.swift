import Foundation

/// Entry point for logins, step-ups and the browser fallback (spec/05 §2.2).
public struct Authentication: Sendable {
  private let core: KeycloakNative

  init(core: KeycloakNative) {
    self.core = core
  }

  /// Creates a flow; nothing is sent until `start()`.
  public func startLogin(_ parameters: LoginParameters = LoginParameters()) -> NativeLoginFlow {
    flow(parameters, stepUpSession: nil)
  }

  /// Step-up / re-authentication inside the existing user session (spec/03 §5): a §2.1 request with
  /// a new PKCE pair plus the stored post-login `auth_session` (`Credentials.authSession`, kept by the
  /// `CredentialsManager`). The server skips the username step and asks only for what the requested
  /// level still needs; `maxAge`/`prompt=login` force every factor again. `.authorized` then carries
  /// tokens for the same session with the new `acr`. Throws `credentials_not_found` when no
  /// post-login `auth_session` is stored; the server answers `invalid_session` when the user session
  /// has ended (start a fresh login then).
  public func stepUp(_ parameters: LoginParameters, authSession: String? = nil) async throws -> NativeLoginFlow {
    let session: String
    if let authSession {
      session = authSession
    } else if let stored = try await core.credentialsManager().authSession() {
      session = stored
    } else {
      throw NativeAuthError(code: NativeAuthError.Code.credentialsNotFound, description: "No post-login auth_session is stored; log in first")
    }
    return flow(parameters, stepUpSession: session)
  }

  /// Convenience: `stepUp` with `acr_values` and/or `max_age` (the §6 `insufficient_authorization`
  /// answer names the `max_age` to use).
  public func stepUp(acrValues: String? = nil, maxAge: Int? = nil, scope: String? = "openid", deviceName: String? = nil) async throws -> NativeLoginFlow {
    try await stepUp(LoginParameters(scope: scope, acrValues: acrValues, maxAge: maxAge, deviceName: deviceName))
  }

  /// Continues after an endpoint refused a token with `insufficient_authorization` and handed back an
  /// `auth_session` (`reauthentication_required` from `CredentialsManager.credentials()`, or the §6
  /// registration endpoints): a step-up flow with that session, `max_age` taken from the error when
  /// the server named one.
  public func continueAfterTokenChallenge(_ error: NativeAuthError, parameters: LoginParameters = LoginParameters()) throws -> NativeLoginFlow {
    guard let session = error.authSession else {
      throw NativeAuthError(code: NativeAuthError.Code.reauthenticationRequired, description: "The server returned no auth_session; start a new login", underlying: error)
    }
    var parameters = parameters
    if parameters.maxAge == nil, let maxAge = error.maxAge { parameters.maxAge = maxAge }
    return flow(parameters, stepUpSession: session)
  }

  public func metadata(forceRefresh: Bool = false) async throws -> NativeAuthMetadata {
    try await core.metadataClient.metadata(forceRefresh: forceRefresh)
  }

  private func flow(_ parameters: LoginParameters, stepUpSession: String?) -> NativeLoginFlow {
    NativeLoginFlow(
      clientId: core.clientId,
      parameters: parameters,
      pkce: PKCE.generate(),
      stepUpSession: stepUpSession,
      metadata: core.metadataClient,
      transport: core.transport,
      dpop: core.dpopSigner,
      tokens: core.tokens(),
      logger: core.options.logger)
  }
}
