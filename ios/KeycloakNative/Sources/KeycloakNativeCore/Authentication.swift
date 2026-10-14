import Foundation

/// Entry point for logins (spec/05 §2.2).
public struct Authentication: Sendable {
  private let core: KeycloakNative

  init(core: KeycloakNative) {
    self.core = core
  }

  /// Creates a flow; nothing is sent until `start()`.
  public func startLogin(_ parameters: LoginParameters = LoginParameters()) -> NativeLoginFlow {
    NativeLoginFlow(
      clientId: core.clientId,
      parameters: parameters,
      pkce: PKCE.generate(),
      metadata: core.metadataClient,
      transport: core.transport,
      dpop: core.dpopSigner,
      tokens: core.tokens(),
      logger: core.options.logger)
  }

  public func metadata(forceRefresh: Bool = false) async throws -> NativeAuthMetadata {
    try await core.metadataClient.metadata(forceRefresh: forceRefresh)
  }

  // EXTENSION POINT (Phase 2, spec/03 §5): `stepUp(acrValues:maxAge:)` presenting the stored
  // post-login auth_session, and `continueAfterTokenChallenge(_:)` for `insufficient_authorization`
  // from the token endpoint. The server answers `invalid_session` to a post-login auth_session today
  // (spec/11 D4), so neither is offered rather than shipped as a stub.
}
