import AuthenticationServices
import Foundation

/// The configured SDK instance (spec/05 §2): one per issuer + client.
public final class KeycloakNative: Sendable {
  public struct Options: Sendable {
    public var dpop: DPoPMode = .automatic
    /// Accept a passkey `rp_id` that is neither the issuer host nor a registrable suffix of it.
    /// Only for development against a tunnel/port-forward (spec/12).
    public var allowRpIdMismatch = false
    public var logger: any NativeAuthLogger = OSLogLogger()
    /// Overrides the `URLSession` transport (tests, custom pinning).
    public var transport: (any Transport)? = nil
    /// Receives redacted request/response entries (Diagnostics flow log).
    public var flowObserver: (any FlowObserver)? = nil
    /// Overrides the Keychain (tests, previews).
    public var secureStore: (any SecureStore)? = nil
    public var keychainService = "io.phasetwo.keycloak.native"
    public var keychainAccessGroup: String? = nil
    /// Overrides the platform passkey bridge (tests).
    public var passkeyPlatform: (any PasskeyPlatform)? = nil
    /// Window for the passkey sheet; defaults to the key window.
    public var presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil
    public var metadataCacheTTL: TimeInterval = 300

    public init() {}
  }

  public let issuer: URL
  public let clientId: String
  public let options: Options

  let transport: any Transport
  let store: any SecureStore
  let metadataClient: MetadataClient
  let dpopSigner: DPoPSigner?
  let passkeyPlatform: any PasskeyPlatform
  private let credentialsManagerInstance: CredentialsManager

  public static func configure(issuer: URL, clientId: String, options: Options = Options()) -> KeycloakNative {
    KeycloakNative(issuer: issuer, clientId: clientId, options: options)
  }

  init(issuer: URL, clientId: String, options: Options) {
    var normalised = issuer.absoluteString
    while normalised.hasSuffix("/") { normalised.removeLast() }
    self.issuer = URL(string: normalised) ?? issuer
    self.clientId = clientId
    self.options = options
    self.transport = ObservingTransport(base: options.transport ?? URLSessionTransport(), logger: options.logger, observer: options.flowObserver)
    self.store = options.secureStore ?? KeychainStore(service: options.keychainService, accessGroup: options.keychainAccessGroup)
    self.metadataClient = MetadataClient(issuer: self.issuer, transport: transport, ttl: options.metadataCacheTTL)
    let scope = "\(self.issuer.absoluteString)|\(clientId)"
    self.dpopSigner = options.dpop == .disabled
      ? nil
      : DPoPSigner(mode: options.dpop, store: store, storeKey: "\(scope)|dpop-key", logger: options.logger)
    self.passkeyPlatform = options.passkeyPlatform ?? ASAuthorizationPasskeyPlatform(anchor: options.presentationAnchor)
    let tokens = Tokens(clientId: clientId, issuer: self.issuer, metadata: metadataClient, transport: transport, dpop: dpopSigner, logger: options.logger)
    self.credentialsManagerInstance = CredentialsManager(store: store, key: "\(scope)|credentials", tokens: tokens, logger: options.logger)
  }

  public func authentication() -> Authentication { Authentication(core: self) }

  public func passkeys() -> Passkeys {
    Passkeys(
      platform: passkeyPlatform,
      issuerHost: issuer.host ?? "",
      allowRpIdMismatch: options.allowRpIdMismatch,
      registration: PasskeyRegistrationClient(issuer: issuer, metadata: metadataClient, transport: transport, dpop: dpopSigner),
      logger: options.logger)
  }

  public func tokens() -> Tokens {
    Tokens(clientId: clientId, issuer: issuer, metadata: metadataClient, transport: transport, dpop: dpopSigner, logger: options.logger)
  }

  /// The single credentials manager of this instance (an actor; refreshes are serialised).
  public func credentialsManager() -> CredentialsManager { credentialsManagerInstance }

  public func metadata(forceRefresh: Bool = false) async throws -> NativeAuthMetadata {
    try await metadataClient.metadata(forceRefresh: forceRefresh)
  }

  /// RFC 7638 thumbprint of the DPoP public key (`jkt`), `nil` when DPoP is disabled.
  public func dpopKeyThumbprint() async throws -> String? {
    try await dpopSigner?.publicJWK()?.thumbprint
  }
}
