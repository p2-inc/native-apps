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
    /// Overrides the system browser used by `WebFallback` (tests).
    public var webPresenter: (any WebAuthenticationPresenter)? = nil
    /// `ASWebAuthenticationSession.prefersEphemeralWebBrowserSession` for the fallback browser.
    public var ephemeralWebSession = false
    /// Window for the passkey sheet; defaults to the key window.
    public var presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil
    public var metadataCacheTTL: TimeInterval = 300

    public init() {}
  }

  public let issuer: URL
  public let clientId: String
  public let options: Options

  /// The (observing, redacting) transport every module of this instance sends through.
  public let transport: any Transport
  let store: any SecureStore
  let metadataClient: MetadataClient
  let dpopSigner: DPoPSigner?
  let passkeyPlatform: any PasskeyPlatform
  let webPresenter: any WebAuthenticationPresenter
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
    self.webPresenter = options.webPresenter ?? ASWebAuthenticationSessionPresenter(anchor: options.presentationAnchor, prefersEphemeralSession: options.ephemeralWebSession)
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

  /// Completes `FlowStep.redirectToWeb` through the system browser (spec/03 §3.4).
  public func webFallback() -> WebFallback {
    WebFallback(clientId: clientId, issuer: issuer, metadata: metadataClient, presenter: webPresenter, tokens: tokens(), logger: options.logger)
  }

  /// Headers for a request to a resource server with the stored tokens: `Authorization: Bearer …`,
  /// or `Authorization: DPoP …` plus a `DPoP` proof with `ath` when the tokens are bound (spec/03 §8).
  public func resourceRequestHeaders(for credentials: Credentials, method: String, url: URL) async throws -> [String: String] {
    var headers = ["Authorization": "\(credentials.authorizationScheme) \(credentials.accessToken)"]
    if credentials.isDPoPBound, let dpopSigner, let proof = try await dpopSigner.proof(method: method, url: url, accessToken: credentials.accessToken) {
      headers["DPoP"] = proof
    }
    return headers
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

  // MARK: - Surface for the KeycloakNativePush module (spec/14 D9: the DPoP key is the device key)

  /// The DPoP key (created on first use). Throws `dpop_key_error` when DPoP is disabled.
  public func dpopKey() async throws -> any DPoPKey {
    guard let dpopSigner else { throw NativeAuthError(code: NativeAuthError.Code.dpopKeyError, description: "DPoP is disabled; the push device API needs a DPoP-bound token (spec/03 §7.1)") }
    return try await dpopSigner.currentKey()
  }

  /// A proof for a request outside Core (the push device API), with extra claims; `nil` when
  /// DPoP is disabled. Server nonces remembered per origin are included; register a new one with
  /// `rememberDPoPNonce`.
  public func dpopProof(method: String, url: URL, accessToken: String?, extraClaims: [String: JSONValue] = [:]) async throws -> String? {
    try await dpopSigner?.proof(method: method, url: url, accessToken: accessToken, extraClaims: extraClaims)
  }

  public func rememberDPoPNonce(_ nonce: String, for url: URL) async {
    await dpopSigner?.setNonce(nonce, for: url)
  }

  /// Key rotation in two steps: a fresh key to register with the server (signing that request with
  /// the current key), then `commitDPoPKeyRotation` once the server accepted it.
  public func prepareDPoPKeyRotation() async throws -> any DPoPKey {
    guard let dpopSigner else { throw NativeAuthError(code: NativeAuthError.Code.dpopKeyError, description: "DPoP is disabled") }
    return try await dpopSigner.prepareRotation()
  }

  public func commitDPoPKeyRotation(_ key: any DPoPKey) async throws {
    guard let dpopSigner else { throw NativeAuthError(code: NativeAuthError.Code.dpopKeyError, description: "DPoP is disabled") }
    try await dpopSigner.commitRotation(key)
  }

  /// The secure store of this instance and a key under its issuer + client scope, for state other
  /// modules persist next to the credentials (the push enrolment).
  public var secureStore: any SecureStore { store }

  public func scopedStorageKey(_ suffix: String) -> String {
    "\(issuer.absoluteString)|\(clientId)|\(suffix)"
  }
}
