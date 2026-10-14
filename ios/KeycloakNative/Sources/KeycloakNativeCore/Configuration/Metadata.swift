import Foundation

/// `GET /realms/{realm}/native-auth/metadata` (spec/03 §1.1). Unknown fields are ignored.
public struct NativeAuthMetadata: Sendable, Equatable, Codable {
  public struct CodeExchange: Sendable, Equatable, Codable {
    public var redirectUriRequired: Bool
    public var redirectUri: String?
    public init(redirectUriRequired: Bool = false, redirectUri: String? = nil) {
      self.redirectUriRequired = redirectUriRequired
      self.redirectUri = redirectUri
    }
  }

  public struct Passkey: Sendable, Equatable, Codable {
    public var rpId: String
    public var registerOptionsEndpoint: URL?
    public var registerFinishEndpoint: URL?
    public init(rpId: String, registerOptionsEndpoint: URL? = nil, registerFinishEndpoint: URL? = nil) {
      self.rpId = rpId
      self.registerOptionsEndpoint = registerOptionsEndpoint
      self.registerFinishEndpoint = registerFinishEndpoint
    }
  }

  public struct ClientAttestation: Sendable, Equatable, Codable {
    public var required: Bool
    public var methods: [String]
    public init(required: Bool = false, methods: [String] = []) {
      self.required = required
      self.methods = methods
    }
  }

  public var protocolVersion: String
  public var fipaDraft: String?
  public var authorizationChallengeEndpoint: URL
  public var tokenEndpoint: URL
  /// The realm's OIDC authorization endpoint (spec/03 §1.1), used by `WebFallback`.
  public var authorizationEndpoint: URL?
  public var codeExchange: CodeExchange
  public var passkey: Passkey?
  public var challengeTypesSupported: [String]
  /// Proof algorithms the challenge endpoint verifies and binds to (spec/03 §8); empty when it does
  /// not verify proofs. The SDK sends ES256 proofs either way and reads `token_type` for the result.
  public var dpopSigningAlgValuesSupported: [String]
  public var clientAttestation: ClientAttestation?
  /// The raw document, for fields this version of the SDK does not model (e.g. `push`).
  public var raw: JSONValue?

  enum CodingKeys: String, CodingKey {
    case protocolVersion = "protocol_version"
    case fipaDraft = "fipa_draft"
    case authorizationChallengeEndpoint = "authorization_challenge_endpoint"
    case tokenEndpoint = "token_endpoint"
    case authorizationEndpoint = "authorization_endpoint"
    case codeExchange = "code_exchange"
    case passkey
    case challengeTypesSupported = "challenge_types_supported"
    case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
    case clientAttestation = "client_attestation"
  }

  public init(from decoder: any Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    protocolVersion = try c.decode(String.self, forKey: .protocolVersion)
    fipaDraft = try c.decodeIfPresent(String.self, forKey: .fipaDraft)
    authorizationChallengeEndpoint = try c.decode(URL.self, forKey: .authorizationChallengeEndpoint)
    tokenEndpoint = try c.decode(URL.self, forKey: .tokenEndpoint)
    authorizationEndpoint = try c.decodeIfPresent(URL.self, forKey: .authorizationEndpoint)
    codeExchange = try c.decodeIfPresent(CodeExchange.self, forKey: .codeExchange) ?? CodeExchange()
    passkey = try c.decodeIfPresent(Passkey.self, forKey: .passkey)
    challengeTypesSupported = try c.decodeIfPresent([String].self, forKey: .challengeTypesSupported) ?? []
    dpopSigningAlgValuesSupported = try c.decodeIfPresent([String].self, forKey: .dpopSigningAlgValuesSupported) ?? []
    clientAttestation = try c.decodeIfPresent(ClientAttestation.self, forKey: .clientAttestation)
    raw = nil
  }

  public func encode(to encoder: any Encoder) throws {
    var c = encoder.container(keyedBy: CodingKeys.self)
    try c.encode(protocolVersion, forKey: .protocolVersion)
    try c.encodeIfPresent(fipaDraft, forKey: .fipaDraft)
    try c.encode(authorizationChallengeEndpoint, forKey: .authorizationChallengeEndpoint)
    try c.encode(tokenEndpoint, forKey: .tokenEndpoint)
    try c.encodeIfPresent(authorizationEndpoint, forKey: .authorizationEndpoint)
    try c.encode(codeExchange, forKey: .codeExchange)
    try c.encodeIfPresent(passkey, forKey: .passkey)
    try c.encode(challengeTypesSupported, forKey: .challengeTypesSupported)
    try c.encode(dpopSigningAlgValuesSupported, forKey: .dpopSigningAlgValuesSupported)
    try c.encodeIfPresent(clientAttestation, forKey: .clientAttestation)
  }

  /// Major version only (spec/03 §10).
  public var protocolMajorVersion: Int? {
    Int(protocolVersion.split(separator: ".").first ?? "")
  }

  public func supports(_ type: ChallengeType) -> Bool {
    challengeTypesSupported.contains(type.wire)
  }

  static func decode(_ data: Data) throws -> NativeAuthMetadata {
    var metadata = try JSONDecoder().decode(NativeAuthMetadata.self, from: data)
    metadata.raw = JSONValue(jsonData: data)
    return metadata
  }
}

extension NativeAuthMetadata.CodeExchange {
  enum CodingKeys: String, CodingKey {
    case redirectUriRequired = "redirect_uri_required"
    case redirectUri = "redirect_uri"
  }
}

extension NativeAuthMetadata.Passkey {
  enum CodingKeys: String, CodingKey {
    case rpId = "rp_id"
    case registerOptionsEndpoint = "register_options_endpoint"
    case registerFinishEndpoint = "register_finish_endpoint"
  }
}

/// Fetches and caches the metadata document per `KeycloakNative` instance.
actor MetadataClient {
  private let url: URL
  private let transport: any Transport
  private let ttl: TimeInterval
  private var cached: (metadata: NativeAuthMetadata, fetchedAt: Date)?
  private var inFlight: Task<NativeAuthMetadata, any Error>?

  init(issuer: URL, transport: any Transport, ttl: TimeInterval) {
    self.url = issuer.appending(path: "native-auth/metadata")
    self.transport = transport
    self.ttl = ttl
  }

  func metadata(forceRefresh: Bool = false) async throws -> NativeAuthMetadata {
    if !forceRefresh, let cached, Date().timeIntervalSince(cached.fetchedAt) < ttl {
      return cached.metadata
    }
    if let inFlight {
      return try await inFlight.value
    }
    let task = Task<NativeAuthMetadata, any Error> { [transport, url] in
      let response = try await transport.send(HTTPRequest(method: "GET", url: url, headers: ["Accept": "application/json"]))
      guard response.statusCode == 200 else {
        throw NativeAuthError(
          code: NativeAuthError.Code.metadataUnavailable,
          statusCode: response.statusCode,
          description: "GET \(url.absoluteString) answered HTTP \(response.statusCode)",
          details: response.json)
      }
      do {
        return try NativeAuthMetadata.decode(response.body)
      } catch {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, statusCode: 200, description: "Metadata document is malformed", underlying: error)
      }
    }
    inFlight = task
    defer { inFlight = nil }
    let metadata = try await task.value
    cached = (metadata, Date())
    return metadata
  }

  func invalidate() {
    cached = nil
  }
}
