import Foundation

/// Parameters of the initial request (spec/03 §2.1).
public struct LoginParameters: Sendable, Equatable {
  public var scope: String?
  public var acrValues: String?
  public var loginHint: String?
  public var prompt: String?
  public var maxAge: Int?
  public var nonce: String?
  public var uiLocales: String?
  /// Free-text device label shown in events / push prompts.
  public var deviceName: String?
  /// Stable app-generated UUID.
  public var deviceId: String?
  /// Extra fields of the initial request (spec/03 §2.3), e.g. a device or risk signal from another
  /// on-device SDK. Use the reserved `x_` prefix so a future profile parameter cannot collide; the
  /// Keycloak implementation keeps them for the whole login (`NativeRequestContext.extensionParameter`).
  /// Sent in key order.
  public var additionalParameters: [String: String]
  /// Extra fields appended to every continuation request of the flow; per-answer fields go through
  /// `respond(_:to:additionalFields:)`.
  public var continuationParameters: [String: String]

  public init(
    scope: String? = "openid",
    acrValues: String? = nil,
    loginHint: String? = nil,
    prompt: String? = nil,
    maxAge: Int? = nil,
    nonce: String? = nil,
    uiLocales: String? = nil,
    deviceName: String? = nil,
    deviceId: String? = nil,
    additionalParameters: [String: String] = [:],
    continuationParameters: [String: String] = [:]
  ) {
    self.scope = scope
    self.acrValues = acrValues
    self.loginHint = loginHint
    self.prompt = prompt
    self.maxAge = maxAge
    self.nonce = nonce
    self.uiLocales = uiLocales
    self.deviceName = deviceName
    self.deviceId = deviceId
    self.additionalParameters = additionalParameters
    self.continuationParameters = continuationParameters
  }
}

/// The challenge-driven state machine (spec/05 §2): `start() -> .challenges -> respond(...) ->
/// .authorized`.
public protocol LoginFlow: Sendable {
  func start() async throws -> FlowStep
  func respond(_ answer: ChallengeAnswer, to challenge: Challenge) async throws -> FlowStep
  /// Like `respond(_:to:)` with extra fields for this request only (spec/03 §2.3), appended after
  /// `LoginParameters.continuationParameters`.
  func respond(_ answer: ChallengeAnswer, to challenge: Challenge, additionalFields: [String: String]) async throws -> FlowStep
  /// `action=cancel`: the server invalidates the session. Safe to call at any point.
  func cancel() async
  /// The current `auth_session` (replaced on every response, spec/03 §5). Exposed for diagnostics.
  var authSession: String? { get async }
  var pendingChallenges: [Challenge] { get async }
}

public actor NativeLoginFlow: LoginFlow {
  public enum State: Sendable, Equatable {
    case idle
    case awaitingAnswer
    case finished
  }

  public nonisolated let clientId: String
  public nonisolated let parameters: LoginParameters
  public nonisolated let pkce: PKCE
  /// The post-login `auth_session` this flow steps up / re-authenticates (spec/03 §5), `nil` for a
  /// fresh login.
  public nonisolated let stepUpSession: String?

  private let metadata: MetadataClient
  private let transport: any Transport
  private let dpop: DPoPSigner?
  private let tokens: Tokens
  private let logger: any NativeAuthLogger

  private var client: ChallengeEndpointClient?
  private var state: State = .idle
  private var session: String?
  private var pending: [Challenge] = []
  private var lastExpiresIn: Int?

  init(
    clientId: String,
    parameters: LoginParameters,
    pkce: PKCE,
    stepUpSession: String? = nil,
    metadata: MetadataClient,
    transport: any Transport,
    dpop: DPoPSigner?,
    tokens: Tokens,
    logger: any NativeAuthLogger
  ) {
    self.clientId = clientId
    self.parameters = parameters
    self.pkce = pkce
    self.stepUpSession = stepUpSession
    self.metadata = metadata
    self.transport = transport
    self.dpop = dpop
    self.tokens = tokens
    self.logger = logger
  }

  public var currentState: State { state }
  public var authSession: String? { session }
  public nonisolated var isStepUp: Bool { stepUpSession != nil }
  public var pendingChallenges: [Challenge] { pending }
  /// Remaining lifetime of the authentication session as last reported.
  public var expiresIn: Int? { lastExpiresIn }

  public func start() async throws -> FlowStep {
    guard state == .idle else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "start() can only be called once per flow")
    }
    let document = try await metadata.metadata()
    if let major = document.protocolMajorVersion, major != 1 {
      logger.log(.warning, "Server protocol_version \(document.protocolVersion) is not 1.x; continuing best-effort")
    }
    let client = ChallengeEndpointClient(endpoint: document.authorizationChallengeEndpoint, transport: transport, dpop: dpop, logger: logger)
    self.client = client

    var fields: [(name: String, value: String)] = [
      ("client_id", clientId),
      ("response_type", "code"),
    ]
    if let scope = parameters.scope, !scope.isEmpty { fields.append(("scope", scope)) }
    fields.append(("code_challenge", pkce.challenge))
    fields.append(("code_challenge_method", PKCE.method))
    if let v = parameters.acrValues { fields.append(("acr_values", v)) }
    if let v = parameters.loginHint { fields.append(("login_hint", v)) }
    if let v = parameters.prompt { fields.append(("prompt", v)) }
    if let v = parameters.maxAge { fields.append(("max_age", String(v))) }
    if let v = parameters.nonce { fields.append(("nonce", v)) }
    if let v = parameters.uiLocales { fields.append(("ui_locales", v)) }
    if let v = parameters.deviceName { fields.append(("device_name", v)) }
    if let v = parameters.deviceId { fields.append(("device_id", v)) }
    fields += try Self.extraFields(parameters.additionalParameters, after: fields)
    if let stepUpSession {
      // spec/03 §5: a §2.1 request plus the post-login auth_session = step-up / re-authentication.
      fields.append(("auth_session", stepUpSession))
    }

    do {
      return try await handle(client.post(fields))
    } catch let error as NativeAuthError {
      noteFailure(error)
      throw error
    }
  }

  public func respond(_ answer: ChallengeAnswer, to challenge: Challenge) async throws -> FlowStep {
    try await respond(answer, to: challenge, additionalFields: [:])
  }

  public func respond(_ answer: ChallengeAnswer, to challenge: Challenge, additionalFields: [String: String]) async throws -> FlowStep {
    guard state == .awaitingAnswer, let session, let client else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "No challenge is pending (state: \(state))")
    }
    guard pending.contains(where: { $0.id == challenge.id && $0.type == challenge.type }) else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(challenge.type) is not in the pending set")
    }
    guard answer.challengeType == challenge.type else {
      throw NativeAuthError(code: NativeAuthError.Code.unsupportedChallenge, description: "A \(answer.challengeType) answer cannot be sent for a \(challenge.type) challenge")
    }
    if case .skip = answer, !challenge.isSkippable {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(challenge.type) is not skippable")
    }
    var fields: [(name: String, value: String)] = [
      ("auth_session", session),
      ("challenge_type", challenge.type.wire),
      ("challenge_id", challenge.id),
    ]
    if let name = answer.formFields.map(\.name).first(where: Self.continuationFieldNames.contains) {
      throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "An answer may not set '\(name)'")
    }
    fields += answer.formFields
    fields += try Self.extraFields(parameters.continuationParameters, after: fields)
    fields += try Self.extraFields(additionalFields, after: fields)
    do {
      return try await handle(client.post(fields))
    } catch let error as NativeAuthError {
      noteFailure(error)
      throw error
    }
  }

  public func cancel() async {
    let previous = state
    state = .finished
    pending = []
    guard previous == .awaitingAnswer, let session, let client else { return }
    self.session = nil
    do {
      // The server answers invalid_session once the session is cancelled (spec/03 §2.2).
      _ = try await client.send([("auth_session", session), ("action", "cancel")])
    } catch {
      logger.log(.debug, "cancel: \(error)")
    }
  }

  // MARK: -

  /// Names the SDK itself sends on some request (spec/03 §2.1, §2.2); callers may not override them.
  static let reservedFieldNames: Set<String> = [
    "client_id", "response_type", "scope", "code_challenge", "code_challenge_method", "acr_values", "login_hint",
    "prompt", "max_age", "nonce", "ui_locales", "device_name", "device_id", "auth_session", "challenge_type",
    "challenge_id", "action",
  ]

  /// The fields every continuation request starts with; an answer never sets them.
  static let continuationFieldNames: Set<String> = ["auth_session", "challenge_type", "challenge_id"]

  /// `extra` in key order, refusing names that are reserved or already in `existing`.
  static func extraFields(_ extra: [String: String], after existing: [(name: String, value: String)]) throws -> [(name: String, value: String)] {
    let taken = Set(existing.map(\.name))
    for name in extra.keys where name.isEmpty || reservedFieldNames.contains(name) || taken.contains(name) {
      throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "Extra field '\(name)' is empty, reserved or already set by the request")
    }
    return extra.sorted { $0.key < $1.key }.map { (name: $0.key, value: $0.value) }
  }

  private func handle(_ outcome: ChallengeOutcome) async throws -> FlowStep {
    switch outcome {
    case .challenges(let set):
      session = set.authSession
      pending = set.challenges
      lastExpiresIn = set.expiresIn
      state = .awaitingAnswer
      let unsupported = set.challenges.filter { !$0.type.isSupported }
      if !unsupported.isEmpty {
        logger.log(.info, "Challenge set contains unsupported types: \(unsupported.map(\.type.wire))")
      }
      return .challenges(set.challenges, set.context)
    case .authorizationCode(let code, let postLoginSession):
      state = .finished
      pending = []
      session = postLoginSession
      let credentials = try await tokens.exchange(code: code, codeVerifier: pkce.verifier, authSession: postLoginSession)
      return .authorized(credentials)
    case .redirectToWeb(let request):
      // The server removed the native authentication session (spec/03 §3.4); the PKCE pair of this
      // flow is what WebFallback exchanges the browser's code with.
      state = .finished
      pending = []
      session = nil
      logger.log(.info, "Server asks for a browser fallback (\(request.reason ?? "no reason"))")
      return .redirectToWeb(request)
    }
  }

  private func noteFailure(_ error: NativeAuthError) {
    switch error.code {
    case NativeAuthError.Code.invalidSession, NativeAuthError.Code.accessDenied, NativeAuthError.Code.invalidClient,
      NativeAuthError.Code.redirectToWeb, NativeAuthError.Code.serverError:
      // Terminal for this flow (spec/03 §3.5): the server removed the authentication session.
      state = .finished
      pending = []
      session = nil
    case NativeAuthError.Code.invalidRequest:
      // The session survives; a fresh auth_session may have been handed back.
      if let fresh = error.authSession { session = fresh }
    default:
      break
    }
  }
}
