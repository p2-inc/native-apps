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

  public init(
    scope: String? = "openid",
    acrValues: String? = nil,
    loginHint: String? = nil,
    prompt: String? = nil,
    maxAge: Int? = nil,
    nonce: String? = nil,
    uiLocales: String? = nil,
    deviceName: String? = nil,
    deviceId: String? = nil
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
  }
}

/// The challenge-driven state machine (spec/05 §2): `start() -> .challenges -> respond(...) ->
/// .authorized`.
public protocol LoginFlow: Sendable {
  func start() async throws -> FlowStep
  func respond(_ answer: ChallengeAnswer, to challenge: Challenge) async throws -> FlowStep
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

  public let clientId: String
  public let parameters: LoginParameters
  public let pkce: PKCE

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
    metadata: MetadataClient,
    transport: any Transport,
    dpop: DPoPSigner?,
    tokens: Tokens,
    logger: any NativeAuthLogger
  ) {
    self.clientId = clientId
    self.parameters = parameters
    self.pkce = pkce
    self.metadata = metadata
    self.transport = transport
    self.dpop = dpop
    self.tokens = tokens
    self.logger = logger
  }

  public var currentState: State { state }
  public var authSession: String? { session }
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
    // EXTENSION POINT (step-up, spec/03 §5): a stored post-login auth_session would be added here.
    // The server rejects it until Phase 2 (spec/11 D4), so the SDK deliberately never sends it.

    do {
      return try await handle(client.post(fields))
    } catch let error as NativeAuthError {
      noteFailure(error)
      throw error
    }
  }

  public func respond(_ answer: ChallengeAnswer, to challenge: Challenge) async throws -> FlowStep {
    guard state == .awaitingAnswer, let session, let client else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "No challenge is pending (state: \(state))")
    }
    guard pending.contains(where: { $0.id == challenge.id && $0.type == challenge.type }) else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(challenge.type) is not in the pending set")
    }
    guard answer.challengeType == challenge.type else {
      throw NativeAuthError(code: NativeAuthError.Code.unsupportedChallenge, description: "A \(answer.challengeType) answer cannot be sent for a \(challenge.type) challenge")
    }
    let fields: [(name: String, value: String)] = [
      ("auth_session", session),
      ("challenge_type", challenge.type.wire),
      ("challenge_id", challenge.id),
    ] + answer.formFields
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
