import Foundation
import KeycloakNativeCore
import Observation

/// Drives the SDK for the example app: one `KeycloakNative` per client, the current flow and step,
/// stored credentials, and the redacted flow log for the Diagnostics screen.
@MainActor
@Observable
public final class DemoModel {
  public let config: DemoConfig
  public private(set) var flowLog: [FlowLogEntry] = []
  public private(set) var scenario: Scenario?
  public private(set) var flow: NativeLoginFlow?
  public private(set) var step: FlowStep?
  public private(set) var credentials: Credentials?
  public private(set) var lastError: NativeAuthError?
  public private(set) var status: String = "Pick a scenario, then start a login."
  public private(set) var isBusy = false
  public private(set) var metadata: NativeAuthMetadata?
  public private(set) var dpopThumbprint: String?
  public private(set) var registeredPasskeys: [RegisteredPasskey] = []

  public var username = ""
  public var password = ""
  public var totp = ""
  public var totpCredentialId: String?
  public var passkeyLabel = "My iPhone"

  private var sdks: [String: KeycloakNative] = [:]

  public init(config: DemoConfig) {
    self.config = config
  }

  public var activeClientId: String {
    scenario?.usesPasskeyClient == true ? config.passkeyClientId : config.clientId
  }

  public func sdk(for clientId: String) -> KeycloakNative {
    if let existing = sdks[clientId] { return existing }
    var options = KeycloakNative.Options()
    options.allowRpIdMismatch = config.allowRpIdMismatch
    options.flowObserver = LogForwarder { [weak self] entry in
      Task { @MainActor in self?.flowLog.append(entry) }
    }
    options.logger = OSLogLogger(minimumLevel: .debug)
    let sdk = KeycloakNative.configure(issuer: config.issuer, clientId: clientId, options: options)
    sdks[clientId] = sdk
    return sdk
  }

  public var sdk: KeycloakNative { sdk(for: activeClientId) }

  public func select(_ scenario: Scenario) {
    self.scenario = scenario
    username = scenario.prefilledUsername ?? ""
    password = ""
    totp = ""
    step = nil
    flow = nil
    lastError = nil
    status = scenario.details
  }

  // MARK: - Login flow

  public func startLogin() async {
    await run("Starting login (\(activeClientId))") {
      let flow = sdk.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: config.deviceName))
      self.flow = flow
      let step = try await flow.start()
      self.apply(step)
    }
  }

  public func answer(_ answer: ChallengeAnswer, to challenge: Challenge) async {
    guard let flow else { return }
    await run("Answering \(challenge.type)") {
      let step = try await flow.respond(answer, to: challenge)
      self.apply(step)
    }
  }

  /// Runs the platform passkey sheet for an assertion challenge; cancellation keeps the flow open.
  public func usePasskey(_ challenge: Challenge, preferImmediatelyAvailable: Bool = false) async {
    guard let params = challenge.passkeyParams else { return }
    await run("Passkey assertion (rp_id \(params.rpId), \(params.discoverable ? "discoverable" : "\(params.allowCredentials.count) allowed"))") {
      let assertion = try await sdk.passkeys().assert(params, preferImmediatelyAvailableCredentials: preferImmediatelyAvailable)
      await self.answer(.passkey(assertion), to: challenge)
    }
  }

  /// `passkey_registration` mid-flow (user dave).
  public func registerPasskeyInFlow(_ challenge: Challenge) async {
    guard let params = challenge.passkeyRegistrationParams else { return }
    await run("Creating a passkey for \(params.user.name)") {
      let attestation = try await sdk.passkeys().register(params)
      await self.answer(.passkeyRegistration(attestation, label: self.passkeyLabel), to: challenge)
    }
  }

  public func cancel() async {
    await flow?.cancel()
    flow = nil
    step = nil
    status = "Cancelled."
  }

  /// S14: wrong passwords until the server locks the account.
  public func runBruteForce() async {
    select(.s14BruteForce)
    await startLogin()
    guard let usernameChallenge = step?.challenges?.first(where: { $0.type == .username }) else { return }
    await answer(.username("erin"), to: usernameChallenge)
    for attempt in 1...6 {
      guard lastError == nil, let passwordChallenge = step?.challenges?.first(where: { $0.type == .password }) else { break }
      await answer(.password("wrong-password-\(attempt)"), to: passwordChallenge)
    }
    if let error = lastError, error.code == NativeAuthError.Code.accessDenied {
      status = "Locked out after repeated failures: \(error.code) — \(error.errorDescription ?? "")"
    }
  }

  // MARK: - After login

  public func registerPasskey() async {
    guard let credentials else { return }
    await run("Registering a passkey (§6)") {
      let registered = try await sdk.passkeys().registerNewPasskey(label: passkeyLabel, credentials: credentials)
      self.registeredPasskeys.append(registered)
      self.status = "Passkey registered: \(registered.label ?? registered.credentialId)"
    }
  }

  public func refreshTokens() async {
    await run("Refreshing tokens") {
      let manager = sdk.credentialsManager()
      if let stored = try await manager.stored() {
        try await manager.store(stored.forcedExpired())
      }
      self.credentials = try await manager.credentials()
      self.status = "Tokens refreshed."
    }
  }

  public func logout() async {
    await run("Logging out") {
      await sdk.credentialsManager().logout()
      self.credentials = nil
      self.registeredPasskeys = []
      self.step = nil
      self.flow = nil
      self.status = "Logged out."
    }
  }

  public func loadDiagnostics() async {
    await run("Loading metadata") {
      self.metadata = try await sdk.metadata(forceRefresh: true)
      self.dpopThumbprint = try await sdk.dpopKeyThumbprint()
    }
  }

  public func clearLog() {
    flowLog = []
  }

  // MARK: -

  private func apply(_ step: FlowStep) {
    self.step = step
    lastError = nil
    switch step {
    case .challenges(let challenges, let context):
      let who = context.username.map { " for \($0)" } ?? ""
      status = "Server offers \(challenges.map(\.type.wire).joined(separator: ", "))\(who)"
    case .authorized(let credentials):
      self.credentials = credentials
      flow = nil
      status = "Signed in as \(credentials.accessTokenClaims?["preferred_username"]?.stringValue ?? "?") (token_type \(credentials.tokenType))"
      Task { try? await sdk.credentialsManager().store(credentials) }
    }
  }

  private func run(_ what: String, _ body: () async throws -> Void) async {
    isBusy = true
    status = what + "…"
    defer { isBusy = false }
    do {
      try await body()
    } catch let error as NativeAuthError {
      lastError = error
      status = "\(error.code): \(error.errorDescription ?? "")"
      if error.code == NativeAuthError.Code.passkeyCancelled {
        status = "Passkey prompt cancelled — pick another way."
      } else if [NativeAuthError.Code.invalidSession, NativeAuthError.Code.accessDenied].contains(error.code) {
        flow = nil
        step = nil
      }
    } catch {
      status = "Unexpected: \(error)"
    }
  }
}

private struct LogForwarder: FlowObserver {
  let handler: @Sendable (FlowLogEntry) -> Void
  func record(_ entry: FlowLogEntry) { handler(entry) }
}

extension Credentials {
  func forcedExpired() -> Credentials {
    Credentials(accessToken: accessToken, tokenType: tokenType, refreshToken: refreshToken, idToken: idToken, scope: scope, expiresAt: Date(timeIntervalSince1970: 0), refreshExpiresAt: refreshExpiresAt, issuedAt: issuedAt, authSession: authSession)
  }
}
