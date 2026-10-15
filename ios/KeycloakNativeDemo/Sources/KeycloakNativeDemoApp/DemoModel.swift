import Foundation
import KeycloakNativeCore
import KeycloakNativeUI
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
  /// S6: the last answer of the demo resource server.
  public private(set) var resourceResult: String?

  public var username = ""
  public var password = ""
  public var totp = ""
  public var otp = ""
  public var totpCredentialId: String?
  public var passkeyLabel = "My iPhone"
  /// Phase 2b required actions (carol / grace).
  public var newPassword = ""
  public var newPasswordConfirm = ""
  public var verifyEmailCode = ""

  private var sdks: [String: KeycloakNative] = [:]

  public init(config: DemoConfig) {
    self.config = config
  }

  public var activeClientId: String {
    switch scenario?.client ?? .standard {
    case .standard: config.clientId
    case .passkey: config.passkeyClientId
    case .stepUp: config.stepUpClientId
    case .otp: config.otpClientId
    }
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

  /// Restores credentials stored by a previous launch (the Keychain `CredentialsManager`, spec/05 §6).
  /// Called once at launch; expired tokens are refreshed on demand (`refreshTokens`, `credentials()`).
  public func restoreSession() async {
    let manager = sdk(for: config.clientId).credentialsManager()
    do {
      if let stored = try await manager.stored() {
        credentials = stored
        let valid = try await manager.hasValid()
        status = "Restored stored credentials for \(stored.accessTokenClaims?["preferred_username"]?.stringValue ?? "?") (\(valid ? "access token valid" : "access token expired; refresh on Home"))"
      }
    } catch let error as NativeAuthError {
      lastError = error
      status = "Restoring credentials failed: \(error.code)"
    } catch {
      status = "Restoring credentials failed: \(error)"
    }
  }

  public func select(_ scenario: Scenario) {
    self.scenario = scenario
    username = scenario.prefilledUsername ?? ""
    password = ""
    totp = ""
    otp = ""
    newPassword = ""
    newPasswordConfirm = ""
    verifyEmailCode = ""
    resourceResult = nil
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

  /// S4: `action=resend` for an `otp` challenge (also the first send when `sent` is false).
  public func resendOtp(_ challenge: Challenge) async {
    await answer(.otpResend, to: challenge)
  }

  /// Hands a `NativeLoginView` (S5/S13) result to the model.
  public func finish(_ result: NativeLoginResult) {
    switch result {
    case .authorized(let credentials):
      apply(.authorized(credentials))
    case .cancelled:
      flow = nil
      step = nil
      status = "Cancelled."
    case .failed(let error):
      lastError = error
      flow = nil
      step = nil
      status = "\(error.code): \(error.errorDescription ?? "")"
    }
  }

  // MARK: - Step-up (S6, S11 after 300 s) and refresh-triggered re-auth (S8)

  /// S6: calls the demo API; on RFC 9470 `401 insufficient_user_authentication` starts a step-up flow
  /// for the requested `acr_values`; the Login tab then shows only what the level needs.
  public func transfer() async {
    guard let credentials else { return }
    await run("GET /transfer") {
      let url = config.resourceServer.appending(path: "transfer")
      var request = URLRequest(url: url)
      for (name, value) in try await sdk.resourceRequestHeaders(for: credentials, method: "GET", url: url) {
        request.setValue(value, forHTTPHeaderField: name)
      }
      let (data, response) = try await URLSession.shared.data(for: request)
      let http = response as? HTTPURLResponse
      let body = String(data: data, encoding: .utf8) ?? ""
      self.resourceResult = "HTTP \(http?.statusCode ?? 0): \(body)"
      guard http?.statusCode == 401, let json = JSONValue(jsonData: data), json["error"]?.stringValue == "insufficient_user_authentication" else {
        self.status = http?.statusCode == 200 ? "Transfer accepted (acr satisfied)." : "Transfer answered HTTP \(http?.statusCode ?? 0)."
        return
      }
      let acr = json["acr_values"]?.stringValue ?? "2"
      let flow = try await sdk.authentication().stepUp(acrValues: acr, scope: "openid profile", deviceName: config.deviceName)
      self.flow = flow
      self.status = "Stepping up to acr \(acr) with the stored auth_session…"
      self.apply(try await flow.start())
    }
  }

  /// S11 after 300 s / spec/03 §6: the registration endpoints refused the stale authentication and
  /// handed back an auth_session + max_age; continue with a step-up.
  public func stepUpAfter(_ error: NativeAuthError) async {
    await run("Re-authenticating (max_age \(error.maxAge.map(String.init) ?? "?"))") {
      let flow = try sdk.authentication().continueAfterTokenChallenge(error, parameters: LoginParameters(scope: "openid profile", deviceName: config.deviceName))
      self.flow = flow
      self.apply(try await flow.start())
    }
  }

  /// S8: ends the session on the server only (RFC 7009 revocation of the refresh token) so the next
  /// refresh is refused and the SDK reports `reauthentication_required`.
  public func endSessionOnServer() async {
    guard let credentials, let refreshToken = credentials.refreshToken else { return }
    await run("Revoking the refresh token on the server") {
      try await sdk.tokens().revoke(token: refreshToken)
      self.status = "Session ended on the server; the stored tokens are now stale. Try “Refresh tokens”."
    }
  }

  // MARK: - After login

  public func registerPasskey() async {
    guard let credentials else { return }
    await run("Registering a passkey (§6)") {
      do {
        let registered = try await sdk.passkeys().registerNewPasskey(label: passkeyLabel, credentials: credentials)
        self.registeredPasskeys.append(registered)
        self.status = "Passkey registered: \(registered.label ?? registered.credentialId)"
      } catch let error as NativeAuthError where error.code == NativeAuthError.Code.insufficientAuthorization && error.authSession != nil {
        // spec/03 §6: too old; step up with the server's max_age, then register again from Home.
        self.lastError = error
        self.status = "Authentication too old for registration: step up (max_age \(error.maxAge ?? 0)) on the Login tab, then retry."
        await self.stepUpAfter(error)
      }
    }
  }

  public func refreshTokens() async {
    await run("Refreshing tokens") {
      let manager = sdk.credentialsManager()
      if let stored = try await manager.stored() {
        try await manager.store(stored.forcedExpired())
      }
      do {
        self.credentials = try await manager.credentials()
        self.status = "Tokens refreshed."
      } catch let error as NativeAuthError where error.code == NativeAuthError.Code.reauthenticationRequired {
        // S8: the refresh was refused. With an auth_session the SDK could step up
        // (continueAfterTokenChallenge); Keycloak answers invalid_grant without one, so log in again.
        self.lastError = error
        self.credentials = nil
        self.status = error.authSession == nil
          ? "reauthentication_required: the session is gone (\(error.errorDescription ?? "")). Start a new login."
          : "reauthentication_required with an auth_session: stepping up…"
        if error.authSession != nil { await self.stepUpAfter(error) }
      }
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
      let kind = context.stepUp ? "Step-up (acr \(context.acrRequested ?? "-")): server offers" : "Server offers"
      status = "\(kind) \(challenges.map(\.type.wire).joined(separator: ", "))\(who)"
    case .authorized(let credentials):
      self.credentials = credentials
      flow = nil
      status = "Signed in as \(credentials.accessTokenClaims?["preferred_username"]?.stringValue ?? "?") (token_type \(credentials.tokenType), acr \(credentials.accessTokenClaims?["acr"]?.stringValue ?? "-"))"
      Task { try? await sdk.credentialsManager().store(credentials) }
    case .redirectToWeb(let request):
      // S7 (spec/03 §3.4): the server cannot finish natively; the Login screen offers the browser.
      status = "Browser needed: \(request.reason ?? "redirect_to_web") — continue in Safari (\(request.expiresIn.map { "\($0) s" } ?? "PAR") )"
    }
  }

  /// S7: completes a `redirectToWeb` step through `ASWebAuthenticationSession` (spec/05 §2.2).
  public func continueInBrowser() async {
    guard let flow, case .redirectToWeb(let request)? = step else { return }
    await run("Opening the browser for \(request.reason ?? "redirect_to_web")") {
      let credentials = try await sdk.webFallback().complete(request, flow: flow)
      self.apply(.authorized(credentials))
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
