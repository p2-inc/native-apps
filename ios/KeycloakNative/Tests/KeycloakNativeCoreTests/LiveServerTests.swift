import Foundation
import Testing
@testable import KeycloakNativeCore

/// End-to-end against the demo compose stack (`KC_PORT=8089 docker compose up --wait`), enabled
/// with `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089`. Uses the real `URLSessionTransport`, a
/// software DPoP key and the software WebAuthn authenticator; this is what the iOS example app does
/// on a device, minus the platform passkey sheet.
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_BASE"] != nil))
struct LiveServerTests {
  static let base = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_BASE"] ?? ""
  static let issuer = URL(string: base + "/realms/demo")!
  static let aliceTotpSecret = "alice-totp-secret-20261014"

  func sdk(clientId: String, passkeys: any PasskeyPlatform = SoftwareAuthenticator(origin: Self.base)) -> KeycloakNative {
    var options = KeycloakNative.Options()
    options.secureStore = InMemorySecureStore()
    options.passkeyPlatform = passkeys
    options.dpop = .software
    options.logger = NoopLogger()
    return KeycloakNative.configure(issuer: Self.issuer, clientId: clientId, options: options)
  }

  func loginAlice(_ kc: KeycloakNative, passkey: Bool = false, authenticator: SoftwareAuthenticator? = nil) async throws -> Credentials {
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    if passkey, let challenge = step.challenges?.first(.passkey) {
      let assertion = try await kc.passkeys().assert(try #require(challenge.passkeyParams))
      step = try await flow.respond(.passkey(assertion), to: challenge)
    } else {
      step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    }
    step = try await flow.respond(.totp(TOTP.code(secret: Self.aliceTotpSecret)), to: try #require(step.challenges?.first(.totp)))
    return try #require(step.credentials)
  }

  @Test func metadataAndS3PasswordTotpLoginWithTokenLifecycle() async throws {
    let kc = sdk(clientId: "demo-ios")
    let metadata = try await kc.metadata()
    #expect(metadata.passkey?.rpId == "localhost")
    #expect(metadata.dpopSigningAlgValuesSupported.contains("ES256"))

    let credentials = try await loginAlice(kc)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(credentials.authSession != nil)
    // Record what Keycloak 26.8.1 does with an unsolicited DPoP proof on the token request (spec/12).
    print("LIVE: token_type=\(credentials.tokenType) dpop_bound=\(credentials.isDPoPBound)")

    let manager = kc.credentialsManager()
    try await manager.store(credentials.expiredCopy())
    let refreshed = try await manager.credentials()
    #expect(refreshed.accessToken != credentials.accessToken && refreshed.authSession == credentials.authSession)
    try await kc.tokens().revoke(token: try #require(refreshed.refreshToken))
    let gone = await #expect(throws: NativeAuthError.self) { try await kc.tokens().refresh(refreshed) }
    #expect(gone?.code == NativeAuthError.Code.invalidGrant)
  }

  @Test func s11RegisterPasskeyAfterLoginThenS1AllowListLogin() async throws {
    let authenticator = SoftwareAuthenticator(origin: Self.base)
    let kc = sdk(clientId: "demo-ios", passkeys: authenticator)
    let credentials = try await loginAlice(kc)
    let registered = try await kc.passkeys().registerNewPasskey(label: "LiveServerTests", credentials: credentials)
    #expect(registered.credentialId == authenticator.credentialIdBase64URL && registered.label == "LiveServerTests")

    let viaPasskey = try await loginAlice(kc, passkey: true)
    #expect(viaPasskey.accessTokenClaims?["preferred_username"]?.stringValue == "alice")

    // S2: discoverable login on demo-ios-passkey with the resident credential just registered.
    let kcDiscoverable = sdk(clientId: "demo-ios-passkey", passkeys: authenticator)
    let flow = kcDiscoverable.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    let passkey = try #require(step.challenges?.first(.passkey))
    #expect(passkey.passkeyParams?.discoverable == true)
    step = try await flow.respond(.passkey(try await kcDiscoverable.passkeys().assert(passkey.passkeyParams!)), to: passkey)
    guard case .challenges(let next, let context) = step else { Issue.record("expected totp"); return }
    #expect(context.username == "alice")
    step = try await flow.respond(.totp(TOTP.code(secret: Self.aliceTotpSecret)), to: try #require(next.first(.totp)))
    #expect(step.credentials != nil)

    // Wrong key → invalid_credential with a fresh challenge, then cancel.
    let wrong = sdk(clientId: "demo-ios", passkeys: SoftwareAuthenticator(origin: Self.base, wrongKey: true))
    let flow2 = wrong.authentication().startLogin(LoginParameters(scope: "openid"))
    step = try await flow2.start()
    step = try await flow2.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let challenge = try #require(step.challenges?.first(.passkey))
    try await Task.sleep(for: .seconds(1.1))  // stay outside Keycloak's quick-login window
    step = try await flow2.respond(.passkey(try await wrong.passkeys().assert(challenge.passkeyParams!)), to: challenge)
    #expect(step.challenges?.first(.passkey)?.error?.code == "invalid_credential")
    await flow2.cancel()
  }

  @Test func daveEnrolsAPasskeyInBandOnFirstLogin() async throws {
    let authenticator = SoftwareAuthenticator(origin: Self.base)
    let kc = sdk(clientId: "demo-ios", passkeys: authenticator)
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    step = try await flow.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    guard let password = step.challenges?.first(.password) else {
      Issue.record("dave already has a passkey from a previous run; reset with docker compose down -v")
      await flow.cancel()
      return
    }
    step = try await flow.respond(.password("dave-password"), to: password)
    guard let registration = step.challenges?.first(.passkeyRegistration) else {
      await flow.cancel()
      return  // action already consumed in this container
    }
    #expect(registration.id == "native-passkey-register" && registration.required)
    let params = try #require(registration.passkeyRegistrationParams)
    let attestation = try await kc.passkeys().register(params)
    step = try await flow.respond(.passkeyRegistration(attestation, label: "Dave's phone"), to: registration)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "dave")

    let second = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    step = try await second.start()
    step = try await second.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    let passkey = try #require(step.challenges?.first(.passkey))
    step = try await second.respond(.passkey(try await kc.passkeys().assert(passkey.passkeyParams!)), to: passkey)
    #expect(step.credentials != nil)
  }

  // MARK: - Phase 2 (spec/13)

  @Test func s6StepUpAgainstTheResourceServerAsksOnlyForTotp() async throws {
    let kc = sdk(clientId: "demo-ios-stepup")
    // Level 1: password only on the step-up flow.
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let level1 = try #require(step.credentials)
    #expect(level1.accessTokenClaims?["acr"]?.stringValue == "1")
    try await kc.credentialsManager().store(level1)

    // The demo API refuses acr 1 with RFC 9470's insufficient_user_authentication …
    let resource = URL(string: (ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_RESOURCE"] ?? "http://localhost:8091") + "/transfer")!
    func call(_ credentials: Credentials) async throws -> (Int, JSONValue?) {
      var request = URLRequest(url: resource)
      for (name, value) in try await kc.resourceRequestHeaders(for: credentials, method: "GET", url: resource) { request.setValue(value, forHTTPHeaderField: name) }
      let (data, response) = try await URLSession.shared.data(for: request)
      return ((response as? HTTPURLResponse)?.statusCode ?? 0, JSONValue(jsonData: data))
    }
    let (status1, body1) = try await call(level1)
    #expect(status1 == 401 && body1?["error"]?.stringValue == "insufficient_user_authentication", "\(status1) \(String(describing: body1))")

    // … so the app steps up: username skipped, only the TOTP is asked, same session, acr 2.
    let stepUp = try await kc.authentication().stepUp(acrValues: body1?["acr_values"]?.stringValue ?? "2", scope: "openid profile", deviceName: "LiveServerTests")
    step = try await stepUp.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected totp, got \(step)"); return }
    #expect(set.types == ["totp"] && context.stepUp && context.acrRequested == "2" && context.username == "alice")
    step = try await stepUp.respond(.totp(TOTP.code(secret: Self.aliceTotpSecret)), to: try #require(set.first(.totp)))
    let level2 = try #require(step.credentials)
    #expect(level2.accessTokenClaims?["acr"]?.stringValue == "2" && level2.accessTokenClaims?["sid"] == level1.accessTokenClaims?["sid"])
    #expect(level2.isDPoPBound, "the token endpoint binds to the SDK's key")
    let (status2, body2) = try await call(level2)
    #expect(status2 == 200 && body2?["status"]?.stringValue == "transferred", "\(status2) \(String(describing: body2))")
  }

  @Test func s4EmailOtpWithResendThroughMailpit() async throws {
    let mailpit = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_MAILPIT"] ?? "http://localhost:8025"
    func latestCode(to email: String) async throws -> String {
      let (data, _) = try await URLSession.shared.data(from: URL(string: mailpit + "/api/v1/messages?limit=20")!)
      let messages = JSONValue(jsonData: data)?["messages"]?.arrayValue ?? []
      let mine = try #require(messages.first { ($0["To"]?.arrayValue ?? []).contains { $0["Address"]?.stringValue == email } })
      let (body, _) = try await URLSession.shared.data(from: URL(string: mailpit + "/api/v1/message/" + (mine["ID"]?.stringValue ?? ""))!)
      let text = JSONValue(jsonData: body)?["Text"]?.stringValue ?? ""
      let match = try #require(text.firstRange(of: /code is (\d{6})/))
      return String(text[match].suffix(6))
    }
    let kc = sdk(clientId: "demo-ios-otp")
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.types == ["totp", "otp"])
    let otp = try #require(step.challenges?.first(.otp))
    #expect(otp.otpParams?.sent == false, "nothing sent until the user picks the email code")
    step = try await flow.respond(.otpResend, to: otp)
    let sent = try #require(step.challenges?.first(.otp))
    #expect(sent.otpParams?.sent == true && (sent.otpParams?.resendWait() ?? 0) > 0)
    step = try await flow.respond(.otp(try await latestCode(to: "alice@example.com")), to: sent)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
  }

  @Test func s7FrankIsRedirectedToTheWeb() async throws {
    let kc = sdk(clientId: "demo-ios")
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("frank"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("frank-password"), to: try #require(step.challenges?.first(.password)))
    guard case .redirectToWeb(let request) = step else { Issue.record("expected redirect_to_web, got \(step)"); return }
    #expect(request.reason == "required_action:UPDATE_PROFILE" && request.callbackScheme == "demoapp" && request.state != nil)
    let url = try await kc.webFallback().authorizationURL(for: request)
    #expect(url.absoluteString.hasPrefix(Self.base + "/realms/demo/protocol/openid-connect/auth?"))
    // The browser flow itself is exercised by RedirectToWebIT; opening Safari is not possible here.
  }

  // MARK: - Phase 2b (spec/14 D1): required actions in-band. Each action is consumed by the first run
  // in a container; later runs find the plain login and only check that it succeeds.

  private func loginToRequiredAction(_ kc: KeycloakNative, username: String, password: String) async throws -> (NativeLoginFlow, FlowStep) {
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username(username), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password(password), to: try #require(step.challenges?.first(.password)))
    return (flow, step)
  }

  @Test func carolUpdatesHerPasswordInBand() async throws {
    let kc = sdk(clientId: "demo-ios")
    var (flow, step) = try await loginToRequiredAction(kc, username: "carol", password: "carol-password")
    if let challenge = step.challenges?.first(.updatePassword) {
      #expect(challenge.id == "native-update-password" && challenge.required)
      step = try await flow.respond(.updatePassword("carol-password", confirm: "nope"), to: challenge)
      let mismatch = try #require(step.challenges?.first(.updatePassword))
      #expect(mismatch.error?.code == ChallengeError.Code.passwordMismatch)
      step = try await flow.respond(.updatePassword("carol-password", confirm: "carol-password"), to: mismatch)
    }
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "carol")
  }

  @Test func graceVerifiesHerEmailWithACode() async throws {
    let mailpit = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_MAILPIT"] ?? "http://localhost:8025"
    let kc = sdk(clientId: "demo-ios")
    var (flow, step) = try await loginToRequiredAction(kc, username: "grace", password: "grace-password")
    if let challenge = step.challenges?.first(.verifyEmail) {
      let params = try #require(challenge.verifyEmailParams)
      #expect(challenge.id == "native-verify-email" && params.sent && params.emailMasked == "g***@example.com")
      let (data, _) = try await URLSession.shared.data(from: URL(string: mailpit + "/api/v1/messages?limit=20")!)
      let messages = JSONValue(jsonData: data)?["messages"]?.arrayValue ?? []
      let mine = try #require(messages.first { ($0["To"]?.arrayValue ?? []).contains { $0["Address"]?.stringValue == "grace@example.com" } })
      let (body, _) = try await URLSession.shared.data(from: URL(string: mailpit + "/api/v1/message/" + (mine["ID"]?.stringValue ?? ""))!)
      let text = JSONValue(jsonData: body)?["Text"]?.stringValue ?? ""
      let match = try #require(text.firstRange(of: /code is (\d{6})/))
      step = try await flow.respond(.verifyEmail(code: String(text[match].suffix(6))), to: challenge)
    }
    #expect(step.credentials?.accessTokenClaims?["email_verified"]?.boolValue == true)
  }

  @Test func hankAcceptsTheTerms() async throws {
    let kc = sdk(clientId: "demo-ios")
    var (flow, step) = try await loginToRequiredAction(kc, username: "hank", password: "hank-password")
    if let challenge = step.challenges?.first(.terms) {
      #expect(challenge.id == "native-terms" && challenge.termsParams?.text?.hasPrefix("Demo terms") == true)
      step = try await flow.respond(.terms(accepted: true), to: challenge)
    }
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "hank")
  }

  @Test func s14BruteForceLockEndsWithAccessDenied() async throws {
    let kc = sdk(clientId: "demo-ios")
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    step = try await flow.respond(.username("erin"), to: try #require(step.challenges?.first(.username)))
    var locked: NativeAuthError?
    for attempt in 1...6 {
      guard let password = step.challenges?.first(.password) else { break }
      do {
        step = try await flow.respond(.password("wrong-\(attempt)"), to: password)
      } catch let error as NativeAuthError {
        locked = error
        break
      }
    }
    #expect(locked?.code == NativeAuthError.Code.accessDenied)
    let state = await flow.currentState
    #expect(state == .finished)
  }
}
