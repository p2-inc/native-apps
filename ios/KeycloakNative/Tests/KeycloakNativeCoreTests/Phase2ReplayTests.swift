import Foundation
import Testing
@testable import KeycloakNativeCore

/// Phase 2 contract tests (spec/13): step-up, OTP, redirect_to_web, DPoP-bound sessions, replayed
/// from the transcripts of StepUpIT, OtpIT, RedirectToWebIT, DPoPBindingIT and PasskeyIT.
@Suite(.serialized) struct Phase2ReplayTests {
  static let stepUpClient = "demo-ios-stepup"
  static let otpClient = "demo-ios-otp"
  static let itParameters = TranscriptReplayTests.itParameters

  // MARK: - Step-up (spec/03 §5)

  @Test func stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession() async throws {
    let (h, transport, t) = try Harness.replay(["StepUpIT.stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession"], clientId: Self.stepUpClient)
    // Level 1 login: username → password, no TOTP (the level-2 condition is not requested).
    let login = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await login.start()
    step = try await login.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await login.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let level1 = try #require(step.credentials)
    #expect(level1.accessTokenClaims?["acr"]?.stringValue == "1")
    try await h.sdk.credentialsManager().store(level1)

    // Step up to acr 2 with the stored post-login auth_session: only the TOTP is asked.
    let stepUp = try await h.sdk.authentication().stepUp(acrValues: "2", scope: "openid profile", deviceName: "NativeAuthIT")
    let v1 = await stepUp.isStepUp
    #expect(v1)
    step = try await stepUp.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected the totp challenge"); return }
    #expect(set.types == ["totp"])
    #expect(context.stepUp && context.acrRequested == "2" && context.username == "alice")
    step = try await stepUp.respond(.totp("000000"), to: try #require(set.first(.totp)))
    let level2 = try #require(step.credentials)
    #expect(level2.accessTokenClaims?["acr"]?.stringValue == "2")
    #expect(level2.accessTokenClaims?["sid"] == level1.accessTokenClaims?["sid"], "same user session")
    #expect(level2.authSession != nil && level2.authSession != level1.authSession, "fresh post-login auth_session")
    try await h.sdk.credentialsManager().store(level2)

    // Level 1 is still satisfied: the step-up completes without any challenge.
    let again = try await h.sdk.authentication().stepUp(acrValues: "1", scope: "openid profile", deviceName: "NativeAuthIT")
    step = try await again.start()
    #expect(step.credentials?.accessTokenClaims?["acr"]?.stringValue == "1")
    #expect(transport.remaining == 0)
    _ = t
  }

  @Test func maxAgeForcesAFullReauthentication() async throws {
    let (h, transport, _) = try Harness.replay(["StepUpIT.maxAgeForcesAFullReauthentication"], clientId: Self.stepUpClient)
    let login = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await login.start()
    step = try await login.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await login.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let credentials = try #require(step.credentials)

    // max_age=0 passed explicitly with the session from the credentials (no Keychain round trip).
    let flow = try await h.sdk.authentication().stepUp(LoginParameters(scope: "openid profile", maxAge: 0, deviceName: "NativeAuthIT"), authSession: credentials.authSession)
    step = try await flow.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected a password challenge"); return }
    #expect(set.first(.password) != nil && set.first(.username) == nil, "username is skipped, the factor is asked again")
    #expect(context.stepUp && context.acrRequested == nil)
    step = try await flow.respond(.password("alice-password"), to: try #require(set.first(.password)))
    #expect(step.credentials?.accessTokenClaims?["auth_time"]?.intValue ?? 0 > credentials.accessTokenClaims?["auth_time"]?.intValue ?? 0)
    #expect(transport.remaining == 0)
  }

  @Test func stepUpWithoutStoredSessionIsCredentialsNotFound() async throws {
    let (h, _, _) = try Harness.replay([], clientId: Self.stepUpClient)
    let error = await #expect(throws: NativeAuthError.self) { try await h.sdk.authentication().stepUp(acrValues: "2") }
    #expect(error?.code == NativeAuthError.Code.credentialsNotFound)
  }

  @Test func staleRegistrationIsRefusedWithAStepUpSessionAndMaxAge() async throws {
    let (h, transport, t) = try Harness.replay(["PasskeyIT.staleAuthenticationIsRefusedForRegistrationUntilAStepUpWithMaxAge"], clientId: TranscriptReplayTests.demoIOS, range: 1...11)
    let login = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await login.start()
    step = try await login.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await login.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await login.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    let stale = try #require(step.credentials)

    // §6: 403 insufficient_authorization with auth_session + max_age.
    let refused = await #expect(throws: NativeAuthError.self) { try await h.sdk.passkeys().registerNewPasskey(label: "x", credentials: stale) }
    #expect(refused?.code == NativeAuthError.Code.insufficientAuthorization)
    #expect(refused?.maxAge == 1 && refused?.authSession != nil)

    // continueAfterTokenChallenge: a step-up with that session and max_age; the plain flow re-runs
    // password + totp (username skipped).
    let flow = try h.sdk.authentication().continueAfterTokenChallenge(try #require(refused), parameters: LoginParameters(scope: "openid profile", deviceName: "NativeAuthIT"))
    #expect(flow.parameters.maxAge == 1)
    step = try await flow.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected challenges"); return }
    #expect(context.stepUp && context.username == "alice" && set.first(.username) == nil)
    step = try await flow.respond(.password("alice-password"), to: try #require(set.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    let fresh = try #require(step.credentials)

    // The options call now succeeds; the scripted platform cancels the ceremony so the test ends there.
    h.passkeys.fail(with: NativeAuthError(code: NativeAuthError.Code.passkeyCancelled, description: "scripted"))
    let cancelled = await #expect(throws: NativeAuthError.self) { try await h.sdk.passkeys().registerNewPasskey(label: "x", credentials: fresh) }
    #expect(cancelled?.code == NativeAuthError.Code.passkeyCancelled)
    #expect(transport.remaining == 0)
    _ = t
  }

  // MARK: - OTP (spec/03 §4.6)

  @Test func bobGetsAnEmailCodeAsTheOnlySecondFactor() async throws {
    let (h, transport, _) = try Harness.replay(["OtpIT.bobGetsAnEmailCodeAsTheOnlySecondFactor"], clientId: Self.otpClient)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let otp = try #require(step.challenges?.first(.otp))
    #expect(step.challenges?.types == ["otp"] && otp.required)
    let params = try #require(otp.otpParams)
    #expect(params.sent && params.channel == "email" && params.destinationMasked == "b***@example.com" && params.digits == 6 && params.ttl == 300)
    #expect(params.resendAllowedAt != nil)

    step = try await flow.respond(.otpResend, to: otp)
    let tooSoon = try #require(step.challenges?.first(.otp))
    #expect(tooSoon.error?.code == ChallengeError.Code.resendTooSoon && tooSoon.otpParams?.sent == true)

    step = try await flow.respond(.otp("000000"), to: tooSoon)
    let wrong = try #require(step.challenges?.first(.otp))
    #expect(wrong.error?.code == ChallengeError.Code.invalidCredential)

    step = try await flow.respond(.otp("000000"), to: wrong)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "bob")
    #expect(transport.remaining == 0)
  }

  @Test func aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest() async throws {
    let (h, transport, _) = try Harness.replay(["OtpIT.aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest"], clientId: Self.otpClient, range: 1...4)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.types == ["totp", "otp"])
    let otp = try #require(step.challenges?.first(.otp))
    #expect(!otp.required && otp.otpParams?.sent == false && otp.otpParams?.resendAllowedAt == nil)

    step = try await flow.respond(.otpResend, to: otp)
    let sent = try #require(step.challenges?.first(.otp))
    #expect(sent.error == nil && sent.otpParams?.sent == true && sent.otpParams?.resendAllowedAt != nil)
    #expect(step.challenges?.types == ["totp", "otp"], "the alternatives stay on offer")
    // The IT answered the code next; the SDK would exchange the resulting code, which the IT did
    // not record, so the replay stops here.
    #expect(transport.remaining == 0)
  }

  // MARK: - redirect_to_web (spec/03 §3.4)

  @Test func pendingNonNativeRequiredActionRedirectsToWebAndTheCodeIsExchangedWithTheNativeVerifier() async throws {
    let transcript = try Transcript.load("RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt")
    // The IT recorded the native login (1-3), then the code exchange of the browser's code; the
    // browser requests themselves are not part of the contract. Replay: 1...3 + the first token call.
    let tokenExchange = try #require(transcript.exchanges.first { $0.request.path.hasSuffix("/token") })
    let recordedCode = try #require(tokenExchange.request.form?["code"])
    let presenter = MockWebPresenter { url in
      // Pretend the user completed the browser flow: the realm redirects to the app with the code.
      let state = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "request_uri" }?.value
      #expect(state?.hasPrefix("urn:ietf:params:oauth:request_uri:") == true)
      return URL(string: "demoapp://auth/callback?state=STATE&code=\(recordedCode)")!
    }
    let (h, transport, _) = try Harness.replay([transcript.test], clientId: TranscriptReplayTests.demoIOS, seqs: [1, 2, 3, tokenExchange.seq], webPresenter: presenter)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("frank"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("frank-password"), to: try #require(step.challenges?.first(.password)))
    guard case .redirectToWeb(let request) = step else { Issue.record("expected redirect_to_web, got \(step)"); return }
    #expect(request.reason == "required_action:UPDATE_PROFILE" && request.redirectUri == "demoapp://auth/callback" && request.callbackScheme == "demoapp")
    #expect(request.expiresIn == 60 && request.state != nil)
    let v2 = await flow.currentState
    #expect(v2 == .finished)

    // Replace the scripted state with the real one now that we know it.
    presenter.callback = { _ in URL(string: "demoapp://auth/callback?state=\(request.state!)&code=\(recordedCode)")! }
    let credentials = try await h.sdk.webFallback().complete(request, flow: flow)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "frank")
    #expect(presenter.opened.count == 1 && presenter.opened[0].scheme == "demoapp")
    let opened = try #require(presenter.opened.first?.url)
    #expect(opened.path.hasSuffix("/protocol/openid-connect/auth"))
    #expect(URLComponents(url: opened, resolvingAgainstBaseURL: false)?.queryItems?.contains { $0.name == "client_id" && $0.value == "demo-ios" } == true)
    // The exchange carried the redirect_uri and this flow's verifier.
    let token = try #require(transport.sent.last)
    #expect(token.formFields?.contains { $0.name == "redirect_uri" && $0.value == "demoapp://auth/callback" } == true)
    #expect(token.formFields?.contains { $0.name == "code_verifier" && $0.value == flow.pkce.verifier } == true)
    #expect(transport.remaining == 0)
  }

  @Test func webFallbackRejectsAStateMismatchAndSurfacesBrowserErrors() async throws {
    #expect(throws: NativeAuthError.self) {
      try WebFallback.code(from: URL(string: "demoapp://auth/callback?state=other&code=x")!, expectedState: "expected")
    }
    let denied = #expect(throws: NativeAuthError.self) {
      try WebFallback.code(from: URL(string: "demoapp://auth/callback?error=access_denied&error_description=nope")!, expectedState: nil)
    }
    #expect(denied?.code == "access_denied")
    #expect(try WebFallback.code(from: URL(string: "demoapp://auth/callback?state=s&code=abc")!, expectedState: "s") == "abc")
  }

  // MARK: - DPoP-bound session (spec/03 §8)

  @Test func sessionCodeAndPostLoginSessionAreBoundToTheProofKey() async throws {
    // Exchanges 11-14: a login where every request carried a proof; 17: the step-up with the same key.
    let (h, transport, _) = try Harness.replay(["DPoPBindingIT.sessionCodeAndPostLoginSessionAreBoundToTheProofKey"], clientId: TranscriptReplayTests.demoIOS, seqs: [11, 12, 13, 14, 17])
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let credentials = try #require(step.credentials)
    #expect(credentials.isDPoPBound && credentials.tokenType == "DPoP")
    #expect(credentials.accessTokenClaims?["cnf"]?["jkt"]?.stringValue != nil)
    // Every challenge request carried a proof with htm/htu of the challenge endpoint.
    for request in transport.sent where request.url.path.hasSuffix("/challenge") {
      let proof = try #require(request.header("DPoP"))
      let payload = try #require(JWT.decodePayload(proof))
      #expect(payload["htm"]?.stringValue == "POST" && payload["htu"]?.stringValue == request.url.absoluteString)
    }
    let stepUp = try await h.sdk.authentication().stepUp(LoginParameters(scope: "openid profile", acrValues: "2", deviceName: "NativeAuthIT"), authSession: credentials.authSession)
    step = try await stepUp.start()
    #expect(step.challenges?.first(.password) != nil)
    #expect(transport.remaining == 0)
  }

  // MARK: - Resource requests

  @Test func resourceRequestHeadersCarryAProofWithAthForBoundTokens() async throws {
    let (h, _, _) = try Harness.replay([], clientId: TranscriptReplayTests.demoIOS)
    let url = URL(string: "https://api.example.com/transfer")!
    let bound = Credentials(accessToken: "at", tokenType: "DPoP", refreshToken: nil, idToken: nil, scope: nil, expiresAt: .distantFuture, refreshExpiresAt: nil, authSession: nil)
    let headers = try await h.sdk.resourceRequestHeaders(for: bound, method: "GET", url: url)
    #expect(headers["Authorization"] == "DPoP at")
    let proof = try #require(headers["DPoP"])
    let payload = try #require(JWT.decodePayload(proof))
    #expect(payload["htm"]?.stringValue == "GET" && payload["htu"]?.stringValue == url.absoluteString && payload["ath"]?.stringValue != nil)
    let bearer = Credentials(accessToken: "at", tokenType: "Bearer", refreshToken: nil, idToken: nil, scope: nil, expiresAt: .distantFuture, refreshExpiresAt: nil, authSession: nil)
    let plain = try await h.sdk.resourceRequestHeaders(for: bearer, method: "GET", url: url)
    #expect(plain == ["Authorization": "Bearer at"])
  }
}
