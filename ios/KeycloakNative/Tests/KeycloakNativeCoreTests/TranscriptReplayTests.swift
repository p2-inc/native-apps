import Foundation
import Testing
@testable import KeycloakNativeCore

/// Contract tests: the SDK drives each recorded scenario through `MockTransport`, which rejects any
/// request that differs from what the integration test sent and answers with what Keycloak sent.
@Suite(.serialized) struct TranscriptReplayTests {
  static let demoIOS = "demo-ios"
  static let demoAlt = "demo-ios-alt"
  static let demoPasskey = "demo-ios-passkey"
  /// The integration tests send this `device_name`; the SDK must send exactly the same field set.
  static let itParameters = LoginParameters(scope: "openid profile", deviceName: "NativeAuthIT")

  // MARK: - Username / password / TOTP (S3)

  @Test func happyPathUsernamePasswordTotpYieldsTokens() async throws {
    let (h, transport, t) = try Harness.replay(["NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri"], clientId: Self.demoIOS, range: 1...5)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)

    var step = try await flow.start()
    let username = try #require(step.challenges?.first(.username))
    #expect(step.challenges?.count == 1 && username.required)
    #expect(username.usernameParams?.allowEmail == true)
    let v10 = await flow.expiresIn
    #expect(v10 == 1800)

    step = try await flow.respond(.username("alice"), to: username)
    guard case .challenges(let set, let context) = step else { Issue.record("expected challenges"); return }
    #expect(context.username == "alice" && context.displayName == "Alice Example" && context.clientName == "Demo iOS App")
    let password = try #require(set.first(.password))
    #expect(password.passwordParams?.usernameKnown == true)

    step = try await flow.respond(.password("alice-password"), to: password)
    let totp = try #require(step.challenges?.first(.totp))
    #expect(step.challenges?.types == ["totp"] && totp.required)
    #expect(totp.totpParams?.digits == 6 && totp.totpParams?.period == 30 && totp.totpParams?.credentialLabels == ["Phone"])

    step = try await flow.respond(.totp("000000", credentialId: nil), to: totp)
    let credentials = try #require(step.credentials)
    let tokenJSON = t[0].exchange(5).response.json!
    #expect(credentials.accessToken == tokenJSON["access_token"]?.stringValue)
    #expect(credentials.refreshToken == tokenJSON["refresh_token"]?.stringValue)
    #expect(credentials.idToken == tokenJSON["id_token"]?.stringValue)
    #expect(credentials.tokenType == "Bearer" && !credentials.isDPoPBound, "the server does not bind yet")
    #expect(credentials.authSession == t[0].exchange(4).response.json?["auth_session"]?.stringValue, "post-login auth_session is kept")
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(credentials.scope?.contains("openid") == true)
    let v11 = await flow.currentState
    #expect(v11 == .finished)
    #expect(transport.remaining == 0)

    // The token request carried a DPoP proof even though the server ignores it today.
    let tokenRequest = transport.sent.last!
    #expect(tokenRequest.header("DPoP")?.split(separator: ".").count == 3)
    #expect(tokenRequest.formFields?.contains { $0.name == "redirect_uri" } == false)

    try await h.sdk.credentialsManager().store(credentials)
    let v12 = try await h.sdk.credentialsManager().hasValid()
    #expect(v12)
    let v13 = try await h.sdk.credentialsManager().authSession()
    #expect(v13 == credentials.authSession)
  }

  @Test func passwordOnlyUserSkipsTheConditionalSecondFactor() async throws {
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.passwordOnlyUserSkipsConditionalSecondFactor"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "bob")
    #expect(transport.remaining == 0)
  }

  @Test func wrongPasswordRechallengesWithErrorDescriptorThenSucceeds() async throws {
    let (h, _, _) = try Harness.replay(["NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let first = try #require(step.challenges?.first(.password))

    step = try await flow.respond(.password("wrong-password"), to: first)
    let again = try #require(step.challenges?.first(.password))
    #expect(again.id == first.id, "same execution is re-challenged")
    #expect(again.error?.code == ChallengeError.Code.invalidCredential)
    #expect(again.error?.message != nil)
    #expect(again.required == (step.challenges?.count == 1))
    let v14 = await flow.currentState
    #expect(v14 == .awaitingAnswer)

    step = try await flow.respond(.password("alice-password"), to: again)
    #expect(step.challenges?.types == ["totp"])
    #expect(step.challenges?.first?.error == nil)
  }

  @Test func wrongTotpRechallengesThenSucceeds() async throws {
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.wrongTotpRechallengesThenSucceeds"], clientId: Self.demoIOS, range: 1...5)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let totp = try #require(step.challenges?.first(.totp))
    step = try await flow.respond(.totp("111111"), to: totp)
    #expect(step.challenges?.first(.totp)?.error?.code == "invalid_credential")
    // The IT stopped at the 200 without exchanging the code; the SDK always exchanges, so stop here.
    #expect(transport.remaining == 1)
  }

  @Test func emptyPasswordIsMissingCredential() async throws {
    let (h, _, _) = try Harness.replay(["NativeAuthIT.emptyPasswordRechallengesWithoutCountingAFailure"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password(""), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.first(.password)?.error?.code == ChallengeError.Code.missingCredential)
  }

  @Test func unknownUsernameRechallengesGenerically() async throws {
    let (h, _, t) = try Harness.replay(["NativeAuthIT.unknownUsernameRechallengesWithGenericError"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    let sent = try #require(t[0].form(2)["username"])
    step = try await flow.respond(.username(sent), to: try #require(step.challenges?.first(.username)))
    guard case .challenges(let set, let context) = step else { Issue.record("expected challenges"); return }
    #expect(set.types == ["username"] && set[0].error?.code == "invalid_credential")
    #expect(context.username == nil)
  }

  // MARK: - Sessions and errors (spec/03 §3.5)

  @Test func invalidAuthSessionValuesAreInvalidSession() throws {
    let t = try Transcript.load("NativeAuthIT.invalidAuthSessionValuesAreRejectedWithInvalidSession")
    for seq in [1, 3] {
      let error = #expect(throws: NativeAuthError.self) { try ChallengeEndpointClient.parse(t.exchange(seq).response.httpResponse) }
      #expect(error?.code == NativeAuthError.Code.invalidSession && error?.statusCode == 400)
      #expect(error?.authSession == nil, "no session to continue with")
    }
  }

  @Test func cancelInvalidatesTheSession() async throws {
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.cancelledAuthSessionCannotBeReused"], clientId: Self.demoIOS, range: 1...2)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    let step = try await flow.start()
    await flow.cancel()
    let v15 = await flow.currentState
    #expect(v15 == .finished)
    let v16 = await flow.authSession
    #expect(v16 == nil)
    #expect(transport.remaining == 0, "action=cancel was sent")
    let error = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.username("alice"), to: try #require(step.challenges?.first))
    }
    #expect(error?.code == NativeAuthError.Code.flowState)
  }

  @Test func expiredAuthSessionEndsTheFlow() async throws {
    let (h, _, _) = try Harness.replay(["NativeAuthIT.expiredAuthSessionIsRejectedWithInvalidSession"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    let step = try await flow.start()
    let v17 = await flow.expiresIn
    #expect(v17! <= 1)
    let error = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    }
    #expect(error?.code == NativeAuthError.Code.invalidSession)
    let v18 = await flow.currentState
    #expect(v18 == .finished)
    let v19 = await flow.authSession
    #expect(v19 == nil)
  }

  @Test func invalidRequestKeepsTheSession() async throws {
    let t = try Transcript.load("NativeAuthIT.unknownChallengeIdIsInvalidRequestAndSessionSurvives")
    for seq in [2, 3] {
      let error = #expect(throws: NativeAuthError.self) { try ChallengeEndpointClient.parse(t.exchange(seq).response.httpResponse) }
      #expect(error?.code == NativeAuthError.Code.invalidRequest)
      #expect(error?.authSessionStillValid == true, "a fresh auth_session is echoed")
    }
    // The SDK refuses to answer a challenge that is not pending before touching the network.
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.unknownChallengeIdIsInvalidRequestAndSessionSurvives"], clientId: Self.demoIOS, range: 1...1)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    _ = try await flow.start()
    let bogus = Challenge(id: "00000000-0000-0000-0000-000000000000", type: .username)
    let local = await #expect(throws: NativeAuthError.self) { try await flow.respond(.username("alice"), to: bogus) }
    #expect(local?.code == NativeAuthError.Code.flowState)
    let mismatch = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.password("x"), to: try #require(await flow.pendingChallenges.first))
    }
    #expect(mismatch?.code == NativeAuthError.Code.unsupportedChallenge)
    let stateAfter = await flow.currentState
    #expect(transport.remaining == 0 && stateAfter == .awaitingAnswer)
  }

  @Test func clientErrorsAreMapped() throws {
    let t = try Transcript.load("NativeAuthIT.missingOrUnknownClientIsRejected")
    let expected: [(Int, String, Int)] = [(1, "invalid_request", 400), (2, "invalid_client", 401), (3, "invalid_client", 401), (4, "invalid_request", 400)]
    for (seq, code, status) in expected {
      let error = #expect(throws: NativeAuthError.self) { try ChallengeEndpointClient.parse(t.exchange(seq).response.httpResponse) }
      #expect(error?.code == code && error?.statusCode == status, "exchange \(seq)")
    }
  }

  // MARK: - Brute force (S14)

  @Test func bruteForceLockEndsWithAccessDenied() async throws {
    let (h, transport, t) = try Harness.replay(["NativeAuthIT.bruteForceLockEndsWithAccessDenied"], clientId: Self.demoIOS)
    let attempts = t[0].exchanges.filter { $0.request.form?["challenge_type"] == "password" }.count
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("erin"), to: try #require(step.challenges?.first(.username)))
    var locked: NativeAuthError?
    for attempt in 1...attempts {
      let password = try #require(step.challenges?.first(.password))
      do {
        step = try await flow.respond(.password("wrong-password-\(attempt)"), to: password)
        #expect(step.challenges?.first(.password)?.error?.code == "invalid_credential")
      } catch let error as NativeAuthError {
        locked = error
        break
      }
    }
    #expect(locked?.code == NativeAuthError.Code.accessDenied)
    #expect(locked?.errorDescription?.lowercased().contains("locked") == true)
    let v21 = await flow.currentState
    #expect(v21 == .finished)

    // The locked account is not revealed on a new login.
    let second = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await second.start()
    step = try await second.respond(.username("erin"), to: try #require(step.challenges?.first(.username)))
    #expect(step.challenges?.types == ["username"] && step.challenges?.first?.error?.code == "invalid_credential")
    #expect(transport.remaining == 0)
  }

  // MARK: - Alternatives (spec/09 Q2, spec/11 D3)

  @Test func alternativesAreOfferedTogetherAndEitherCanBeAnswered() async throws {
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered"], clientId: Self.demoAlt)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let set = try #require(step.challenges)
    #expect(set.types == ["password", "totp"])
    #expect(set.allSatisfy { !$0.required })
    #expect(set[0].id != set[1].id)
    step = try await flow.respond(.totp("222222"), to: set[1])
    #expect(step.credentials != nil)

    // After a wrong TOTP the set keeps flow order with the error on the failed entry.
    let second = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await second.start()
    step = try await second.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await second.respond(.totp("333333"), to: try #require(step.challenges?.first(.totp)))
    let again = try #require(step.challenges)
    #expect(again.types == ["password", "totp"])
    #expect(again[1].error?.code == "invalid_credential" && again[0].error == nil)
    #expect(transport.remaining == 1, "the IT's final password answer is not exchanged for tokens")
  }

  @Test func alternativesAreFilteredByConfiguredCredentials() async throws {
    let (h, _, _) = try Harness.replay(["NativeAuthIT.q2_alternativesAreFilteredByConfiguredCredentials"], clientId: Self.demoAlt)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    #expect(step.challenges?.types == ["password"] && step.challenges?.first?.required == true)
  }

  // MARK: - Tokens (spec/09 Q1, spec/05 §2.2)

  @Test func pkceVerifierIsEnforcedByTheTokenEndpoint() async throws {
    let (h, _, _) = try Harness.replay(["NativeAuthIT.pkceVerifierIsEnforced"], clientId: Self.demoIOS)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let error = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.totp("444444"), to: try #require(step.challenges?.first(.totp)))
    }
    #expect(error?.code == NativeAuthError.Code.invalidGrant && error?.statusCode == 400)
  }

  @Test func sentinelRedirectUriModeSendsRedirectUriOnExchange() async throws {
    // Metadata recorded in sentinel mode + the round-trip login of the sibling test.
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.q1_sentinelModeRoundTrip"], clientId: Self.demoIOS, metadataFrom: "NativeAuthIT.q1_sentinelModeRejectsTokenRequestWithoutRedirectUri")
    let metadata = try await h.sdk.metadata()
    #expect(metadata.codeExchange.redirectUriRequired && metadata.codeExchange.redirectUri == "urn:keycloak:native-auth")
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("555555"), to: try #require(step.challenges?.first(.totp)))
    #expect(step.credentials != nil)
    #expect(transport.sent.last?.formFields?.contains { $0.name == "redirect_uri" && $0.value == "urn:keycloak:native-auth" } == true)
    #expect(transport.remaining == 0)
  }

  @Test func tokensCanBeRefreshedLoggedOutAndRevoked() async throws {
    let (h, transport, _) = try Harness.replay(["NativeAuthIT.tokensCanBeRefreshedLoggedOutAndRevoked"], clientId: Self.demoIOS)
    let tokens = h.sdk.tokens()
    let manager = h.sdk.credentialsManager()

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let credentials = try #require(step.credentials)

    // Expired credentials in the manager trigger exactly one refresh for concurrent callers.
    let expired = Credentials(
      accessToken: credentials.accessToken, refreshToken: credentials.refreshToken, idToken: credentials.idToken, scope: credentials.scope,
      expiresAt: Date().addingTimeInterval(-1), refreshExpiresAt: credentials.refreshExpiresAt, authSession: credentials.authSession)
    try await manager.store(expired)
    let v22 = try await manager.hasValid()
    #expect(v22 == false)
    async let a = manager.credentials()
    async let b = manager.credentials()
    let (ra, rb) = try await (a, b)
    #expect(ra == rb && ra.accessToken != expired.accessToken)
    #expect(ra.authSession == credentials.authSession, "the post-login auth_session survives a refresh")
    let v23 = try await manager.stored()
    #expect(v23 == ra)

    try await tokens.logout(refreshToken: try #require(ra.refreshToken))
    let afterLogout = await #expect(throws: NativeAuthError.self) { try await tokens.refresh(ra) }
    #expect(afterLogout?.code == NativeAuthError.Code.invalidGrant)

    let second = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await second.start()
    step = try await second.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await second.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let fresh = try #require(step.credentials)
    try await tokens.revoke(token: try #require(fresh.refreshToken))

    try await manager.store(fresh.withAuthSession(nil).expiredCopy())
    let viaManager = await #expect(throws: NativeAuthError.self) { try await manager.credentials() }
    #expect(viaManager?.code == NativeAuthError.Code.reauthenticationRequired)
    let v24 = try await manager.stored()
    #expect(v24 == nil, "revoked session: stored credentials are cleared")
    #expect(transport.remaining == 0)
  }

  // MARK: - Passkeys (spec/03 §4.3, §4.4, §6)

  @Test func allowListLoginAfterUsernameOffersPasskeyAndPassword() async throws {
    let (h, transport, t) = try Harness.replay(["PasskeyIT.allowListLoginAfterUsernameOffersPasskeyAndPassword"], clientId: Self.demoIOS, range: 1...5)
    let recorded = PasskeyAssertion(form: t[0].form(3))
    h.passkeys.enqueue(recorded)

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let set = try #require(step.challenges)
    #expect(set.types == ["passkey", "password"])
    let passkey = set[0]
    #expect(!passkey.required)
    let params = try #require(passkey.passkeyParams)
    #expect(params.rpId == "localhost" && params.userVerification == "required" && !params.discoverable)
    #expect(params.allowCredentials.contains { $0.id == recorded.credentialId })
    #expect(Set(params.allowCredentials.first { $0.id == recorded.credentialId }!.transports) == ["hybrid", "internal"])
    #expect(params.challengeData != nil)

    let assertion = try await h.sdk.passkeys().assert(params)
    #expect(h.passkeys.assertParams.first?.challenge == params.challenge)
    step = try await flow.respond(.passkey(assertion), to: passkey)
    #expect(step.challenges?.types == ["totp"])
    step = try await flow.respond(.totp("666666"), to: try #require(step.challenges?.first(.totp)))
    let credentials = try #require(step.credentials)
    #expect(credentials.authSession != nil, "post-login auth_session for step-up (Phase 2)")
    #expect(transport.remaining == 0)
  }

  @Test func discoverableLoginWithUserHandle() async throws {
    let (h, transport, t) = try Harness.replay(["PasskeyIT.discoverableLoginWithUserHandle"], clientId: Self.demoPasskey, range: 1...4)
    let recorded = PasskeyAssertion(form: t[0].form(2))
    #expect(recorded.userHandle != nil)
    h.passkeys.enqueue(recorded)

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected challenges"); return }
    #expect(set.types == ["passkey", "username"])
    #expect(context.username == nil)
    let params = try #require(set[0].passkeyParams)
    #expect(params.discoverable && params.allowCredentials.isEmpty)

    let assertion = try await h.sdk.passkeys().assert(params, preferImmediatelyAvailableCredentials: true)
    #expect(h.passkeys.preferImmediatelyAvailable == [true])
    step = try await flow.respond(.passkey(assertion), to: set[0])
    guard case .challenges(let next, let identified) = step else { Issue.record("expected totp"); return }
    #expect(next.types == ["totp"] && identified.username == "alice")
    step = try await flow.respond(.totp("777777"), to: next[0])
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(transport.remaining == 0)
  }

  @Test func wrongSignatureRechallengesWithFreshChallenge() async throws {
    let (h, _, t) = try Harness.replay(["PasskeyIT.wrongSignatureRechallengesWithInvalidCredential"], clientId: Self.demoIOS)
    for seq in [3, 4, 5] { h.passkeys.enqueue(PasskeyAssertion(form: t[0].form(seq))) }
    let passkeys = h.sdk.passkeys()

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let first = try #require(step.challenges?.first(.passkey))
    let challenge = try #require(first.passkeyParams).challenge

    step = try await flow.respond(.passkey(try await passkeys.assert(first.passkeyParams!)), to: first)
    let again = try #require(step.challenges?.first(.passkey))
    #expect(again.error?.code == "invalid_credential")
    #expect(again.passkeyParams?.challenge != challenge, "a new challenge is issued after a failed attempt")
    #expect(step.challenges?.first?.type == .passkey)

    step = try await flow.respond(.passkey(try await passkeys.assert(again.passkeyParams!)), to: again)
    let third = try #require(step.challenges?.first(.passkey))
    #expect(third.error?.code == "invalid_credential", "replaying the old challenge value fails")
    step = try await flow.respond(.passkey(try await passkeys.assert(third.passkeyParams!)), to: third)
    #expect(step.challenges?.types == ["totp"])
  }

  @Test func missingAssertionFieldsAreMissingCredential() throws {
    let t = try Transcript.load("PasskeyIT.missingAssertionFieldsRechallengeWithoutCountingAFailure")
    guard case .challenges(let set) = try ChallengeEndpointClient.parse(t.exchange(3).response.httpResponse) else { Issue.record("expected challenges"); return }
    #expect(set.challenges.first(.passkey)?.error?.code == ChallengeError.Code.missingCredential)
  }

  @Test func registerThroughAuthenticatedEndpointsAfterLogin() async throws {
    let (h, transport, t) = try Harness.replay(["PasskeyIT.registerThroughAuthenticatedEndpointsAfterPasswordTotpLogin"], clientId: Self.demoIOS)
    let recorded = PasskeyAttestation(json: t[0].exchange(7).request.json!)
    h.passkeys.enqueue(recorded)

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("888888"), to: try #require(step.challenges?.first(.totp)))
    let credentials = try #require(step.credentials)

    let registered = try await h.sdk.passkeys().registerNewPasskey(label: "Second device", credentials: credentials)
    #expect(registered.credentialId == recorded.credentialId && registered.label == "Second device")
    let options = try #require(h.passkeys.registerParams.first)
    #expect(options.rp.id == "localhost" && options.rp.name == "Native Auth Demo")
    #expect(options.user.name == "alice" && options.user.displayName == "Alice Example")
    #expect(options.pubKeyCredParams == [-7, -257])
    #expect(options.userVerification == "required" && options.residentKey == "required" && options.attestation == "none")
    #expect(options.timeoutMilliseconds == 60000)
    let finishRequest = transport.sent.last!
    #expect(finishRequest.header("Authorization")?.hasPrefix("Bearer ") == true)
    #expect(finishRequest.header("Content-Type") == "application/json")

    // registration_id is single use.
    let registration = PasskeyRegistrationClient(issuer: h.sdk.issuer, metadata: h.sdk.metadataClient, transport: h.sdk.transport, dpop: h.sdk.dpopSigner)
    let replay = await #expect(throws: NativeAuthError.self) {
      try await registration.finish(credentials: credentials, registrationId: t[0].exchange(7).request.json!["registration_id"]!.stringValue!, attestation: recorded, label: "Second device")
    }
    #expect(replay?.code == NativeAuthError.Code.invalidRequest && replay?.statusCode == 400)
    #expect(transport.remaining == 0)
  }

  @Test func registrationEndpointsRequireAValidToken() async throws {
    let t = try Transcript.load("PasskeyIT.registrationEndpointsRequireABearerToken")
    let metadata = try Transcript.load("NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath")
    let transport = MockTransport([metadata.exchange(1), t.exchange(2)])
    let h = Harness(issuer: metadata.issuer, clientId: Self.demoIOS, transport: transport)
    let garbage = Credentials(accessToken: "not-a-token", refreshToken: nil, idToken: nil, scope: nil, expiresAt: .distantFuture, refreshExpiresAt: nil, authSession: nil)
    let error = await #expect(throws: NativeAuthError.self) { try await h.sdk.passkeys().registerNewPasskey(label: nil, credentials: garbage) }
    #expect(error?.code == NativeAuthError.Code.invalidToken && error?.statusCode == 401)
  }

  @Test func requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks() async throws {
    let (h, transport, t) = try Harness.replay(["PasskeyIT.requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks"], clientId: Self.demoIOS)
    h.passkeys.enqueue(PasskeyAttestation(form: t[0].form(4)))  // the bad one (wrong RP ID)
    h.passkeys.enqueue(PasskeyAttestation(form: t[0].form(5)))
    h.passkeys.enqueue(PasskeyAssertion(form: t[0].form(9)))
    let passkeys = h.sdk.passkeys()

    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    #expect(step.challenges?.types == ["password"], "no passkey yet")
    step = try await flow.respond(.password("dave-password"), to: try #require(step.challenges?.first(.password)))
    guard case .challenges(let set, let context) = step else { Issue.record("expected registration"); return }
    #expect(set.types == ["passkey_registration"] && set[0].required && set[0].id == "native-passkey-register")
    #expect(context.username == "dave")
    let params = try #require(set[0].passkeyRegistrationParams)
    #expect(params.user.name == "dave" && params.rp.id == "localhost")
    let v25 = await flow.expiresIn
    #expect(v25! > 0)

    step = try await flow.respond(.passkeyRegistration(try await passkeys.register(params), label: nil), to: set[0])
    let again = try #require(step.challenges?.first(.passkeyRegistration))
    #expect(again.error?.code == ChallengeError.Code.invalidAttestation)
    #expect(again.passkeyRegistrationParams?.challenge != params.challenge)

    step = try await flow.respond(.passkeyRegistration(try await passkeys.register(again.passkeyRegistrationParams!), label: "Dave's phone"), to: again)
    let credentials = try #require(step.credentials)
    #expect(credentials.authSession != nil)

    // Next login: the passkey is offered and the action is gone.
    let second = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await second.start()
    step = try await second.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    let offered = try #require(step.challenges)
    #expect(offered.types == ["passkey", "password"])
    step = try await second.respond(.passkey(try await passkeys.assert(offered[0].passkeyParams!)), to: offered[0])
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "dave")
    #expect(transport.remaining == 0)
  }
}

extension Credentials {
  func expiredCopy() -> Credentials {
    Credentials(accessToken: accessToken, tokenType: tokenType, refreshToken: refreshToken, idToken: idToken, scope: scope, expiresAt: Date().addingTimeInterval(-1), refreshExpiresAt: refreshExpiresAt, issuedAt: issuedAt, authSession: authSession)
  }
}
