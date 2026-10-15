import Foundation
import Testing
@testable import KeycloakNativeCore
@testable import KeycloakNativePush

/// Phase 3 contract tests (spec/14 D9, D10): push MFA replayed from the transcripts of PushMfaIT —
/// in-app enrolment through `/native-auth/push/enroll/start` + `/push-mfa/enroll/complete`, the
/// `push` challenge with number match (spec/03 §4.7), the device side of the ba-itsys API
/// (spec/03 §7) with the DPoP key as device key (§7.1), `push_enrollment` mid-flow (§4.15) and
/// the maintenance calls.
@Suite(.serialized) struct Phase3ReplayTests {
  static let client = TranscriptReplayTests.demoIOS
  static let itParameters = TranscriptReplayTests.itParameters
  static let enrolTranscript = "PushMfaIT.aliceEnrolsHerDeviceFromInsideTheApp"

  /// alice as the IT enrolled her: the harness' DPoP key plays the device key, the device API is
  /// called with a DPoP-bound token (the transcript only checks the scheme).
  /// alice's Keycloak user id of the recording (a fresh container per `mvn verify`).
  static func aliceUserId() throws -> String {
    try #require(try Transcript.load(enrolTranscript).exchange(7).response.json?["user_id"]?.stringValue)
  }

  func enrolledAlice(_ h: Harness) async throws -> Push {
    _ = try await h.sdk.metadata()  // the harness queues the metadata exchange first
    let push = h.sdk.push(tokenProvider: StaticDeviceTokenProvider(DeviceToken(accessToken: "alice.native.token", scheme: "DPoP")))
    let key = try await h.sdk.dpopKey()
    try push.store(
      PushEnrollment(
        credentialId: "cred-alice-test", deviceId: "device-alice-test", userId: try Self.aliceUserId(), username: "alice",
        deviceLabel: "Alice's test iPhone", pushProviderType: "apns", pushProviderId: "0123", deviceApiBase: h.sdk.issuer.appending(path: "push-mfa"),
        keyThumbprint: key.publicJWK.thumbprint))
    return push
  }

  @Test func metadataCarriesThePushBlock() async throws {
    let (h, _, _) = try Harness.replay([], clientId: Self.client, metadataFrom: Self.enrolTranscript)
    let metadata = try await h.sdk.metadata()
    let push = try #require(metadata.push)
    #expect(push.enabled && push.deviceToken == "native" && push.deviceClientId == nil)
    #expect(push.enrollStartEndpoint == h.sdk.issuer.appending(path: "native-auth/push/enroll/start"))
    #expect(push.deviceApiBase == h.sdk.issuer.appending(path: "push-mfa"))
    #expect(push.pushProviderTypes.contains("apns") && push.pushProviderTypes.contains("none"))
    #expect(metadata.supports(.push) && metadata.supports(.pushEnrollment))
    #expect(ChallengeType.push.isSupported && ChallengeType.pushEnrollment.isRequiredAction)
  }

  @Test func aliceEnrolsHerDeviceFromInsideTheApp() async throws {
    let (h, transport, t) = try Harness.replay([Self.enrolTranscript], clientId: Self.client, metadataFrom: Self.enrolTranscript, range: 2...8)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    let credentials = try #require(step.credentials)
    #expect(credentials.isDPoPBound)
    try await h.sdk.credentialsManager().store(credentials)

    let push = h.sdk.push()
    #expect(!push.isEnrolled)
    let enrollment = try await push.enroll(deviceLabel: "Alice's test iPhone", pushProviderType: "apns", pushProviderId: "0123456789abcdef")
    #expect(transport.remaining == 0)
    #expect(push.isEnrolled && push.enrollment == enrollment)
    #expect(enrollment.userId == (try Self.aliceUserId()) && enrollment.username == "alice")
    #expect(enrollment.deviceApiBase.absoluteString == t[0].exchange(7).response.json?["device_api_base"]?.stringValue)
    #expect(enrollment.keyThumbprint == (try await h.sdk.dpopKeyThumbprint()))
    #expect(enrollment.pushProviderType == "apns" && enrollment.pushProviderId == "0123456789abcdef")

    // The device JWT carried the DPoP key and the recorded claims (spec/03 §7).
    let complete = try #require(transport.sent.last)
    #expect(complete.url.path.hasSuffix("/push-mfa/enroll/complete") && complete.header("Authorization")?.hasPrefix("DPoP ") == true)
    let proofHeader = try #require(complete.header("DPoP"))
    let proof = try #require(JWT.decodePayload(proofHeader))
    #expect(proof["sub"]?.stringValue == enrollment.userId && proof["deviceId"]?.stringValue == enrollment.deviceId && proof["ath"] != nil)
    let completeBody = try #require(complete.body)
    let deviceJWT = try #require(JSONValue(jsonData: completeBody)?["token"]?.stringValue)
    let claims = try #require(JWT.decodePayload(deviceJWT))
    let recordedToken = try #require(t[0].exchange(7).response.json?["enrollment_token"]?.stringValue)
    let recorded = try #require(JWT.decodePayload(recordedToken))
    #expect(claims["enrollmentId"] == recorded["enrollmentId"] && claims["nonce"] == recorded["nonce"] && claims["sub"] == recorded["sub"])
    #expect(claims["cnf"]?["jwk"]?["x"] == (try await h.sdk.dpopKey()).publicJWK.jsonValue["x"])
    #expect(claims["pushProviderType"]?.stringValue == "apns" && claims["deviceType"]?.stringValue == "ios" && claims["credentialId"]?.stringValue == enrollment.credentialId)

    // Neither the enrolment token nor the device JWT nor the APNs token reach the flow log.
    let log = h.observer.entries.map { ($0.requestBody ?? "") + ($0.responseBody ?? "") + $0.requestHeaders.values.joined() }.joined()
    #expect(!log.contains(deviceJWT) && !log.contains("0123456789abcdef"))
    #expect(!log.contains(recordedToken))
  }

  @Test func scenarioA_theDeviceListsAndApprovesABrowserLogin() async throws {
    let (h, transport, t) = try Harness.replay(["PushMfaIT.scenarioA_aBrowserLoginIsApprovedOnTheEnrolledDevice"], clientId: Self.client, metadataFrom: Self.enrolTranscript)
    let push = try await enrolledAlice(h)
    let pending = try await push.pendingApprovals()
    #expect(pending.count == 1)
    let approval = try #require(pending.first)
    #expect(approval.clientId == "web-app" && approval.username == "alice" && approval.numbers.isEmpty && !approval.requiresPin)
    #expect(approval.cid == t[0].exchange(1).response.json?["challenges"]?[0]?["cid"]?.stringValue)
    let status = try await push.respond(to: approval, .approve())
    #expect(status == "approved" && transport.remaining == 0)
    let respond = try #require(transport.sent.last)
    let respondBody = try #require(respond.body)
    let respondJWT = try #require(JSONValue(jsonData: respondBody)?["token"]?.stringValue)
    let claims = try #require(JWT.decodePayload(respondJWT))
    #expect(claims["cid"]?.stringValue == approval.cid && claims["action"]?.stringValue == "approve" && claims["credId"]?.stringValue == "cred-alice-test" && claims["userVerification"] == nil)
    let pendingRequest = transport.sent[1]  // [0] is the metadata fetch
    let query = URLComponents(url: pendingRequest.url, resolvingAgainstBaseURL: false)?.queryItems ?? []
    #expect(query.contains { $0.name == "userId" && $0.value == (try? Self.aliceUserId()) })
  }

  @Test func scenarioB_nativeLoginWithPushAndNumberMatch() async throws {
    let (h, transport, _) = try Harness.replay(["PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch"], clientId: Self.client, metadataFrom: Self.enrolTranscript)
    let push = try await enrolledAlice(h)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.types == ["totp", "push"])
    var challenge = try #require(step.challenges?.first(.push))
    var params = try #require(challenge.pushParams)
    #expect(!params.sent && params.cid == nil && params.devices == ["Alice's test iPhone"] && params.pollInterval == 3 && !params.isPending)

    step = try await flow.respond(.pushResend, to: challenge)
    challenge = try #require(step.challenges?.first(.push))
    params = try #require(challenge.pushParams)
    #expect(params.sent && params.status == .pending && params.isPending && params.cid != nil && params.expiresAt != nil)
    let number = try #require(params.userVerificationNumber)

    step = try await flow.respond(.pushPoll, to: challenge)
    challenge = try #require(step.challenges?.first(.push))
    #expect(challenge.pushParams?.status == .pending && challenge.error == nil)

    // The phone: three numbers, a wrong pick is refused, the right one approves.
    let pendingList = try await push.pendingApprovals()
    let approval = try #require(pendingList.first)
    #expect(approval.cid == params.cid && approval.numbers.count == 3 && approval.numbers.contains(number))
    let wrong = try #require(approval.numbers.first { $0 != number })
    await #expect(throws: NativeAuthError.self) { try await push.respond(to: approval, .approve(userVerification: wrong)) }
    #expect(try await push.respond(to: approval, .approve(userVerification: number)) == "approved")

    step = try await flow.respond(.pushPoll, to: challenge)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(transport.remaining == 0)
  }

  @Test func scenarioB_aDeniedPushIsAnErrorAndResendIsRateLimited() async throws {
    let (h, transport, _) = try Harness.replay(["PushMfaIT.scenarioB_aDeniedPushIsAFailureAndTheAlternativeStillWorks"], clientId: Self.client, metadataFrom: Self.enrolTranscript, range: 1...7)
    let push = try await enrolledAlice(h)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.pushResend, to: try #require(step.challenges?.first(.push)))
    let sent = try #require(step.challenges?.first(.push))
    let cid = try #require(sent.pushParams?.cid)
    #expect(try await push.respond(cid: cid, .deny) == "denied")

    step = try await flow.respond(.pushPoll, to: sent)
    let denied = try #require(step.challenges?.first(.push))
    #expect(denied.error?.code == ChallengeError.Code.denied)
    #expect(denied.pushParams?.sent == false && denied.pushParams?.isPending == false && denied.pushParams?.resendAllowedAt != nil)
    step = try await flow.respond(.pushResend, to: denied)
    let tooSoon = try #require(step.challenges?.first(.push))
    #expect(tooSoon.error?.code == ChallengeError.Code.resendTooSoon)
    #expect(step.challenges?.first(.totp) != nil, "the other alternative stays")
    #expect(transport.remaining == 0)
  }

  @Test func judyEnrolsMidFlowAndIsThenAskedForPush() async throws {
    let (h, transport, t) = try Harness.replay(["PushMfaIT.judyEnrolsMidFlowThroughTheNativeRequiredAction"], clientId: Self.client, metadataFrom: Self.enrolTranscript)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("judy"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("judy-password"), to: try #require(step.challenges?.first(.password)))
    let challenge = try #require(step.challenges?.first(.pushEnrollment))
    #expect(step.challenges?.count == 1 && challenge.required && challenge.id == "native-push-enroll")
    let params = try #require(challenge.pushEnrollmentParams)
    #expect(params.deviceApiBase == h.sdk.issuer.appending(path: "push-mfa") && params.expiresIn ?? 0 > 0)
    #expect(params.enrollmentClaims?["username"]?.stringValue == "judy" && params.userId == params.enrollmentClaims?["sub"]?.stringValue)

    // A JWT signed by another key than the session's DPoP key is refused (spec/03 §4.15) and the
    // re-challenge keeps the pending enrolment.
    let claims = try #require(params.enrollmentClaims)
    let otherKey = SoftwareDPoPKey()
    let wrongJWT = try DeviceJWT.sign(["sub": claims["sub"]!, "enrollmentId": claims["enrollmentId"]!, "nonce": claims["nonce"]!, "exp": 1_900_000_000, "cnf": ["jwk": otherKey.publicJWK.jsonValue], "credentialId": "c", "deviceId": "d", "deviceType": "ios", "deviceLabel": "x", "pushProviderType": "none"], with: otherKey)
    step = try await flow.respond(.pushEnrollment(token: wrongJWT), to: challenge)
    let refused = try #require(step.challenges?.first(.pushEnrollment))
    #expect(refused.error?.code == ChallengeError.Code.invalidCredential)
    let again = try #require(refused.pushEnrollmentParams)
    #expect(again.enrollmentClaims?["enrollmentId"] == claims["enrollmentId"], "the pending challenge is kept")

    let push = h.sdk.push()
    let prepared = try await push.prepareEnrollment(for: again, deviceLabel: "Judy's phone")
    #expect(prepared.enrollment.username == "judy" && prepared.enrollment.pushProviderType == "none" && !push.isEnrolled)
    step = try await flow.respond(prepared.answer, to: refused)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "judy")
    try push.commit(prepared)
    #expect(push.enrollment?.credentialId == prepared.enrollment.credentialId)
    // The in-flow answer: a form field `token` (masked in the transcript), never logged.
    let answerRequest = transport.sent[5]
    #expect(answerRequest.formFields?.contains { $0.name == "token" && $0.value.hasPrefix("eyJ") } == true)
    #expect(!h.observer.entries.compactMap(\.requestBody).joined().contains("eyJ0eXAiOiJKV1Qi"), "the device JWT is masked in the flow log")

    // Next login: push is the single second factor and is sent at once (spec/03 §4.7).
    let secondLogin = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await secondLogin.start()
    step = try await secondLogin.respond(.username("judy"), to: try #require(step.challenges?.first(.username)))
    step = try await secondLogin.respond(.password("judy-password"), to: try #require(step.challenges?.first(.password)))
    let pushChallenge = try #require(step.challenges?.first(.push))
    #expect(step.challenges?.count == 1 && pushChallenge.pushParams?.sent == true && pushChallenge.pushParams?.cid != nil)
    #expect(pushChallenge.pushParams?.devices == ["Judy's phone"])
    #expect(transport.remaining == 0)
    _ = t
  }

  @Test func aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout() async throws {
    let (h, transport, _) = try Harness.replay(["PushMfaIT.aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout"], clientId: Self.client, metadataFrom: Self.enrolTranscript, seqs: [1, 3, 5, 6, 7, 8, 9, 10, 11])
    var push = try await enrolledAlice(h)
    let before = try await h.sdk.dpopKeyThumbprint()

    // 1. A new APNs token (the recorded one): one PUT; the same token again is a no-op locally.
    let recordedHex = try #require(Transcript.load("PushMfaIT.aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout").exchange(1).request.json?["pushProviderId"]?.stringValue)
    let token = Data(stride(from: 0, to: recordedHex.count, by: 2).map { i -> UInt8 in
      let start = recordedHex.index(recordedHex.startIndex, offsetBy: i)
      return UInt8(recordedHex[start..<recordedHex.index(start, offsetBy: 2)], radix: 16)!
    })
    try await push.updateAPNsToken(token)
    #expect(push.enrollment?.pushProviderId == recordedHex)
    try await push.updateAPNsToken(token)
    #expect(transport.sent.count == 2, "unchanged token: no request ([0] is the metadata fetch)")

    // 2. Key rotation: proof by the old key, body with the new JWK; afterwards the DPoP key changed
    // and the stored credentials are gone (they were bound to the old key).
    let credentials = Credentials(accessToken: "old", tokenType: "DPoP", refreshToken: "r", idToken: nil, scope: nil, expiresAt: Date().addingTimeInterval(300), refreshExpiresAt: nil, issuedAt: Date(), authSession: nil)
    try await h.sdk.credentialsManager().store(credentials)
    try await push.rotateKey()
    let after = try await h.sdk.dpopKeyThumbprint()
    #expect(after != before && push.enrollment?.keyThumbprint == after)
    #expect(try await h.sdk.credentialsManager().stored() == nil)
    let rotate = transport.sent[2]
    #expect(rotate.method == "PUT" && rotate.url.path.hasSuffix("/device/rotate-key"))
    let rotateBody = try #require(rotate.body)
    let body = try #require(JSONValue(jsonData: rotateBody))
    #expect(body["publicKeyJwk"]?["alg"]?.stringValue == "ES256" && body["publicKeyJwk"]?["crv"]?.stringValue == "P-256")
    let rotateProof = try #require(rotate.header("DPoP"))
    let proofKey = try #require(JWT.decodeHeader(rotateProof)?["jwk"])
    #expect(proofKey["x"] != body["publicKeyJwk"]?["x"], "the proof is signed by the old key")

    // 3. A new DPoP-bound login binds tokens to the new key; the device API works again.
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    try await h.sdk.credentialsManager().store(try #require(step.credentials))
    push = h.sdk.push()
    #expect(try await push.pendingApprovals().isEmpty)

    // 4. Panic button.
    try await push.lockout()
    #expect(transport.sent.last?.url.path.hasSuffix("/login/lockout") == true && transport.remaining == 0)
  }

  @Test func answersAndParamsOfPhase3() throws {
    #expect(ChallengeAnswer.pushResend.formFields.map { "\($0.name)=\($0.value)" } == ["action=resend"])
    #expect(ChallengeAnswer.pushPoll.formFields.map { "\($0.name)=\($0.value)" } == ["action=poll"])
    #expect(ChallengeAnswer.pushEnrollment(token: "t").formFields.map { "\($0.name)=\($0.value)" } == ["token=t"])
    #expect(ChallengeAnswer.pushEnrollmentCheck.formFields.map { "\($0.name)=\($0.value)" } == ["action=check"])
    #expect(ChallengeAnswer.pushPoll.challengeType == .push && ChallengeAnswer.pushEnrollmentCheck.challengeType == .pushEnrollment)
    let params = PushParams(json: ["sent": true, "cid": "c", "expires_at": 1_800_000_000, "poll_interval": 5, "status": "pending", "user_verification": ["type": "number_match", "number": "42"], "devices": [["label": "A"], ["label": "B"]]])
    #expect(params.isPending && params.userVerificationNumber == "42" && params.devices == ["A", "B"] && params.pollInterval == 5)
    let pin = PushParams(json: ["sent": true, "status": "approved", "user_verification": ["type": "pin"]])
    #expect(!pin.isPending && pin.userVerificationNumber == nil && pin.pollInterval == 3)
    let payload = try #require(PushNotificationPayload(userInfo: ["confirmToken": "eyJhbGciOiJub25lIn0." + Base64URL.encode(Data("{\"cid\":\"c1\",\"credId\":\"k1\",\"exp\":1800000000}".utf8)) + ".", "aps": ["alert": "x"]]))
    #expect(payload.cid == "c1" && payload.credentialId == "k1" && payload.expiresAt != nil)
    #expect(PushNotificationPayload(userInfo: ["aps": ["alert": "x"]]) == nil)
  }
}
