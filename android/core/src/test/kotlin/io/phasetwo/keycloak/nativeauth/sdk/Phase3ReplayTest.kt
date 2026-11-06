package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeError
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PushParams
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DeviceJwt
import io.phasetwo.keycloak.nativeauth.sdk.dpop.SoftwareDPoPKey
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.push.DeviceToken
import io.phasetwo.keycloak.nativeauth.sdk.push.NativeDeviceTokenProvider
import io.phasetwo.keycloak.nativeauth.sdk.push.Push
import io.phasetwo.keycloak.nativeauth.sdk.push.PushApprovalAction
import io.phasetwo.keycloak.nativeauth.sdk.push.PushEnrollment
import io.phasetwo.keycloak.nativeauth.sdk.push.PushNotificationPayload
import io.phasetwo.keycloak.nativeauth.sdk.push.StaticDeviceTokenProvider
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.first
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import java.net.URI
import java.time.Instant
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 3 contract tests (spec/14 D9, D10): push MFA replayed from the transcripts of PushMfaIT and
 * FcmPushIT: in-app enrolment through `/native-auth/push/enroll/start` + `/push-mfa/enroll/complete`,
 * the `push` challenge with number match (spec/03 §4.7), the device side of the ba-itsys API
 * (spec/03 §7) with the DPoP key as device key (§7.1), `push_enrollment` mid-flow (§4.15), the
 * maintenance calls, and the FCM message and token refresh. Twin of `Phase3ReplayTests.swift` plus
 * the FcmPushIT cases.
 */
class Phase3ReplayTest {
  private val client = TranscriptReplayTest.DEMO
  private val itParameters = TranscriptReplayTest.IT_PARAMETERS
  private val enrolTranscript = "PushMfaIT.aliceEnrolsHerDeviceFromInsideTheApp"
  private val fcmEnrolTranscript = "FcmPushIT.aliceEnrolsHerAndroidPhone"

  /** alice's Keycloak user id of the recording (a fresh container per `mvn verify`). */
  private fun userIdOf(transcript: String): String = Transcript.load(transcript).exchange(7).response.json["user_id"].stringValue.req()

  private fun issuerPath(h: Harness, path: String): URI = URI.create("${h.sdk.issuer}/$path")

  /**
   * alice as the IT enrolled her: the harness' DPoP key plays the device key, the device API is called
   * with a DPoP-bound token (the transcript only checks the scheme).
   */
  private suspend fun enrolledAlice(h: Harness, transcript: String = enrolTranscript, provider: String = "fcm"): Push {
    h.sdk.metadata()  // the harness queues the metadata exchange first
    val push = h.sdk.push(StaticDeviceTokenProvider(DeviceToken("alice.native.token", "DPoP")))
    val key = h.sdk.dpopKey()
    push.store(
      PushEnrollment(
        credentialId = "cred-alice-test", deviceId = "device-alice-test", userId = userIdOf(transcript), username = "alice",
        deviceLabel = "Alice's test Pixel", pushProviderType = provider, pushProviderId = "0123", deviceApiBase = issuerPath(h, "push-mfa"),
        keyThumbprint = key.publicJwk.thumbprint,
      ),
    )
    return push
  }

  private suspend fun NativeLoginFlow.toSecondFactor(username: String, password: String): FlowStep {
    var step = start()
    step = respond(ChallengeAnswer.Username(username), step.require(ChallengeType.Username))
    return respond(ChallengeAnswer.Password(password), step.require(ChallengeType.Password))
  }

  private fun bodyJson(body: ByteArray?): JsonElement? = body?.let(::parseJsonOrNull)

  @Test
  fun metadataCarriesThePushBlock() = runTest {
    val (h, _, _) = Harness.replay(emptyList(), client, metadataFrom = enrolTranscript)
    val metadata = h.sdk.metadata()
    val push = metadata.push.req()
    assertTrue(push.enabled && push.deviceToken == "native" && push.deviceClientId == null)
    assertEquals(issuerPath(h, "native-auth/push/enroll/start"), push.enrollStartEndpoint)
    assertEquals(issuerPath(h, "push-mfa"), push.deviceApiBase)
    assertTrue(push.pushProviderTypes.containsAll(listOf("apns", "fcm", "none")))
    assertTrue(metadata.supports(ChallengeType.Push) && metadata.supports(ChallengeType.PushEnrollment))
    assertTrue(ChallengeType.Push.isSupported && ChallengeType.PushEnrollment.isRequiredAction)
  }

  @Test
  fun aliceEnrolsHerDeviceFromInsideTheApp() = runTest {
    val (h, transport, t) = Harness.replay(listOf(enrolTranscript), client, metadataFrom = enrolTranscript, range = 2..8)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    val credentials = step.credentials.req()
    assertTrue(credentials.isDPoPBound)
    h.sdk.credentialsManager().store(credentials)

    val push = h.sdk.push()
    assertFalse(push.isEnrolled())
    val enrollment = push.enroll("Alice's test Pixel", "fcm", "fcm-registration-token-0123")
    assertEquals(0, transport.remaining)
    assertEquals(enrollment, push.enrollment())
    assertEquals(userIdOf(enrolTranscript), enrollment.userId)
    assertEquals("alice", enrollment.username)
    assertEquals(t[0].exchange(7).response.json["device_api_base"].stringValue, enrollment.deviceApiBase.toString())
    assertEquals(h.sdk.dpopKeyThumbprint(), enrollment.keyThumbprint)
    assertEquals("fcm" to "fcm-registration-token-0123", enrollment.pushProviderType to enrollment.pushProviderId)

    // The device JWT carried the DPoP key and the recorded claims (spec/03 §7).
    val complete = transport.sent.last()
    assertTrue(complete.url.path.endsWith("/push-mfa/enroll/complete") && complete.header("Authorization").orEmpty().startsWith("DPoP "))
    val proof = Jwt.decodePayload(complete.header("DPoP").req())
    assertEquals(enrollment.userId, proof["sub"].stringValue)
    assertEquals(enrollment.deviceId, proof["deviceId"].stringValue)
    assertNotNull(proof["ath"])
    val deviceJwt = bodyJson(complete.body)["token"].stringValue.req()
    val claims = Jwt.decodePayload(deviceJwt)
    val recordedToken = t[0].exchange(7).response.json["enrollment_token"].stringValue.req()
    val recorded = Jwt.decodePayload(recordedToken)
    for (claim in listOf("enrollmentId", "nonce", "sub")) assertEquals(recorded[claim], claims[claim], claim)
    assertEquals(h.sdk.dpopKey().publicJwk.x, claims["cnf"]["jwk"]["x"].stringValue)
    assertEquals("fcm", claims["pushProviderType"].stringValue)
    assertEquals("android", claims["deviceType"].stringValue)
    assertEquals(enrollment.credentialId, claims["credentialId"].stringValue)
    assertEquals("fcm-registration-token-0123", claims["pushProviderId"].stringValue)

    // Neither the enrolment token nor the device JWT nor the push token reach the flow log.
    val log = h.observer.entries.joinToString { (it.requestBody ?: "") + (it.responseBody ?: "") + it.requestHeaders.values.joinToString() }
    assertFalse(log.contains(deviceJwt) || log.contains("fcm-registration-token-0123") || log.contains(recordedToken))
  }

  @Test
  fun scenarioA_theDeviceListsAndApprovesABrowserLogin() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PushMfaIT.scenarioA_aBrowserLoginIsApprovedOnTheEnrolledDevice"), client, metadataFrom = enrolTranscript)
    val push = enrolledAlice(h)
    val pending = push.pendingApprovals()
    assertEquals(1, pending.size)
    val approval = pending.first()
    assertEquals("web-app", approval.clientId)
    assertEquals("alice", approval.username)
    assertTrue(approval.numbers.isEmpty() && !approval.requiresPin)
    assertEquals(t[0].exchange(1).response.json["challenges"][0]["cid"].stringValue, approval.cid)
    assertEquals("approved", push.respond(approval, PushApprovalAction.Approve()))
    assertEquals(0, transport.remaining)
    val claims = Jwt.decodePayload(bodyJson(transport.sent.last().body)["token"].stringValue.req())
    assertEquals(approval.cid, claims["cid"].stringValue)
    assertEquals("approve", claims["action"].stringValue)
    assertEquals("cred-alice-test", claims["credId"].stringValue)
    assertNull(claims["userVerification"])
    val pendingRequest = transport.sent[1]  // [0] is the metadata fetch
    assertEquals("userId=${userIdOf(enrolTranscript)}", pendingRequest.url.rawQuery)
  }

  @Test
  fun scenarioB_nativeLoginWithPushAndNumberMatch() = runTest {
    val (h, transport, _) = Harness.replay(listOf("PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch"), client, metadataFrom = enrolTranscript)
    val push = enrolledAlice(h)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    assertEquals(listOf("totp", "push"), step.challenges.req().types())
    var challenge = step.require(ChallengeType.Push)
    var params = challenge.pushParams.req()
    assertTrue(!params.sent && params.cid == null && params.devices.size == 1 && params.pollInterval == 3 && !params.isPending)

    step = flow.respond(ChallengeAnswer.PushResend, challenge)
    challenge = step.require(ChallengeType.Push)
    params = challenge.pushParams.req()
    assertTrue(params.sent && params.status == PushParams.Status.PENDING && params.isPending && params.cid != null && params.expiresAt != null)
    val number = params.userVerificationNumber.req()

    step = flow.respond(ChallengeAnswer.PushPoll, challenge)
    challenge = step.require(ChallengeType.Push)
    assertEquals(PushParams.Status.PENDING, challenge.pushParams?.status)
    assertNull(challenge.error)

    // The phone: three numbers, a wrong pick is refused, the right one approves.
    val approval = push.pendingApprovals().first()
    assertEquals(params.cid, approval.cid)
    assertTrue(approval.numbers.size == 3 && number in approval.numbers)
    val wrong = approval.numbers.first { it != number }
    val mismatch = expectError { push.respond(approval, PushApprovalAction.Approve(wrong)) }
    assertEquals(NativeAuthError.Code.USER_VERIFICATION_MISMATCH, mismatch.code)
    assertEquals("User verification mismatch", mismatch.errorDescription)
    assertEquals("approved", push.respond(approval, PushApprovalAction.Approve(number)))

    step = flow.respond(ChallengeAnswer.PushPoll, challenge)
    assertEquals("alice", step.credentials.req().username)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun scenarioB_aDeniedPushIsAnErrorAndResendIsRateLimited() = runTest {
    val (h, transport, _) =
      Harness.replay(listOf("PushMfaIT.scenarioB_aDeniedPushIsAFailureAndTheAlternativeStillWorks"), client, metadataFrom = enrolTranscript, range = 1..7)
    val push = enrolledAlice(h)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.PushResend, step.require(ChallengeType.Push))
    val sent = step.require(ChallengeType.Push)
    assertEquals("denied", push.respond(sent.pushParams?.cid.req(), PushApprovalAction.Deny))

    step = flow.respond(ChallengeAnswer.PushPoll, sent)
    val denied = step.require(ChallengeType.Push)
    assertEquals(ChallengeError.Code.DENIED, denied.error?.code)
    assertTrue(denied.pushParams?.sent == false && denied.pushParams?.isPending == false && denied.pushParams?.resendAllowedAt != null)
    step = flow.respond(ChallengeAnswer.PushResend, denied)
    assertEquals(ChallengeError.Code.RESEND_TOO_SOON, step.require(ChallengeType.Push).error?.code)
    assertNotNull(step.challenges?.first(ChallengeType.Totp), "the other alternative stays")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun judyEnrolsMidFlowAndIsThenAskedForPush() = runTest {
    val (h, transport, _) = Harness.replay(listOf("PushMfaIT.judyEnrolsMidFlowThroughTheNativeRequiredAction"), client, metadataFrom = enrolTranscript)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("judy", "judy-password")
    val challenge = step.require(ChallengeType.PushEnrollment)
    assertTrue(step.challenges?.size == 1 && challenge.required && challenge.id == "native-push-enroll")
    val params = challenge.pushEnrollmentParams.req()
    assertEquals(issuerPath(h, "push-mfa"), params.deviceApiBase)
    assertTrue((params.expiresIn ?: 0) > 0)
    assertEquals("judy", params.enrollmentClaims["username"].stringValue)
    assertEquals(params.enrollmentClaims["sub"].stringValue, params.userId)

    // A JWT signed by another key than the session's DPoP key is refused (spec/03 §4.15) and the
    // re-challenge keeps the pending enrolment.
    val claims = params.enrollmentClaims.req()
    val otherKey = SoftwareDPoPKey()
    val wrongJwt = DeviceJwt.sign(
      mapOf(
        "sub" to claims["sub"].req(), "enrollmentId" to claims["enrollmentId"].req(), "nonce" to claims["nonce"].req(), "exp" to JsonPrimitive(1_900_000_000),
        "cnf" to JsonObject(mapOf("jwk" to otherKey.publicJwk.json)), "credentialId" to JsonPrimitive("c"), "deviceId" to JsonPrimitive("d"),
        "deviceType" to JsonPrimitive("android"), "deviceLabel" to JsonPrimitive("x"), "pushProviderType" to JsonPrimitive("none"),
      ),
      otherKey,
    )
    step = flow.respond(ChallengeAnswer.PushEnrollment(wrongJwt), challenge)
    val refused = step.require(ChallengeType.PushEnrollment)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, refused.error?.code)
    val again = refused.pushEnrollmentParams.req()
    assertEquals(claims["enrollmentId"], again.enrollmentClaims["enrollmentId"], "the pending challenge is kept")

    val push = h.sdk.push()
    val prepared = push.prepareEnrollment(again, "Judy's phone")
    assertTrue(prepared.enrollment.username == "judy" && prepared.enrollment.pushProviderType == "none" && !push.isEnrolled())
    step = flow.respond(prepared.answer, refused)
    assertEquals("judy", step.credentials.req().username)
    push.commit(prepared)
    assertEquals(prepared.enrollment.credentialId, push.enrollment()?.credentialId)
    // The in-flow answer: a form field `token` (masked in the transcript), never logged.
    val answer = transport.sent[5]
    assertTrue(answer.formFields.orEmpty().any { (name, value) -> name == "token" && value.startsWith("eyJ") })
    assertFalse(h.observer.entries.mapNotNull { it.requestBody }.joinToString().contains(prepared.answer.token), "the device JWT is masked in the flow log")

    // Next login: push is the single second factor and is sent at once (spec/03 §4.7).
    step = h.sdk.authentication().startLogin(itParameters).toSecondFactor("judy", "judy-password")
    val pushChallenge = step.require(ChallengeType.Push)
    assertTrue(step.challenges?.size == 1 && pushChallenge.pushParams?.sent == true && pushChallenge.pushParams?.cid != null)
    assertEquals(listOf("Judy's phone"), pushChallenge.pushParams?.devices)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout() = runTest {
    val name = "PushMfaIT.aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout"
    val (h, transport, _) = Harness.replay(listOf(name), client, metadataFrom = enrolTranscript, seqs = listOf(1, 3, 5, 6, 7, 8, 9, 10, 11))
    var push = enrolledAlice(h, provider = "apns")
    val before = h.sdk.dpopKeyThumbprint()

    // 1. A new push token (the recorded one): one PUT; the same token again is a no-op locally.
    val recorded = Transcript.load(name).exchange(1).request.json["pushProviderId"].stringValue.req()
    push.updatePushProvider("apns", recorded)
    assertEquals(recorded, push.enrollment()?.pushProviderId)
    push.updatePushProvider("apns", recorded)
    assertEquals(2, transport.sent.size, "unchanged token: no request ([0] is the metadata fetch)")

    // 2. Key rotation: proof by the old key, body with the new JWK; afterwards the DPoP key changed
    // and the stored credentials are gone (they were bound to the old key).
    val credentials = Credentials("old", tokenType = "DPoP", refreshToken = "r", idToken = null, scope = null, expiresAt = Instant.now().plusSeconds(300), refreshExpiresAt = null, authSession = null)
    h.sdk.credentialsManager().store(credentials)
    push.rotateKey()
    val after = h.sdk.dpopKeyThumbprint()
    assertNotEquals(before, after)
    assertEquals(after, push.enrollment()?.keyThumbprint)
    assertNull(h.sdk.credentialsManager().stored())
    val rotate = transport.sent[2]
    assertTrue(rotate.method == "PUT" && rotate.url.path.endsWith("/device/rotate-key"))
    val jwk = bodyJson(rotate.body)["publicKeyJwk"]
    assertEquals("ES256", jwk["alg"].stringValue)
    assertEquals("P-256", jwk["crv"].stringValue)
    val proofKey = Jwt.decodeHeader(rotate.header("DPoP").req())["jwk"]
    assertNotEquals(jwk["x"], proofKey["x"], "the proof is signed by the old key")

    // 3. A new DPoP-bound login binds tokens to the new key; the device API works again.
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    h.sdk.credentialsManager().store(step.credentials.req())
    push = h.sdk.push()
    assertTrue(push.pendingApprovals().isEmpty())

    // 4. Panic button.
    push.lockout()
    assertTrue(transport.sent.last().url.path.endsWith("/login/lockout"))
    assertEquals(0, transport.remaining)
  }

  // FCM (FcmPushIT): the Android side of the same API.

  @Test
  fun aliceEnrolsHerAndroidPhone() = runTest {
    val (h, transport, t) = Harness.replay(listOf(fcmEnrolTranscript), client, metadataFrom = fcmEnrolTranscript, range = 2..8)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    h.sdk.credentialsManager().store(step.credentials.req())

    val enrollment = h.sdk.push().enroll("Alice's test Pixel", "fcm", "fcm-alice-1:APA91bFakeRegistrationToken")
    assertEquals(0, transport.remaining)
    assertEquals(userIdOf(fcmEnrolTranscript), enrollment.userId)
    val claims = Jwt.decodePayload(bodyJson(transport.sent.last().body)["token"].stringValue.req())
    assertEquals("android", claims["deviceType"].stringValue)
    assertEquals("fcm", claims["pushProviderType"].stringValue)
    assertEquals("fcm-alice-1:APA91bFakeRegistrationToken", claims["pushProviderId"].stringValue)
    assertEquals(Jwt.decodePayload(t[0].exchange(7).response.json["enrollment_token"].stringValue.req())["nonce"], claims["nonce"])
  }

  @Test
  fun anFcmMessageLeadsThePhoneToTheApproval() = runTest {
    val (h, transport, t) =
      Harness.replay(listOf("FcmPushIT.aNativeLoginSendsAnFcmMessageAndThePhoneApproves"), client, metadataFrom = fcmEnrolTranscript)
    val push = enrolledAlice(h, fcmEnrolTranscript)
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.toSecondFactor("alice", "alice-password")
    assertEquals(listOf("totp", "push"), step.challenges.req().types())
    step = flow.respond(ChallengeAnswer.PushResend, step.require(ChallengeType.Push))
    val challenge = step.require(ChallengeType.Push)
    val params = challenge.pushParams.req()
    assertEquals(listOf("Alice's test Pixel"), params.devices)

    // The FCM message as ba-itsys' fcm sender builds it: data.token = the confirm token (FcmPushIT
    // checks the sent message; the transcript records only the HTTP exchanges with Keycloak).
    val message = mapOf("token" to confirmToken(params.cid.req(), "cred-alice-test"))
    val payload = push.handleMessage(message).req()
    assertEquals(params.cid, payload.cid)
    assertNull(push.handleMessage(mapOf("token" to confirmToken(params.cid.req(), "someone-else"))), "a message for another credential is ignored")

    val approval = push.pendingApproval(payload).req()
    assertTrue(params.userVerificationNumber.req() in approval.numbers)
    assertEquals("approved", push.respond(approval, PushApprovalAction.Approve(params.userVerificationNumber)))
    step = flow.respond(ChallengeAnswer.PushPoll, challenge)
    assertEquals("alice", step.credentials.req().username)
    assertEquals(0, transport.remaining)
    assertEquals(t[0].exchange(5).response.json["challenges"][0]["cid"].stringValue, approval.cid)
  }

  @Test
  fun aRefreshedFcmTokenIsSentOnce() = runTest {
    val name = "FcmPushIT.aRefreshedRegistrationTokenReceivesTheNextPush"
    val (h, transport, t) = Harness.replay(listOf(name), client, metadataFrom = fcmEnrolTranscript, range = 1..1)
    val push = enrolledAlice(h, fcmEnrolTranscript)
    val newToken = t[0].exchange(1).request.json["pushProviderId"].stringValue.req()
    push.updatePushProvider("fcm", newToken)
    push.updatePushProvider("fcm", newToken)
    assertEquals(0, transport.remaining)
    assertEquals(2, transport.sent.size, "the second call changes nothing and sends nothing")
    assertEquals("fcm" to newToken, push.enrollment()?.let { it.pushProviderType to it.pushProviderId })
  }

  @Test
  fun theDeviceApiNeedsAnEnrolmentAPushBlockAndABoundLogin() = runTest {
    val h = Harness(URI("https://idp.example.com/realms/demo"), client, ScriptedTransport({ ScriptedTransport.json(200, ScriptedTransport.METADATA_JSON) }))
    val push = h.sdk.push(StaticDeviceTokenProvider(DeviceToken("t")))
    assertEquals(NativeAuthError.Code.PUSH_NOT_ENROLLED, expectError { push.pendingApprovals() }.code)
    assertEquals(NativeAuthError.Code.PUSH_UNAVAILABLE, expectError { push.enroll("x") }.code, "metadata without a push block")
    val provider = NativeDeviceTokenProvider(h.sdk.credentialsManager())
    assertEquals(NativeAuthError.Code.DEVICE_TOKEN_UNAVAILABLE, expectError { provider.deviceToken() }.code, "nobody signed in")
    h.sdk.credentialsManager().store(Credentials("bearer", refreshToken = null, idToken = null, scope = null, expiresAt = Instant.now().plusSeconds(300), refreshExpiresAt = null, authSession = null))
    assertEquals(NativeAuthError.Code.DEVICE_TOKEN_UNAVAILABLE, expectError { provider.deviceToken() }.code, "a Bearer token is not enough")
  }

  @Test
  fun answersAndParamsOfPhase3() {
    assertEquals(listOf("action" to "resend"), ChallengeAnswer.PushResend.formFields)
    assertEquals(listOf("action" to "poll"), ChallengeAnswer.PushPoll.formFields)
    assertEquals(listOf("token" to "t"), ChallengeAnswer.PushEnrollment("t").formFields)
    assertEquals(listOf("action" to "check"), ChallengeAnswer.PushEnrollmentCheck.formFields)
    assertTrue(ChallengeAnswer.PushPoll.challengeType == ChallengeType.Push && ChallengeAnswer.PushEnrollmentCheck.challengeType == ChallengeType.PushEnrollment)
    val params = PushParams(
      buildJsonObject {
        put("sent", true); put("cid", "c"); put("expires_at", 1_800_000_000); put("poll_interval", 5); put("status", "pending")
        putJsonObject("user_verification") { put("type", "number_match"); put("number", "42") }
        putJsonArray("devices") { add(buildJsonObject { put("label", "A") }); add(buildJsonObject { put("label", "B") }) }
      },
    )
    assertTrue(params.isPending && params.userVerificationNumber == "42" && params.devices == listOf("A", "B") && params.pollInterval == 5)
    val pin = PushParams(buildJsonObject { put("sent", true); put("status", "approved"); putJsonObject("user_verification") { put("type", "pin") } })
    assertTrue(!pin.isPending && pin.userVerificationNumber == null && pin.pollInterval == 3)

    val fcm = PushNotificationPayload.parse(mapOf("token" to confirmToken("c1", "k1"))).req()
    assertTrue(fcm.cid == "c1" && fcm.credentialId == "k1" && fcm.expiresAt != null)
    assertEquals("c1", PushNotificationPayload.parse(mapOf("confirmToken" to confirmToken("c1", "k1")))?.cid, "the APNs key works too")
    assertNull(PushNotificationPayload.parse(mapOf("title" to "x")))
    assertFalse(fcm.toString().contains(fcm.confirmToken))
  }

  private fun confirmToken(cid: String, credId: String): String =
    "eyJhbGciOiJub25lIn0." + Base64Url.encode("""{"cid":"$cid","credId":"$credId","exp":1800000000}""") + "."
}
