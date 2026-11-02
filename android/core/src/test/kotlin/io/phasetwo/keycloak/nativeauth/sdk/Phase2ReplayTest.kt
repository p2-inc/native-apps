package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeError
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.longValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.MockWebPresenter
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.first
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import io.phasetwo.keycloak.nativeauth.sdk.web.WebFallback
import java.net.URI
import java.time.Instant
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private fun URI.query(name: String): String? =
  rawQuery?.let { FormEncoding.decode(it.toByteArray()) }?.firstOrNull { it.first == name }?.second

/**
 * Phase 2 contract tests (spec/13): step-up, OTP, redirect_to_web, DPoP-bound sessions, replayed from
 * the transcripts of StepUpIT, OtpIT, RedirectToWebIT, DPoPBindingIT and PasskeyIT. Twin of
 * `Phase2ReplayTests.swift`.
 */
class Phase2ReplayTest {
  companion object {
    const val STEP_UP_CLIENT = "demo-ios-stepup"
    const val OTP_CLIENT = "demo-ios-otp"
    val IT_PARAMETERS = TranscriptReplayTest.IT_PARAMETERS
    val STEP_UP_PARAMETERS = LoginParameters(scope = "openid profile", acrValues = "2", deviceName = "NativeAuthIT")
  }

  private suspend fun NativeLoginFlow.usernamePassword(username: String, password: String): FlowStep {
    var step = start()
    step = respond(ChallengeAnswer.Username(username), step.require(ChallengeType.Username))
    return respond(ChallengeAnswer.Password(password), step.require(ChallengeType.Password))
  }

  // Step-up (spec/03 §5)

  @Test
  fun stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession() = runTest {
    val (h, transport, _) = Harness.replay(listOf("StepUpIT.stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession"), STEP_UP_CLIENT)
    // Level 1 login: username → password, no TOTP (the level-2 condition is not requested).
    val level1 = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("alice", "alice-password").credentials.req()
    assertEquals("1", level1.accessTokenClaims["acr"].stringValue)
    h.sdk.credentialsManager().store(level1)

    // Step up to acr 2 with the stored post-login auth_session: only the TOTP is asked.
    val stepUp = h.sdk.authentication().stepUp(acrValues = "2", scope = "openid profile", deviceName = "NativeAuthIT")
    assertTrue(stepUp.isStepUp)
    var step = stepUp.start()
    val set = step.challenges.req("expected the totp challenge")
    val context = (step as FlowStep.Challenges).context
    assertEquals(listOf("totp"), set.types())
    assertTrue(context.stepUp && context.acrRequested == "2" && context.username == "alice")
    step = stepUp.respond(ChallengeAnswer.Totp("000000"), set[0])
    val level2 = step.credentials.req()
    assertEquals("2", level2.accessTokenClaims["acr"].stringValue)
    assertEquals(level1.accessTokenClaims["sid"], level2.accessTokenClaims["sid"], "same user session")
    assertTrue(level2.authSession != null && level2.authSession != level1.authSession, "fresh post-login auth_session")
    h.sdk.credentialsManager().store(level2)

    // Level 1 is still satisfied: the step-up completes without any challenge.
    step = h.sdk.authentication().stepUp(acrValues = "1", scope = "openid profile", deviceName = "NativeAuthIT").start()
    assertEquals("1", step.credentials?.accessTokenClaims["acr"].stringValue)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun maxAgeForcesAFullReauthentication() = runTest {
    val (h, transport, _) = Harness.replay(listOf("StepUpIT.maxAgeForcesAFullReauthentication"), STEP_UP_CLIENT)
    val credentials = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("alice", "alice-password").credentials.req()

    // max_age=0 passed explicitly with the session from the credentials (no store round trip).
    val flow = h.sdk.authentication().stepUp(LoginParameters(scope = "openid profile", maxAge = 0, deviceName = "NativeAuthIT"), credentials.authSession)
    var step = flow.start()
    val set = step.challenges.req("expected a password challenge")
    val context = (step as FlowStep.Challenges).context
    assertTrue(set.first(ChallengeType.Password) != null && set.first(ChallengeType.Username) == null, "username is skipped, the factor is asked again")
    assertTrue(context.stepUp && context.acrRequested == null)
    step = flow.respond(ChallengeAnswer.Password("alice-password"), step.require(ChallengeType.Password))
    assertTrue((step.credentials?.accessTokenClaims["auth_time"].longValue ?: 0) > (credentials.accessTokenClaims["auth_time"].longValue ?: 0))
    assertEquals(0, transport.remaining)
  }

  @Test
  fun stepUpWithoutStoredSessionIsCredentialsNotFound() = runTest {
    val (h, _, _) = Harness.replay(emptyList(), STEP_UP_CLIENT)
    assertEquals(NativeAuthError.Code.CREDENTIALS_NOT_FOUND, expectError { h.sdk.authentication().stepUp(acrValues = "2") }.code)
  }

  @Test
  fun staleRegistrationIsRefusedWithAStepUpSessionAndMaxAge() = runTest {
    val (h, transport, _) = Harness.replay(
      listOf("PasskeyIT.staleAuthenticationIsRefusedForRegistrationUntilAStepUpWithMaxAge"), TranscriptReplayTest.DEMO, range = 1..11,
    )
    val login = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = login.usernamePassword("alice", "alice-password")
    step = login.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    val stale = step.credentials.req()

    // §6: 403 insufficient_authorization with auth_session + max_age.
    val refused = expectError { h.sdk.passkeys().registerNewPasskey("x", stale) }
    assertEquals(NativeAuthError.Code.INSUFFICIENT_AUTHORIZATION, refused.code)
    assertTrue(refused.maxAge == 1 && refused.authSession != null)

    // continueAfterTokenChallenge: a step-up with that session and max_age; the plain flow re-runs
    // password + totp (username skipped).
    val flow = h.sdk.authentication().continueAfterTokenChallenge(refused, LoginParameters(scope = "openid profile", deviceName = "NativeAuthIT"))
    assertEquals(1, flow.parameters.maxAge)
    step = flow.start()
    val set = step.challenges.req()
    val context = (step as FlowStep.Challenges).context
    assertTrue(context.stepUp && context.username == "alice" && set.first(ChallengeType.Username) == null)
    step = flow.respond(ChallengeAnswer.Password("alice-password"), step.require(ChallengeType.Password))
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    val fresh = step.credentials.req()

    // The options call now succeeds; the scripted platform cancels the ceremony so the test ends there.
    h.passkeys.fail(NativeAuthError(NativeAuthError.Code.PASSKEY_CANCELLED, errorDescription = "scripted"))
    assertEquals(NativeAuthError.Code.PASSKEY_CANCELLED, expectError { h.sdk.passkeys().registerNewPasskey("x", fresh) }.code)
    assertEquals(0, transport.remaining)
  }

  // OTP (spec/03 §4.6)

  @Test
  fun bobGetsAnEmailCodeAsTheOnlySecondFactor() = runTest {
    val (h, transport, _) = Harness.replay(listOf("OtpIT.bobGetsAnEmailCodeAsTheOnlySecondFactor"), OTP_CLIENT)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.usernamePassword("bob", "bob-password")
    val otp = step.require(ChallengeType.Otp)
    assertTrue(step.challenges?.types() == listOf("otp") && otp.required)
    val params = otp.otpParams.req()
    assertTrue(params.sent && params.channel == "email" && params.destinationMasked == "b***@example.com" && params.digits == 6 && params.ttl == 300)
    assertNotNull(params.resendAllowedAt)

    step = flow.respond(ChallengeAnswer.OtpResend, otp)
    val tooSoon = step.require(ChallengeType.Otp)
    assertTrue(tooSoon.error?.code == ChallengeError.Code.RESEND_TOO_SOON && tooSoon.otpParams?.sent == true)

    step = flow.respond(ChallengeAnswer.Otp("000000"), tooSoon)
    val wrong = step.require(ChallengeType.Otp)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, wrong.error?.code)

    step = flow.respond(ChallengeAnswer.Otp("000000"), wrong)
    assertEquals("bob", step.credentials?.username)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest() = runTest {
    val (h, transport, _) = Harness.replay(listOf("OtpIT.aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest"), OTP_CLIENT, range = 1..4)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.usernamePassword("alice", "alice-password")
    assertEquals(listOf("totp", "otp"), step.challenges?.types())
    val otp = step.require(ChallengeType.Otp)
    assertTrue(!otp.required && otp.otpParams?.sent == false && otp.otpParams?.resendAllowedAt == null)

    step = flow.respond(ChallengeAnswer.OtpResend, otp)
    val sent = step.require(ChallengeType.Otp)
    assertTrue(sent.error == null && sent.otpParams?.sent == true && sent.otpParams?.resendAllowedAt != null)
    assertEquals(listOf("totp", "otp"), step.challenges?.types(), "the alternatives stay on offer")
    // The IT answered the code next; the SDK would exchange the resulting code, which the IT did not
    // record, so the replay stops here.
    assertEquals(0, transport.remaining)
  }

  // redirect_to_web (spec/03 §3.4)

  @Test
  fun pendingNonNativeRequiredActionRedirectsToWebAndTheCodeIsExchangedWithTheNativeVerifier() = runTest {
    val transcript = Transcript.load("RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt")
    // The IT recorded the native login (1-3), then the code exchange of the browser's code; the
    // browser requests themselves are not part of the contract. Replay: 1..3 + the first token call.
    val tokenExchange = transcript.exchanges.first { it.request.path.endsWith("/token") }
    val recordedCode = tokenExchange.request.form?.get("code").req()
    val presenter = MockWebPresenter { url ->
      assertTrue(url.query("request_uri").orEmpty().startsWith("urn:ietf:params:oauth:request_uri:"))
      URI("demoapp://auth/callback?state=STATE&code=$recordedCode")
    }
    val (h, transport, _) = Harness.replay(listOf(transcript.test), TranscriptReplayTest.DEMO, seqs = listOf(1, 2, 3, tokenExchange.seq), webPresenter = presenter)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    val step = flow.usernamePassword("frank", "frank-password")
    val request = step.redirectToWeb.req("expected redirect_to_web, got $step")
    assertTrue(request.reason == "required_action:UPDATE_PROFILE" && request.redirectUri == "demoapp://auth/callback" && request.callbackScheme == "demoapp")
    assertTrue(request.expiresIn == 60 && request.state != null)
    assertEquals(NativeLoginFlow.State.FINISHED, flow.currentState)

    // Replace the scripted state with the real one now that we know it.
    presenter.callback = { URI("demoapp://auth/callback?state=${request.state}&code=$recordedCode") }
    val credentials = h.sdk.webFallback().complete(request, flow)
    assertEquals("frank", credentials.username)
    assertTrue(presenter.opened.size == 1 && presenter.opened[0].second == "demoapp")
    val opened = presenter.opened.first().first
    assertTrue(opened.path.endsWith("/protocol/openid-connect/auth"))
    assertEquals("demo-ios", opened.query("client_id"))
    // The exchange carried the redirect_uri and this flow's verifier.
    val token = transport.sent.last().formFields.orEmpty()
    assertTrue(token.contains("redirect_uri" to "demoapp://auth/callback"))
    assertTrue(token.contains("code_verifier" to flow.pkce.verifier))
    assertEquals(0, transport.remaining)
  }

  @Test
  fun webFallbackRejectsAStateMismatchAndSurfacesBrowserErrors() {
    assertThrows(NativeAuthError::class.java) { WebFallback.code(URI("demoapp://auth/callback?state=other&code=x"), "expected") }
    val denied = assertThrows(NativeAuthError::class.java) { WebFallback.code(URI("demoapp://auth/callback?error=access_denied&error_description=nope"), null) }
    assertEquals("access_denied", denied.code)
    assertEquals("abc", WebFallback.code(URI("demoapp://auth/callback?state=s&code=abc"), "s"))
  }

  // DPoP-bound session (spec/03 §8)

  @Test
  fun sessionCodeAndPostLoginSessionAreBoundToTheProofKey() = runTest {
    // Exchanges 11-14: a login where every request carried a proof; 17: the step-up with the same key.
    val (h, transport, _) = Harness.replay(
      listOf("DPoPBindingIT.sessionCodeAndPostLoginSessionAreBoundToTheProofKey"), TranscriptReplayTest.DEMO, seqs = listOf(11, 12, 13, 14, 17),
    )
    val credentials = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("bob", "bob-password").credentials.req()
    assertTrue(credentials.isDPoPBound && credentials.tokenType == "DPoP")
    assertNotNull(credentials.accessTokenClaims["cnf"]["jkt"].stringValue)
    // Every challenge request carried a proof with htm/htu of the challenge endpoint.
    for (request in transport.sent.filter { it.url.path.endsWith("/challenge") }) {
      val payload = Jwt.decodePayload(request.header("DPoP").req()).req()
      assertTrue(payload["htm"].stringValue == "POST" && payload["htu"].stringValue == request.url.toString())
    }
    val step = h.sdk.authentication().stepUp(STEP_UP_PARAMETERS, credentials.authSession).start()
    assertNotNull(step.challenges?.first(ChallengeType.Password))
    assertEquals(0, transport.remaining)
  }

  // Resource requests

  @Test
  fun resourceRequestHeadersCarryAProofWithAthForBoundTokens() = runTest {
    val (h, _, _) = Harness.replay(emptyList(), TranscriptReplayTest.DEMO)
    val url = URI("https://api.example.com/transfer")
    val bound = Credentials("at", tokenType = "DPoP", refreshToken = null, idToken = null, scope = null, expiresAt = Instant.MAX, refreshExpiresAt = null, authSession = null)
    val headers = h.sdk.resourceRequestHeaders(bound, "GET", url)
    assertEquals("DPoP at", headers["Authorization"])
    val payload = Jwt.decodePayload(headers["DPoP"].req()).req()
    assertTrue(payload["htm"].stringValue == "GET" && payload["htu"].stringValue == url.toString() && payload["ath"].stringValue != null)
    val bearer = bound.copy(tokenType = "Bearer")
    assertEquals(mapOf("Authorization" to "Bearer at"), h.sdk.resourceRequestHeaders(bearer, "GET", url))
    assertNull(Jwt.decodePayload("x"))
    assertNotEquals(bound, bearer)
  }
}
