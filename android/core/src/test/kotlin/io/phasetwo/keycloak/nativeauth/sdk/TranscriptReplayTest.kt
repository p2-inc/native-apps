package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeEndpointClient
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeError
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeOutcome
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyRegistrationClient
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.MockTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.support.assertionFrom
import io.phasetwo.keycloak.nativeauth.sdk.support.attestationFrom
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.first
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.require
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import java.time.Instant
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal fun FlowStep.require(type: ChallengeType): Challenge = challenges.req("expected challenges, got $this").require(type)

internal val Credentials.username: String? get() = accessTokenClaims["preferred_username"].stringValue

internal fun Credentials.expiredCopy(): Credentials = copy(expiresAt = Instant.now().minusSeconds(1))

/**
 * Contract tests: the SDK drives each recorded scenario through [MockTransport], which rejects any
 * request that differs from what the integration test sent and answers with what Keycloak sent.
 * Twin of `TranscriptReplayTests.swift`.
 */
class TranscriptReplayTest {
  companion object {
    const val DEMO = "demo-ios"
    const val DEMO_ALT = "demo-ios-alt"
    const val DEMO_PASSKEY = "demo-ios-passkey"

    /** The integration tests send this `device_name`; the SDK must send exactly the same field set. */
    val IT_PARAMETERS = LoginParameters(scope = "openid profile", deviceName = "NativeAuthIT")
  }

  private suspend fun NativeLoginFlow.usernamePassword(username: String, password: String): FlowStep {
    var step = start()
    step = respond(ChallengeAnswer.Username(username), step.require(ChallengeType.Username))
    return respond(ChallengeAnswer.Password(password), step.require(ChallengeType.Password))
  }

  private fun parseError(transcript: Transcript, seq: Int): NativeAuthError =
    assertThrows(NativeAuthError::class.java) { ChallengeEndpointClient.parse(transcript.exchange(seq).response.httpResponse) }

  // Username / password / TOTP (S3)

  @Test
  fun happyPathUsernamePasswordTotpYieldsTokens() = runTest {
    val (h, transport, t) = Harness.replay(listOf("NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri"), DEMO, range = 1..5)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)

    var step = flow.start()
    val username = step.require(ChallengeType.Username)
    assertTrue(step.challenges?.size == 1 && username.required)
    assertEquals(true, username.usernameParams?.allowEmail)
    assertEquals(1800, flow.expiresIn)

    step = flow.respond(ChallengeAnswer.Username("alice"), username)
    val context = (step as FlowStep.Challenges).context
    assertTrue(context.username == "alice" && context.displayName == "Alice Example" && context.clientName == "Demo iOS App")
    val password = step.require(ChallengeType.Password)
    assertEquals(true, password.passwordParams?.usernameKnown)

    step = flow.respond(ChallengeAnswer.Password("alice-password"), password)
    val totp = step.require(ChallengeType.Totp)
    assertTrue(step.challenges?.types() == listOf("totp") && totp.required)
    val totpParams = totp.totpParams.req()
    assertTrue(totpParams.digits == 6 && totpParams.period == 30 && totpParams.credentialLabels == listOf("Phone"))

    step = flow.respond(ChallengeAnswer.Totp("000000"), totp)
    val credentials = step.credentials.req()
    val tokenJson = t[0].exchange(5).response.json
    assertEquals(tokenJson["access_token"].stringValue, credentials.accessToken)
    assertEquals(tokenJson["refresh_token"].stringValue, credentials.refreshToken)
    assertEquals(tokenJson["id_token"].stringValue, credentials.idToken)
    assertTrue(credentials.tokenType == "Bearer" && !credentials.isDPoPBound, "the token is not DPoP-bound in this scenario")
    assertEquals(t[0].exchange(4).response.json["auth_session"].stringValue, credentials.authSession, "post-login auth_session is kept")
    assertEquals("alice", credentials.username)
    assertTrue(credentials.scope.orEmpty().contains("openid"))
    assertEquals(NativeLoginFlow.State.FINISHED, flow.currentState)
    assertEquals(0, transport.remaining)

    // The token request carried a DPoP proof.
    val tokenRequest = transport.sent.last()
    assertEquals(3, tokenRequest.header("DPoP")?.split('.')?.size)
    assertFalse(tokenRequest.formFields.orEmpty().any { it.first == "redirect_uri" })

    h.sdk.credentialsManager().store(credentials)
    assertTrue(h.sdk.credentialsManager().hasValid())
    assertEquals(credentials.authSession, h.sdk.credentialsManager().authSession())
  }

  @Test
  fun passwordOnlyUserSkipsTheConditionalSecondFactor() = runTest {
    val (h, transport, _) = Harness.replay(listOf("NativeAuthIT.passwordOnlyUserSkipsConditionalSecondFactor"), DEMO)
    val step = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("bob", "bob-password")
    assertEquals("bob", step.credentials?.username)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun wrongPasswordRechallengesWithErrorDescriptorThenSucceeds() = runTest {
    val (h, _, _) = Harness.replay(listOf("NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds"), DEMO)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    val first = step.require(ChallengeType.Password)

    step = flow.respond(ChallengeAnswer.Password("wrong-password"), first)
    val again = step.require(ChallengeType.Password)
    assertEquals(first.id, again.id, "same execution is re-challenged")
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, again.error?.code)
    assertNotNull(again.error?.message)
    assertEquals(step.challenges?.size == 1, again.required)
    assertEquals(NativeLoginFlow.State.AWAITING_ANSWER, flow.currentState)

    step = flow.respond(ChallengeAnswer.Password("alice-password"), again)
    assertEquals(listOf("totp"), step.challenges?.types())
    assertNull(step.challenges?.first()?.error)
  }

  @Test
  fun wrongTotpRechallengesThenSucceeds() = runTest {
    val (h, transport, _) = Harness.replay(listOf("NativeAuthIT.wrongTotpRechallengesThenSucceeds"), DEMO, range = 1..5)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.usernamePassword("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("111111"), step.require(ChallengeType.Totp))
    assertEquals("invalid_credential", step.require(ChallengeType.Totp).error?.code)
    // The IT stopped at the 200 without exchanging the code; the SDK always exchanges, so stop here.
    assertEquals(1, transport.remaining)
  }

  @Test
  fun emptyPasswordIsMissingCredential() = runTest {
    val (h, _, _) = Harness.replay(listOf("NativeAuthIT.emptyPasswordRechallengesWithoutCountingAFailure"), DEMO)
    val step = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("alice", "")
    assertEquals(ChallengeError.Code.MISSING_CREDENTIAL, step.require(ChallengeType.Password).error?.code)
  }

  @Test
  fun unknownUsernameGetsAPhantomPasswordChallengeThatLocksLikeARealAccount() = runTest {
    // spec/03 §4.1 (spec/14 D3): the unknown user sees [password], invalid_credential with a
    // retry.remaining countdown, then access_denied, indistinguishable from a real account.
    val (h, transport, t) = Harness.replay(listOf("NativeAuthIT.unknownUsernameGetsAPhantomPasswordChallengeThatLocksLikeARealAccount"), DEMO)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username(t[0].form(2).getValue("username")), step.require(ChallengeType.Username))
    val set = step.challenges.req()
    assertTrue(set.types() == listOf("password") && set[0].required && set[0].passwordParams?.usernameKnown == true && set[0].error == null)
    assertNull((step as FlowStep.Challenges).context.username, "a phantom user is never identified")
    step = flow.respond(ChallengeAnswer.Password(""), set[0])
    assertEquals(ChallengeError.Code.MISSING_CREDENTIAL, step.require(ChallengeType.Password).error?.code)
    for (expectedRemaining in listOf(4, 3, 2, 1)) {
      step = flow.respond(ChallengeAnswer.Password("wrong"), step.require(ChallengeType.Password))
      val failed = step.require(ChallengeType.Password)
      assertTrue(failed.error?.code == ChallengeError.Code.INVALID_CREDENTIAL && failed.retry?.remaining == expectedRemaining)
    }
    val locked = expectError { flow.respond(ChallengeAnswer.Password("wrong"), step.require(ChallengeType.Password)) }
    assertTrue(locked.code == NativeAuthError.Code.ACCESS_DENIED && locked.errorDescription.orEmpty().lowercase().contains("locked"))
    assertEquals(0, transport.remaining)
  }

  // Sessions and errors (spec/03 §3.5)

  @Test
  fun invalidAuthSessionValuesAreInvalidSession() {
    val t = Transcript.load("NativeAuthIT.invalidAuthSessionValuesAreRejectedWithInvalidSession")
    for (seq in listOf(1, 3)) {
      val error = parseError(t, seq)
      assertTrue(error.code == NativeAuthError.Code.INVALID_SESSION && error.statusCode == 400)
      assertNull(error.authSession, "no session to continue with")
    }
  }

  @Test
  fun cancelInvalidatesTheSession() = runTest {
    val (h, transport, _) = Harness.replay(listOf("NativeAuthIT.cancelledAuthSessionCannotBeReused"), DEMO, range = 1..2)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    val step = flow.start()
    flow.cancel()
    assertEquals(NativeLoginFlow.State.FINISHED, flow.currentState)
    assertNull(flow.authSession)
    assertEquals(0, transport.remaining, "action=cancel was sent")
    assertEquals(NativeAuthError.Code.FLOW_STATE, expectError { flow.respond(ChallengeAnswer.Username("alice"), step.challenges.req().first()) }.code)
  }

  @Test
  fun expiredAuthSessionEndsTheFlow() = runTest {
    val (h, _, _) = Harness.replay(listOf("NativeAuthIT.expiredAuthSessionIsRejectedWithInvalidSession"), DEMO)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    val step = flow.start()
    assertTrue(flow.expiresIn.req() <= 1)
    assertEquals(NativeAuthError.Code.INVALID_SESSION, expectError { flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username)) }.code)
    assertEquals(NativeLoginFlow.State.FINISHED, flow.currentState)
    assertNull(flow.authSession)
  }

  @Test
  fun invalidRequestKeepsTheSession() = runTest {
    val t = Transcript.load("NativeAuthIT.unknownChallengeIdIsInvalidRequestAndSessionSurvives")
    for (seq in listOf(2, 3)) {
      val error = parseError(t, seq)
      assertEquals(NativeAuthError.Code.INVALID_REQUEST, error.code)
      assertTrue(error.authSessionStillValid, "a fresh auth_session is echoed")
    }
    // The SDK refuses to answer a challenge that is not pending before touching the network.
    val (h, transport, _) = Harness.replay(listOf(t.test), DEMO, range = 1..1)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    flow.start()
    val bogus = Challenge("00000000-0000-0000-0000-000000000000", ChallengeType.Username)
    assertEquals(NativeAuthError.Code.FLOW_STATE, expectError { flow.respond(ChallengeAnswer.Username("alice"), bogus) }.code)
    assertEquals(NativeAuthError.Code.UNSUPPORTED_CHALLENGE, expectError { flow.respond(ChallengeAnswer.Password("x"), flow.pendingChallenges.first()) }.code)
    assertTrue(transport.remaining == 0 && flow.currentState == NativeLoginFlow.State.AWAITING_ANSWER)
  }

  @Test
  fun clientErrorsAreMapped() {
    val t = Transcript.load("NativeAuthIT.missingOrUnknownClientIsRejected")
    for ((seq, code, status) in listOf(Triple(1, "invalid_request", 400), Triple(2, "invalid_client", 401), Triple(3, "invalid_client", 401), Triple(4, "invalid_request", 400))) {
      val error = parseError(t, seq)
      assertTrue(error.code == code && error.statusCode == status, "exchange $seq")
    }
  }

  // Brute force (S14)

  @Test
  fun bruteForceLockEndsWithAccessDenied() = runTest {
    val (h, transport, t) = Harness.replay(listOf("NativeAuthIT.bruteForceLockEndsWithAccessDenied"), DEMO)
    val attempts = t[0].exchanges.count { it.request.form?.get("challenge_type") == "password" }
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("erin"), step.require(ChallengeType.Username))
    var locked: NativeAuthError? = null
    for (attempt in 1..attempts) {
      try {
        step = flow.respond(ChallengeAnswer.Password("wrong-password-$attempt"), step.require(ChallengeType.Password))
        val failed = step.require(ChallengeType.Password)
        assertTrue(failed.error?.code == "invalid_credential" && (failed.retry?.remaining ?: -1) >= 0, "retry.remaining counts down (spec/03 §3.3)")
      } catch (e: NativeAuthError) {
        locked = e
        break
      }
    }
    assertEquals(NativeAuthError.Code.ACCESS_DENIED, locked?.code)
    assertTrue(locked?.errorDescription.orEmpty().lowercase().contains("locked"))
    assertEquals(NativeLoginFlow.State.FINISHED, flow.currentState)

    // The locked account is not revealed on a new login: the same phantom password challenge an
    // unknown user gets (spec/03 §4.1).
    val second = h.sdk.authentication().startLogin(IT_PARAMETERS)
    step = second.start()
    step = second.respond(ChallengeAnswer.Username("erin"), step.require(ChallengeType.Username))
    val set = step.challenges.req("expected the phantom password challenge")
    assertTrue(set.types() == listOf("password") && set[0].error == null && (step as FlowStep.Challenges).context.username == null)
    assertEquals(0, transport.remaining)
  }

  // Alternatives (spec/09 Q2, spec/11 D3)

  @Test
  fun alternativesAreOfferedTogetherAndEitherCanBeAnswered() = runTest {
    val (h, transport, _) = Harness.replay(listOf("NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered"), DEMO_ALT)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    val set = step.challenges.req()
    assertEquals(listOf("password", "totp"), set.types())
    assertTrue(set.none { it.required })
    assertNotEquals(set[0].id, set[1].id)
    step = flow.respond(ChallengeAnswer.Totp("222222"), set[1])
    assertNotNull(step.credentials)

    // After a wrong TOTP the set keeps flow order with the error on the failed entry.
    val second = h.sdk.authentication().startLogin(IT_PARAMETERS)
    step = second.start()
    step = second.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    step = second.respond(ChallengeAnswer.Totp("333333"), step.require(ChallengeType.Totp))
    val again = step.challenges.req()
    assertEquals(listOf("password", "totp"), again.types())
    assertTrue(again[1].error?.code == "invalid_credential" && again[0].error == null)
    assertEquals(1, transport.remaining, "the IT's final password answer is not exchanged for tokens")
  }

  @Test
  fun alternativesAreFilteredByConfiguredCredentials() = runTest {
    val (h, _, _) = Harness.replay(listOf("NativeAuthIT.q2_alternativesAreFilteredByConfiguredCredentials"), DEMO_ALT)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("bob"), step.require(ChallengeType.Username))
    assertTrue(step.challenges?.types() == listOf("password") && step.challenges?.first()?.required == true)
  }

  // Tokens (spec/09 Q1, spec/05 §2.2)

  @Test
  fun pkceVerifierIsEnforcedByTheTokenEndpoint() = runTest {
    val (h, _, _) = Harness.replay(listOf("NativeAuthIT.pkceVerifierIsEnforced"), DEMO)
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    val step = flow.usernamePassword("alice", "alice-password")
    val error = expectError { flow.respond(ChallengeAnswer.Totp("444444"), step.require(ChallengeType.Totp)) }
    assertTrue(error.code == NativeAuthError.Code.INVALID_GRANT && error.statusCode == 400)
  }

  @Test
  fun sentinelRedirectUriModeSendsRedirectUriOnExchange() = runTest {
    // Metadata recorded in sentinel mode + the round-trip login of the sibling test.
    val (h, transport, _) = Harness.replay(
      listOf("NativeAuthIT.q1_sentinelModeRoundTrip"), DEMO, metadataFrom = "NativeAuthIT.q1_sentinelModeRejectsTokenRequestWithoutRedirectUri",
    )
    val metadata = h.sdk.metadata()
    assertTrue(metadata.codeExchange.redirectUriRequired && metadata.codeExchange.redirectUri == "urn:keycloak:native-auth")
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.usernamePassword("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("555555"), step.require(ChallengeType.Totp))
    assertNotNull(step.credentials)
    assertTrue(transport.sent.last().formFields.orEmpty().contains("redirect_uri" to "urn:keycloak:native-auth"))
    assertEquals(0, transport.remaining)
  }

  @Test
  fun tokensCanBeRefreshedLoggedOutAndRevoked() = runTest {
    val (h, transport, _) = Harness.replay(listOf("NativeAuthIT.tokensCanBeRefreshedLoggedOutAndRevoked"), DEMO)
    val tokens = h.sdk.tokens()
    val manager = h.sdk.credentialsManager()
    val credentials = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("bob", "bob-password").credentials.req()

    // Expired credentials in the manager trigger exactly one refresh for concurrent callers.
    val expired = credentials.expiredCopy()
    manager.store(expired)
    assertFalse(manager.hasValid())
    val a = async { manager.credentials() }
    val b = async { manager.credentials() }
    val (ra, rb) = a.await() to b.await()
    assertTrue(ra == rb && ra.accessToken != expired.accessToken)
    assertEquals(credentials.authSession, ra.authSession, "the post-login auth_session survives a refresh")
    assertEquals(ra, manager.stored())

    tokens.logout(ra.refreshToken.req())
    assertEquals(NativeAuthError.Code.INVALID_GRANT, expectError { tokens.refresh(ra) }.code)

    val fresh = h.sdk.authentication().startLogin(IT_PARAMETERS).usernamePassword("bob", "bob-password").credentials.req()
    tokens.revoke(fresh.refreshToken.req())

    manager.store(fresh.withAuthSession(null).expiredCopy())
    assertEquals(NativeAuthError.Code.REAUTHENTICATION_REQUIRED, expectError { manager.credentials() }.code)
    assertNull(manager.stored(), "revoked session: stored credentials are cleared")
    assertEquals(0, transport.remaining)
  }

  // Passkeys (spec/03 §4.3, §4.4, §6)

  @Test
  fun allowListLoginAfterUsernameOffersPasskeyAndPassword() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PasskeyIT.allowListLoginAfterUsernameOffersPasskeyAndPassword"), DEMO, range = 1..5)
    val recorded = assertionFrom(t[0].form(3))
    h.passkeys.enqueue(recorded)

    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    val set = step.challenges.req()
    assertEquals(listOf("passkey", "password"), set.types())
    val passkey = set[0]
    assertFalse(passkey.required)
    val params = passkey.passkeyParams.req()
    assertTrue(params.rpId == "localhost" && params.userVerification == "required" && !params.discoverable)
    val allowed = params.allowCredentials.firstOrNull { it.id == recorded.credentialId }.req("the recorded credential is allowed")
    assertEquals(setOf("hybrid", "internal"), allowed.transports.toSet())
    assertNotNull(params.challengeBytes)

    val assertion = h.sdk.passkeys().assert(params)
    assertEquals(params.challenge, h.passkeys.assertParams.first().challenge)
    step = flow.respond(ChallengeAnswer.Passkey(assertion), passkey)
    assertEquals(listOf("totp"), step.challenges?.types())
    step = flow.respond(ChallengeAnswer.Totp("666666"), step.require(ChallengeType.Totp))
    assertNotNull(step.credentials.req().authSession, "post-login auth_session for step-up")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun discoverableLoginWithUserHandle() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PasskeyIT.discoverableLoginWithUserHandle"), DEMO_PASSKEY, range = 1..4)
    val recorded = assertionFrom(t[0].form(2))
    assertNotNull(recorded.userHandle)
    h.passkeys.enqueue(recorded)

    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    val set = step.challenges.req()
    assertEquals(listOf("passkey", "username"), set.types())
    assertNull((step as FlowStep.Challenges).context.username)
    val params = set[0].passkeyParams.req()
    assertTrue(params.discoverable && params.allowCredentials.isEmpty())

    val assertion = h.sdk.passkeys().assert(params, preferImmediatelyAvailableCredentials = true)
    assertEquals(listOf(true), h.passkeys.preferImmediatelyAvailable)
    step = flow.respond(ChallengeAnswer.Passkey(assertion), set[0])
    val next = step.challenges.req("expected totp")
    assertTrue(next.types() == listOf("totp") && (step as FlowStep.Challenges).context.username == "alice")
    step = flow.respond(ChallengeAnswer.Totp("777777"), next[0])
    assertEquals("alice", step.credentials?.username)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun wrongSignatureRechallengesWithFreshChallenge() = runTest {
    val (h, _, t) = Harness.replay(listOf("PasskeyIT.wrongSignatureRechallengesWithInvalidCredential"), DEMO)
    for (seq in listOf(3, 4, 5)) h.passkeys.enqueue(assertionFrom(t[0].form(seq)))
    val passkeys = h.sdk.passkeys()

    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    val first = step.require(ChallengeType.Passkey)
    val challenge = first.passkeyParams.req().challenge

    step = flow.respond(ChallengeAnswer.Passkey(passkeys.assert(first.passkeyParams.req())), first)
    val again = step.require(ChallengeType.Passkey)
    assertEquals("invalid_credential", again.error?.code)
    assertNotEquals(challenge, again.passkeyParams?.challenge, "a new challenge is issued after a failed attempt")
    assertEquals(ChallengeType.Passkey, step.challenges?.first()?.type)

    step = flow.respond(ChallengeAnswer.Passkey(passkeys.assert(again.passkeyParams.req())), again)
    val third = step.require(ChallengeType.Passkey)
    assertEquals("invalid_credential", third.error?.code, "replaying the old challenge value fails")
    step = flow.respond(ChallengeAnswer.Passkey(passkeys.assert(third.passkeyParams.req())), third)
    assertEquals(listOf("totp"), step.challenges?.types())
  }

  @Test
  fun missingAssertionFieldsAreMissingCredential() {
    val t = Transcript.load("PasskeyIT.missingAssertionFieldsRechallengeWithoutCountingAFailure")
    val outcome = ChallengeEndpointClient.parse(t.exchange(3).response.httpResponse) as ChallengeOutcome.Challenges
    assertEquals(ChallengeError.Code.MISSING_CREDENTIAL, outcome.set.challenges.first(ChallengeType.Passkey)?.error?.code)
  }

  @Test
  fun registerThroughAuthenticatedEndpointsAfterLogin() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PasskeyIT.registerThroughAuthenticatedEndpointsAfterPasswordTotpLogin"), DEMO)
    val finishJson = t[0].exchange(7).request.json.req()
    val recorded = attestationFrom(finishJson)
    h.passkeys.enqueue(recorded)

    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.usernamePassword("alice", "alice-password")
    step = flow.respond(ChallengeAnswer.Totp("888888"), step.require(ChallengeType.Totp))
    val credentials = step.credentials.req()

    val registered = h.sdk.passkeys().registerNewPasskey("Second device", credentials)
    assertTrue(registered.credentialId == recorded.credentialId && registered.label == "Second device")
    val options = h.passkeys.registerParams.first()
    assertTrue(options.rp.id == "localhost" && options.rp.name == "Native Auth Demo")
    assertTrue(options.user.name == "alice" && options.user.displayName == "Alice Example")
    assertEquals(listOf(-7, -257), options.pubKeyCredParams)
    assertTrue(options.userVerification == "required" && options.residentKey == "required" && options.attestation == "none")
    assertEquals(60000, options.timeoutMilliseconds)
    val finishRequest = transport.sent.last()
    assertTrue(finishRequest.header("Authorization").orEmpty().startsWith("Bearer "))
    assertEquals("application/json", finishRequest.header("Content-Type"))

    // registration_id is single use.
    val registration = PasskeyRegistrationClient(h.sdk.issuer, h.sdk.metadataClient, h.sdk.transport, h.sdk.dpopSigner)
    val replay = expectError { registration.finish(credentials, finishJson["registration_id"].stringValue.req(), recorded, "Second device") }
    assertTrue(replay.code == NativeAuthError.Code.INVALID_REQUEST && replay.statusCode == 400)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun registrationEndpointsRequireAValidToken() = runTest {
    val t = Transcript.load("PasskeyIT.registrationEndpointsRequireABearerToken")
    val metadata = Transcript.load(Harness.METADATA)
    val h = Harness(metadata.issuer, DEMO, MockTransport(listOf(metadata.exchange(1), t.exchange(2))))
    val garbage = Credentials("not-a-token", refreshToken = null, idToken = null, scope = null, expiresAt = Instant.MAX, refreshExpiresAt = null, authSession = null)
    val error = expectError { h.sdk.passkeys().registerNewPasskey(null, garbage) }
    assertTrue(error.code == NativeAuthError.Code.INVALID_TOKEN && error.statusCode == 401)
  }

  @Test
  fun requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PasskeyIT.requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks"), DEMO)
    h.passkeys.enqueue(attestationFrom(t[0].form(4)))  // the bad one (wrong RP ID)
    h.passkeys.enqueue(attestationFrom(t[0].form(5)))
    h.passkeys.enqueue(assertionFrom(t[0].form(9)))
    val passkeys = h.sdk.passkeys()

    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("dave"), step.require(ChallengeType.Username))
    assertEquals(listOf("password"), step.challenges?.types(), "no passkey yet")
    step = flow.respond(ChallengeAnswer.Password("dave-password"), step.require(ChallengeType.Password))
    val set = step.challenges.req("expected registration")
    assertTrue(set.types() == listOf("passkey_registration") && set[0].required && set[0].id == "native-passkey-register")
    assertEquals("dave", (step as FlowStep.Challenges).context.username)
    val params = set[0].passkeyRegistrationParams.req()
    assertTrue(params.user.name == "dave" && params.rp.id == "localhost")
    assertTrue(flow.expiresIn.req() > 0)

    step = flow.respond(ChallengeAnswer.PasskeyRegistration(passkeys.register(params)), set[0])
    val again = step.require(ChallengeType.PasskeyRegistration)
    assertEquals(ChallengeError.Code.INVALID_ATTESTATION, again.error?.code)
    assertNotEquals(params.challenge, again.passkeyRegistrationParams?.challenge)

    step = flow.respond(ChallengeAnswer.PasskeyRegistration(passkeys.register(again.passkeyRegistrationParams.req()), label = "Dave's phone"), again)
    assertNotNull(step.credentials.req().authSession)

    // Next login: the passkey is offered and the action is gone.
    val second = h.sdk.authentication().startLogin(IT_PARAMETERS)
    step = second.start()
    step = second.respond(ChallengeAnswer.Username("dave"), step.require(ChallengeType.Username))
    val offered = step.challenges.req()
    assertEquals(listOf("passkey", "password"), offered.types())
    step = second.respond(ChallengeAnswer.Passkey(passkeys.assert(offered[0].passkeyParams.req())), offered[0])
    assertEquals("dave", step.credentials?.username)
    assertEquals(0, transport.remaining)
  }
}
