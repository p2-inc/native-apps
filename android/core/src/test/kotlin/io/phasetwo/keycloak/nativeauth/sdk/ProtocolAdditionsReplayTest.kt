package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FormField
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Additions to v1.0-rc (spec/03 §2.3, §3.3, §4.11): `skip` for optional required actions, `Custom`
 * answers and extra request fields, replayed from EnrolOnFirstLoginIT and ExtensionParametersIT.
 * Twin of `ProtocolAdditionsReplayTests.swift`.
 */
class ProtocolAdditionsReplayTest {
  private val client = TranscriptReplayTest.DEMO
  private val itParameters = TranscriptReplayTest.IT_PARAMETERS

  private suspend fun bobUpToRegistration(flow: NativeLoginFlow): Challenge {
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("bob"), step.require(ChallengeType.Username))
    step = flow.respond(ChallengeAnswer.Password("bob-password"), step.require(ChallengeType.Password))
    val challenges = step.challenges.req()
    assertTrue(challenges.size == 1 && challenges[0].type == ChallengeType.PasskeyRegistration)
    return challenges[0]
  }

  // skip (spec/03 §4.11)

  @Test
  fun anOptionalEnrolmentIsSkippedAndOfferedAgain() = runTest {
    val (h, transport, _) = Harness.replay(listOf("EnrolOnFirstLoginIT.bobMayDeclineAnOptionalEnrolmentAndIsOfferedItAgainAtTheNextLogin"), client)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val offer = bobUpToRegistration(flow)
    assertTrue(offer.isSkippable)

    val credentials = flow.respond(ChallengeAnswer.Skip(offer.type), offer).credentials.req("a skip completes the login like any other answer")
    assertEquals("bob", credentials.username)

    assertTrue(bobUpToRegistration(h.sdk.authentication().startLogin(itParameters)).isSkippable, "the next login offers it again")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun aMandatoryEnrolmentIsNotSkippableAndTheSdkRefusesLocally() = runTest {
    val (h, transport, _) = Harness.replay(listOf("EnrolOnFirstLoginIT.aMandatoryEnrolmentIsNotSkippableAndRefusesSkip"), client, range = 1..4)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val registration = bobUpToRegistration(flow)
    assertFalse(registration.isSkippable)
    assertEquals(NativeAuthError.Code.FLOW_STATE, expectError { flow.respond(ChallengeAnswer.Skip(ChallengeType.PasskeyRegistration), registration) }.code)
    assertEquals(1, transport.remaining, "nothing was sent")

    // A Custom answer goes out as is; the server refuses the skip and the session survives.
    val sent = expectError { flow.respond(ChallengeAnswer.Custom(ChallengeType.PasskeyRegistration, listOf(FormField("action", "skip"))), registration) }
    assertEquals(NativeAuthError.Code.INVALID_REQUEST, sent.code)
    assertEquals(NativeLoginFlow.State.AWAITING_ANSWER, flow.currentState)
    assertEquals(0, transport.remaining)
  }

  // extra fields (spec/03 §2.3)

  @Test
  fun extraFieldsGoOutOnTheInitialAndContinuationRequestsAndAreMasked() = runTest {
    val (h, transport, _) = Harness.replay(listOf("ExtensionParametersIT.extensionParametersAreAcceptedOnEveryRequest"), client)
    val parameters = LoginParameters(
      scope = "openid profile", additionalParameters = mapOf("x_device_signal" to "a1b2c3d4"), continuationParameters = mapOf("x_risk_score" to "12"),
    )
    val flow = h.sdk.authentication().startLogin(parameters)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("bob"), step.require(ChallengeType.Username), additionalFields = mapOf("x_device_signal" to "a1b2c3d4"))
    step = flow.respond(ChallengeAnswer.Password("bob-password"), step.require(ChallengeType.Password))
    assertNotNull(step.credentials)
    assertEquals(0, transport.remaining)
    val log = h.observer.entries.mapNotNull { it.requestBody }.joinToString("\n")
    assertTrue(log.contains("x_device_signal=***") && !log.contains("a1b2c3d4"), "x_ values never reach the flow log")
  }

  @Test
  fun extraFieldsMayNotOverrideProtocolOrAnswerFields() {
    val existing = listOf("auth_session" to "s", "challenge_type" to "username", "challenge_id" to "e", "username" to "bob")
    for (name in listOf("auth_session", "client_id", "action", "username", "")) {
      assertThrows(NativeAuthError::class.java, { NativeLoginFlow.extraFields(mapOf(name to "x"), existing) }, "$name is refused")
    }
    assertEquals(listOf("x_a", "x_b"), NativeLoginFlow.extraFields(mapOf("x_b" to "2", "x_a" to "1"), existing).map { it.first }, "sent in key order")
  }

  @Test
  fun aCustomAnswerMayNotSetTheContinuationFields() = runTest {
    val (h, _, _) = Harness.replay(listOf("EnrolOnFirstLoginIT.aMandatoryEnrolmentIsNotSkippableAndRefusesSkip"), client, range = 1..3)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val registration = bobUpToRegistration(flow)
    val error = expectError { flow.respond(ChallengeAnswer.Custom(ChallengeType.PasskeyRegistration, listOf(FormField("challenge_id", "other"))), registration) }
    assertEquals(NativeAuthError.Code.INVALID_PARAMETER, error.code)
  }
}
