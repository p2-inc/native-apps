package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.KcActionStatus
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.first
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Application-initiated actions (spec/21): `Authentication.requiredAction` sends `kc_action` with the
 * stored post-login `auth_session`; the flow reports `kcActionStatus` after `Authorized`. Replayed from
 * the transcripts of KcActionIT (alice on the plain `native` flow). Twin of the iOS
 * KcActionReplayTests.
 */
class KcActionReplayTest {
  private companion object {
    const val CLIENT = TranscriptReplayTest.DEMO
    val IT_PARAMETERS = TranscriptReplayTest.IT_PARAMETERS
  }

  /** username → password → TOTP; the code is exchanged and the credentials stored. */
  private suspend fun signIn(h: Harness): Credentials {
    val flow = h.sdk.authentication().startLogin(IT_PARAMETERS)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("alice"), step.require(ChallengeType.Username))
    step = flow.respond(ChallengeAnswer.Password("alice-password"), step.require(ChallengeType.Password))
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    val credentials = step.credentials.req()
    assertNull(flow.kcActionStatus, "a login without kc_action has no status")
    h.sdk.credentialsManager().store(credentials)
    return credentials
  }

  private suspend fun requiredAction(h: Harness, alias: String, maxAge: Int? = null): NativeLoginFlow =
    h.sdk.authentication().requiredAction(alias, maxAge = maxAge, scope = "openid profile", deviceName = "NativeAuthIT")

  @Test
  fun changingThePasswordRightAfterSigningInSignsOutOtherDevices() = runTest {
    // Exchanges 1–5 are the other device's login; 6–13 are this app.
    val (h, transport, _) = Harness.replay(listOf("KcActionIT.aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd"), CLIENT, range = 6..13)
    signIn(h)
    val flow = requiredAction(h, "UPDATE_PASSWORD")
    assertTrue(flow.isStepUp && flow.parameters.kcAction == "UPDATE_PASSWORD")
    var step = flow.start()
    // Within the realm's maximum authentication age: no factor, straight to the action.
    val challenge = step.require(ChallengeType.UpdatePassword)
    assertEquals(1, step.challenges?.size)
    assertTrue(challenge.isSkippable, "the user may cancel an action the app asked for")
    assertEquals(true, challenge.updatePasswordParams?.logoutOtherSessions, "offered, suggested on")

    step = flow.respond(ChallengeAnswer.UpdatePassword("alice-new-password", "alice-new-password", logoutOtherSessions = true), challenge)
    assertEquals("alice", step.credentials.req().accessTokenClaims["preferred_username"].stringValue)
    assertEquals(KcActionStatus.Success, flow.kcActionStatus)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun theRealmsMaxAuthAgeAsksForTheFactorsFirst() = runTest {
    val (h, transport, _) = Harness.replay(listOf("KcActionIT.theRealmsMaxAuthAgeForcesReauthenticationFirst"), CLIENT, range = 1..8)
    signIn(h)
    val flow = requiredAction(h, "UPDATE_PASSWORD")
    var step = flow.start()
    val set = step.challenges.req("expected the password factor")
    assertTrue(set.first(ChallengeType.Password) != null && set.first(ChallengeType.Username) == null, "the user is known; the factor is asked again")
    val context = (step as FlowStep.Challenges).context
    assertTrue(context.stepUp && context.username == "alice")
    step = flow.respond(ChallengeAnswer.Password("alice-password"), step.require(ChallengeType.Password))
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    assertNotNull(step.challenges?.first(ChallengeType.UpdatePassword), "then the action")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun maxAgeZeroReauthenticatesAndCancellingReportsCancelled() = runTest {
    val (h, transport, _) = Harness.replay(listOf("KcActionIT.maxAgeZeroReauthenticatesAndCancellingKeepsThePassword"), CLIENT, range = 1..10)
    signIn(h)
    val flow = requiredAction(h, "UPDATE_PASSWORD", maxAge = 0)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Password("alice-password"), step.require(ChallengeType.Password))
    step = flow.respond(ChallengeAnswer.Totp("000000"), step.require(ChallengeType.Totp))
    val challenge = step.require(ChallengeType.UpdatePassword)
    step = flow.respond(ChallengeAnswer.Skip(ChallengeType.UpdatePassword), challenge)
    assertNotNull(step.credentials, "cancelling still signs the user in again")
    assertEquals(KcActionStatus.Cancelled, flow.kcActionStatus)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun anActionThatCannotBeInitiatedReportsError() = runTest {
    val (h, transport, _) = Harness.replay(listOf("KcActionIT.anActionThatCannotBeInitiatedReportsError"), CLIENT)
    signIn(h)
    for (action in listOf("TERMS_AND_CONDITIONS", "no-such-action")) {
      val flow = requiredAction(h, action)
      val credentials = flow.start().credentials.req("$action: the code is issued anyway")
      h.sdk.credentialsManager().store(credentials)
      assertEquals(KcActionStatus.Error, flow.kcActionStatus, action)
    }
    assertEquals(0, transport.remaining)
  }

  @Test
  fun kcActionIsReservedAndStatusParsing() {
    assertThrows(NativeAuthError::class.java) { NativeLoginFlow.extraFields(mapOf("kc_action" to "UPDATE_PASSWORD"), emptyList()) }
    assertEquals(KcActionStatus.Success, KcActionStatus.fromWire("success"))
    assertEquals(KcActionStatus.Other("later"), KcActionStatus.fromWire("later"))
    assertEquals(
      listOf("password", "password_confirm", "logout_other_sessions"),
      ChallengeAnswer.UpdatePassword("a", "a", logoutOtherSessions = false).formFields.map { it.first },
    )
    assertEquals(listOf("password", "password_confirm"), ChallengeAnswer.UpdatePassword("a", "a").formFields.map { it.first })
  }
}
