package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeError
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.boolValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.attestationFrom
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.first
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 2b contract tests (spec/14): the native required actions `update_password`, `verify_email`
 * and `terms` (spec/03 §4.11–§4.14), recovery codes, enrolment on first login, the SMS webhook and
 * the idle timeout of the post-login `auth_session`. Twin of `Phase2bReplayTests.swift`.
 */
class Phase2bReplayTest {
  private val client = TranscriptReplayTest.DEMO
  private val itParameters = TranscriptReplayTest.IT_PARAMETERS

  private suspend fun NativeLoginFlow.upToSecondStep(username: String, password: String): FlowStep {
    var step = start()
    step = respond(ChallengeAnswer.Username(username), step.require(ChallengeType.Username))
    return respond(ChallengeAnswer.Password(password), step.require(ChallengeType.Password))
  }

  private suspend fun loginToRequiredAction(h: Harness, username: String, password: String): Pair<NativeLoginFlow, Challenge> {
    val flow = h.sdk.authentication().startLogin(itParameters)
    val challenges = flow.upToSecondStep(username, password).challenges.req()
    assertTrue(challenges.size == 1 && challenges[0].required && challenges[0].type.isRequiredAction, "a required action is the single entry")
    return flow to challenges[0]
  }

  private fun Harness.loggedBodies(): String = observer.entries.mapNotNull { it.requestBody }.joinToString("\n")

  @Test
  fun metadataAdvertisesTheNativeRequiredActions() = runTest {
    val (h, _, _) = Harness.replay(emptyList(), client, metadataFrom = "RequiredActionsIT.metadataAdvertisesTheNativeRequiredActions")
    val metadata = h.sdk.metadata()
    for (type in listOf("update_password", "verify_email", "terms", "passkey_registration")) {
      assertTrue(type in metadata.challengeTypesSupported, "$type advertised")
    }
    assertTrue(ChallengeType.fromWire("update_password") == ChallengeType.UpdatePassword && ChallengeType.Terms.isSupported && ChallengeType.VerifyEmail.isSupported)
  }

  @Test
  fun carolUpdatesHerPasswordInBand() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RequiredActionsIT.carolUpdatesHerPasswordInBand"), client, range = 1..8)
    val (flow, challenge) = loginToRequiredAction(h, "carol", "carol-password")
    assertTrue(challenge.type == ChallengeType.UpdatePassword && challenge.id == "native-update-password")
    val params = challenge.updatePasswordParams.req()
    assertTrue(params.username == "carol" && params.minimumLength == 8)
    assertEquals(listOf("At least 8 characters"), params.hints)

    var step = flow.respond(ChallengeAnswer.UpdatePassword("", ""), challenge)
    val missing = step.require(ChallengeType.UpdatePassword)
    assertEquals(ChallengeError.Code.MISSING_CREDENTIAL, missing.error?.code)

    step = flow.respond(ChallengeAnswer.UpdatePassword("carol-password", "other"), missing)
    val mismatch = step.require(ChallengeType.UpdatePassword)
    assertEquals(ChallengeError.Code.PASSWORD_MISMATCH, mismatch.error?.code)

    step = flow.respond(ChallengeAnswer.UpdatePassword("short", "short"), mismatch)
    val rejected = step.require(ChallengeType.UpdatePassword)
    assertEquals(ChallengeError.Code.INVALID_PASSWORD, rejected.error?.code)
    assertTrue(rejected.error?.message.orEmpty().contains("8"), "the policy message is rendered: ${rejected.error?.message}")

    step = flow.respond(ChallengeAnswer.UpdatePassword("carol-password", "carol-password"), rejected)
    assertEquals("carol", step.credentials?.username)
    assertEquals(0, transport.remaining)
    // The new password never reaches the flow log.
    val logged = h.loggedBodies()
    assertFalse(logged.contains("carol-password") || logged.contains("short"))
  }

  @Test
  fun disablingTheNativeVariantFallsBackToRedirectToWeb() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RequiredActionsIT.disablingTheNativeVariantFallsBackToRedirectToWeb"), client)
    val step = h.sdk.authentication().startLogin(itParameters).upToSecondStep("carol", "carol-password")
    assertEquals("required_action:UPDATE_PASSWORD", step.redirectToWeb.req("expected redirect_to_web, got $step").reason)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun graceVerifiesHerEmailWithACode() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RequiredActionsIT.graceVerifiesHerEmailWithACode"), client)
    val (flow, challenge) = loginToRequiredAction(h, "grace", "grace-password")
    assertTrue(challenge.type == ChallengeType.VerifyEmail && challenge.id == "native-verify-email")
    val params = challenge.verifyEmailParams.req()
    assertTrue(params.sent && params.emailMasked == "g***@example.com" && params.digits == 6 && params.ttl == 300 && params.resendAllowedAt != null)

    var step = flow.respond(ChallengeAnswer.VerifyEmailResend, challenge)
    val tooSoon = step.require(ChallengeType.VerifyEmail)
    assertTrue(tooSoon.error?.code == ChallengeError.Code.RESEND_TOO_SOON && tooSoon.verifyEmailParams?.sent == true)

    step = flow.respond(ChallengeAnswer.VerifyEmail("000000"), tooSoon)
    val wrong = step.require(ChallengeType.VerifyEmail)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, wrong.error?.code)

    step = flow.respond(ChallengeAnswer.VerifyEmail("000000"), wrong)
    assertEquals(true, step.credentials.req().accessTokenClaims["email_verified"].boolValue)
    assertEquals(0, transport.remaining)
    assertFalse(h.loggedBodies().contains("code=0"), "the verification code is masked in the flow log")
  }

  @Test
  fun hankDeclinesThenAcceptsTheTerms() = runTest {
    // Exchanges 1-4: decline → access_denied; 5-9: accept → code → tokens (the IT's `accepted=maybe`
    // probe comes after that and is not replayed: a Boolean answer cannot reproduce it).
    val (h, transport, _) = Harness.replay(listOf("RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin"), client, range = 1..9)
    val (declining, challenge) = loginToRequiredAction(h, "hank", "hank-password")
    assertTrue(challenge.type == ChallengeType.Terms && challenge.id == "native-terms")
    val params = challenge.termsParams.req()
    assertTrue(params.text.orEmpty().startsWith("Demo terms") && params.url.toString() == "https://example.com/terms" && params.version == "2026-10")

    val error = expectError { declining.respond(ChallengeAnswer.Terms(false), challenge) }
    assertEquals(NativeAuthError.Code.ACCESS_DENIED, error.code)
    assertTrue(error.errorDescription.orEmpty().contains("required_action:TERMS_AND_CONDITIONS") && error.errorDescription.orEmpty().contains("declined"))
    assertEquals(NativeLoginFlow.State.FINISHED, declining.currentState)

    val (accepting, again) = loginToRequiredAction(h, "hank", "hank-password")
    assertEquals("hank", accepting.respond(ChallengeAnswer.Terms(true), again).credentials?.username)
    assertEquals(0, transport.remaining)
  }

  // Recovery codes (spec/03 §4.8, spec/14 D2)

  @Test
  fun ivyUsesARecoveryCodeInsteadOfTheTotp() = runTest {
    // Exchanges 1-6: [totp, recovery_code], a wrong code, then a code in display format → tokens.
    val (h, transport, _) = Harness.replay(listOf("RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"), client, range = 1..6)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val set = flow.upToSecondStep("ivy", "ivy-password").challenges.req()
    assertTrue(set.types() == listOf("totp", "recovery_code") && !set[1].required)
    val recovery = set.first(ChallengeType.RecoveryCode).req()
    val params = recovery.recoveryCodeParams.req()
    assertTrue(params.remaining == 3 && params.warningThreshold == 4 && params.shouldWarn)
    var step = flow.respond(ChallengeAnswer.RecoveryCode("IVY9-IVY9-IVY9"), recovery)
    val wrong = step.require(ChallengeType.RecoveryCode)
    assertTrue(wrong.error?.code == ChallengeError.Code.INVALID_CREDENTIAL && wrong.recoveryCodeParams?.remaining == 3)
    step = flow.respond(ChallengeAnswer.RecoveryCode("ivy1-ivy1-ivy1"), wrong)
    assertEquals("ivy", step.credentials?.username)
    val logged = h.loggedBodies()
    assertFalse(logged.contains("IVY9") || logged.contains("ivy1"), "recovery codes are masked in the flow log")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun ivyUsedCodeIsRefusedAndTheCountGoesDown() = runTest {
    // Exchanges 7-10: the second login shows remaining 2 and refuses the code used before (the IT's
    // second successful code was not exchanged, so the replay stops there).
    val (h, transport, _) = Harness.replay(listOf("RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"), client, range = 7..10)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val recovery = flow.upToSecondStep("ivy", "ivy-password").require(ChallengeType.RecoveryCode)
    assertEquals(2, recovery.recoveryCodeParams?.remaining)
    val step = flow.respond(ChallengeAnswer.RecoveryCode("IVY1IVY1IVY1"), recovery)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, step.require(ChallengeType.RecoveryCode).error?.code)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun ivyLastRecoveryCodeHandsTheLoginToTheBrowser() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"), client, range = 12..18)
    val flow = h.sdk.authentication().startLogin(itParameters)
    val recovery = flow.upToSecondStep("ivy", "ivy-password").require(ChallengeType.RecoveryCode)
    assertEquals(1, recovery.recoveryCodeParams?.remaining)
    val step = flow.respond(ChallengeAnswer.RecoveryCode("IVY3IVY3IVY3"), recovery)
    assertEquals("required_action:CONFIGURE_RECOVERY_AUTHN_CODES", step.redirectToWeb.req("expected redirect_to_web, got $step").reason)

    val again = h.sdk.authentication().startLogin(itParameters).upToSecondStep("ivy", "ivy-password")
    assertEquals(listOf("totp"), again.challenges?.types(), "no code left: the alternative is gone")
    assertEquals(0, transport.remaining)
  }

  // Enrol on first login (spec/14 D4), SMS webhook (spec/14 D5), idle-timeout auth_session (spec/14 D6)

  @Test
  fun bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin() = runTest {
    val (h, transport, t) = Harness.replay(listOf("EnrolOnFirstLoginIT.bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin"), client)
    h.passkeys.enqueue(attestationFrom(t[0].form(4)))
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username("bob"), step.require(ChallengeType.Username))
    assertEquals(listOf("password"), step.challenges?.types(), "no passkey yet: the password is the only primary factor")
    step = flow.respond(ChallengeAnswer.Password("bob-password"), step.require(ChallengeType.Password))
    val registration = step.require(ChallengeType.PasskeyRegistration)
    assertTrue(registration.id == "native-passkey-register" && registration.required && registration.type.isRequiredAction)
    val params = registration.passkeyRegistrationParams.req()
    assertEquals("bob", params.user.name)
    step = flow.respond(ChallengeAnswer.PasskeyRegistration(h.sdk.passkeys().register(params), "Bob's phone"), registration)
    assertEquals("bob", step.credentials?.username)

    // The next login offers the new passkey beside the password.
    val again = h.sdk.authentication().startLogin(itParameters)
    step = again.start()
    step = again.respond(ChallengeAnswer.Username("bob"), step.require(ChallengeType.Username))
    assertTrue(step.challenges?.types() == listOf("passkey", "password") && step.require(ChallengeType.Passkey).passkeyParams?.discoverable == false)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun bobGetsAnSmsCodeThroughTheWebhook() = runTest {
    val (h, transport, _) = Harness.replay(listOf("SmsOtpIT.bobGetsAnSmsCodeThroughTheWebhook"), "demo-native-sms")
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.upToSecondStep("bob", "bob-password")
    val otp = step.require(ChallengeType.Otp)
    val params = otp.otpParams.req()
    assertTrue(otp.required && params.channel == "sms" && params.destinationMasked == "***23" && params.sent)
    step = flow.respond(ChallengeAnswer.Otp("000000"), otp)
    val wrong = step.require(ChallengeType.Otp)
    assertTrue(wrong.error?.code == ChallengeError.Code.INVALID_CREDENTIAL && wrong.otpParams?.sent == true)
    step = flow.respond(ChallengeAnswer.Otp("000000"), wrong)
    assertEquals("bob", step.credentials?.username)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive() = runTest {
    // 1-4: login + exchange; 5: a refresh keeps the session alive; 6: the step-up with the expired
    // post-login auth_session is invalid_session (the IT's final refresh, 7, is not replayed).
    val (h, transport, _) = Harness.replay(
      listOf("StepUpIT.postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive"), Phase2ReplayTest.STEP_UP_CLIENT, range = 1..6,
    )
    val credentials = h.sdk.authentication().startLogin(itParameters).upToSecondStep("alice", "alice-password").credentials.req()
    val refreshed = h.sdk.tokens().refresh(credentials)
    assertEquals(credentials.authSession, refreshed.authSession, "a refresh does not renew the post-login auth_session")
    val stepUp = h.sdk.authentication().stepUp(LoginParameters(scope = "openid profile", acrValues = "2", deviceName = "NativeAuthIT"), refreshed.authSession)
    assertEquals(NativeAuthError.Code.INVALID_SESSION, expectError { stepUp.start() }.code, "the idle timeout passed: log in again (spec/14 D6)")
    assertEquals(0, transport.remaining)
  }

  @Test
  fun answersCarryTheRightFields() {
    fun ChallengeAnswer.wire() = formFields.map { "${it.first}=${it.second}" }
    assertEquals(listOf("password", "password_confirm"), ChallengeAnswer.UpdatePassword("a", "b").formFields.map { it.first })
    assertEquals(listOf("code=1"), ChallengeAnswer.VerifyEmail("1").wire())
    assertEquals(listOf("action=resend"), ChallengeAnswer.VerifyEmailResend.wire())
    assertEquals(listOf("accepted=true"), ChallengeAnswer.Terms(true).wire())
    assertTrue(ChallengeAnswer.Terms(false).challengeType == ChallengeType.Terms && ChallengeAnswer.VerifyEmailResend.challengeType == ChallengeType.VerifyEmail)
  }
}
