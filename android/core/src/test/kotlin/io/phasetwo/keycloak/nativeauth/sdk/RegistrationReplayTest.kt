package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Registration and forgotten-password reset (spec/22 phase 3), replayed from RegistrationIT. */
class RegistrationReplayTest {
  private val registration = LoginParameters(scope = "openid profile", deviceName = "NativeAuthIT", flow = "registration")
  private val reset = LoginParameters(scope = "openid profile", deviceName = "NativeAuthIT", flow = "reset_credentials")

  @Test
  fun theRegistrationChallengeDescribesTheProfileAndReturnsFieldErrors() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RegistrationIT.fieldErrorsComeBackOnTheRegistrationChallenge"), TranscriptReplayTest.DEMO)
    val flow = h.sdk.authentication().startLogin(registration)
    var step = flow.start()
    val challenge = step.require(ChallengeType.Registration)
    val params = challenge.registrationParams.req()
    assertEquals(listOf("username", "email", "firstName", "lastName"), params.attributes.map { it.name })
    assertEquals("Email", params.attributes[1].displayName)
    assertTrue(params.attributes.all { it.required })
    step = flow.respond(
      ChallengeAnswer.Registration(
        mapOf("username" to listOf("bob"), "email" to listOf("not-an-email"), "firstName" to listOf("Rita"), "lastName" to listOf("Example")),
        password = "x",
        confirm = "y",
      ),
      challenge,
    )
    val again = step.require(ChallengeType.Registration)
    assertEquals("invalid_profile", again.error?.code)
    assertEquals(listOf("Username already exists."), again.registrationParams.req().fieldErrors["username"])
    assertEquals(0, transport.remaining)
  }

  @Test
  fun ritaRegistersAndIsSignedIn() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RegistrationIT.ritaRegistersAndIsSignedIn"), TranscriptReplayTest.DEMO, range = 1..3)
    val flow = h.sdk.authentication().startLogin(registration)
    val step = flow.start()
    val credentials = flow.respond(
      ChallengeAnswer.Registration(
        mapOf("username" to listOf("rita"), "email" to listOf("rita@example.com"), "firstName" to listOf("Rita"), "lastName" to listOf("Example")),
        password = "rita-password-1",
        confirm = "rita-password-1",
      ),
      step.require(ChallengeType.Registration),
    ).credentials.req()
    assertEquals("rita", credentials.accessTokenClaims["preferred_username"].stringValue)
    assertEquals(0, transport.remaining)
  }

  @Test
  fun forgotPasswordIsUsernameCodeAndANewPassword() = runTest {
    val (h, transport, _) = Harness.replay(listOf("RegistrationIT.ritaResetsHerPasswordWithAnEmailedCode"), TranscriptReplayTest.DEMO, range = 1..6)
    val flow = h.sdk.authentication().startLogin(reset)
    var step = flow.start()
    assertEquals(listOf("username"), step.challenges?.types())
    step = flow.respond(ChallengeAnswer.Username("rita@example.com"), step.require(ChallengeType.Username))
    val otp = step.require(ChallengeType.Otp)
    assertEquals("r***@example.com", otp.otpParams.req().destinationMasked)
    step = flow.respond(ChallengeAnswer.Otp("000000"), otp)
    step = flow.respond(ChallengeAnswer.Otp("123456"), step.require(ChallengeType.Otp))
    step = flow.respond(ChallengeAnswer.UpdatePassword("rita-password-2", "rita-password-2"), step.require(ChallengeType.UpdatePassword))
    assertTrue(step is FlowStep.Authorized)
    assertEquals(0, transport.remaining)
  }
}
