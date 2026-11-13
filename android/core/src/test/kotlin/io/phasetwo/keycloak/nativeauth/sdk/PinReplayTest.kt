package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeError
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.intValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.logging.Redactor
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * PIN extension contract tests (spec/03 §4.17, §4.18, spec/20 D7), replaying `PinIT`'s recorded
 * transcripts (client `demo-native-pin`: username, password, then the PIN; pia has the PIN 2580, pete
 * sets one, rita's PIN locks after 3 attempts). Twin of `PinReplayTests.swift`.
 */
class PinReplayTest {
  private val client = "demo-native-pin"
  private val itParameters = TranscriptReplayTest.IT_PARAMETERS

  private suspend fun loginToPinStep(h: Harness, user: String, type: ChallengeType): Pair<NativeLoginFlow, Challenge> {
    val flow = h.sdk.authentication().startLogin(itParameters)
    var step = flow.start()
    step = flow.respond(ChallengeAnswer.Username(user), step.require(ChallengeType.Username))
    step = flow.respond(ChallengeAnswer.Password(if (user == "rita") "pia-password" else "$user-password"), step.require(ChallengeType.Password))
    assertEquals(1, step.challenges?.size)
    return flow to step.require(type)
  }

  private fun Harness.loggedEverything(): String =
    (observer.entries.mapNotNull { it.requestBody } + logger.lines).joinToString("\n")

  @Test
  fun metadataAdvertisesPinWhenTheExtensionIsInstalled() = runTest {
    val (h, _, _) = Harness.replay(emptyList(), client, metadataFrom = "PinIT.metadataAdvertisesPinWhenTheExtensionIsInstalled")
    val metadata = h.sdk.metadata()
    assertTrue("pin" in metadata.challengeTypesSupported && "pin_setup" in metadata.challengeTypesSupported)
  }

  @Test
  fun wireValuesAndClassification() {
    assertEquals(ChallengeType.Pin, ChallengeType.fromWire("pin"))
    assertEquals(ChallengeType.PinSetup, ChallengeType.fromWire("pin_setup"))
    assertEquals("pin_setup", ChallengeType.PinSetup.wire)
    assertTrue(ChallengeType.Pin.isSupported && ChallengeType.PinSetup.isSupported)
    assertTrue(!ChallengeType.Pin.isRequiredAction && ChallengeType.PinSetup.isRequiredAction)
  }

  @Test
  fun paramsDecodeWithDefaults() {
    val pin = Challenge.parse(j("""{"type":"pin","id":"p","params":{"length":6}}""")).req()
    assertEquals(6, pin.pinParams?.length)
    assertNull(pin.pinSetupParams)
    assertEquals(4, Challenge.parse(j("""{"type":"pin","id":"p"}""")).req().pinParams?.length, "length defaults to 4")
    val setup = Challenge.parse(j("""{"type":"pin_setup","id":"native-configure-pin","params":{"length":5}}""")).req()
    val params = setup.pinSetupParams.req()
    assertEquals(5, params.length)
    assertNull(setup.pinParams)
    assertTrue(params.isWellFormed("24680"))
    assertFalse(params.isWellFormed("2468") || params.isWellFormed("2468a") || params.isWellFormed("２４６８０"))
  }

  @Test
  fun answersCarryTheRightFields() {
    assertEquals(listOf("pin" to "1234"), ChallengeAnswer.Pin("1234").formFields)
    assertEquals(listOf("pin" to "1357", "pin_confirm" to "1358"), ChallengeAnswer.PinSetup("1357", "1358").formFields)
    assertEquals(ChallengeType.Pin, ChallengeAnswer.Pin("1").challengeType)
    assertEquals(ChallengeType.PinSetup, ChallengeAnswer.PinSetup("1", "1").challengeType)
    assertFalse(ChallengeAnswer.Pin("2580").toString().contains("2580"), "toString does not print the PIN")
  }

  @Test
  fun pinsAreRedacted() {
    assertTrue(Redactor.sensitiveKeys.containsAll(listOf("pin", "pin_confirm")))
    for (answer in listOf(ChallengeAnswer.Pin("1234"), ChallengeAnswer.PinSetup("1357", "1357"))) {
      assertTrue(Redactor.redactForm(answer.formFields).all { it.second == Redactor.MASK })
    }
    assertEquals(4, Redactor.redactJson(j("""{"params":{"length":4}}"""))["params"]["length"].intValue, "the length is not a secret")
  }

  @Test
  fun piaSignsInWithHerPinAfterAWrongOne() = runTest {
    val (h, transport, t) = Harness.replay(listOf("PinIT.piaSignsInWithHerPinAfterAWrongOne"), client)
    val (flow, challenge) = loginToPinStep(h, "pia", ChallengeType.Pin)
    assertTrue(challenge.required && challenge.pinParams?.length == 4 && challenge.error == null && !challenge.isLocked)

    var step = flow.respond(ChallengeAnswer.Pin("0000"), challenge)
    val wrong = step.require(ChallengeType.Pin)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, wrong.error?.code)
    assertEquals(2, wrong.retry?.remaining)
    assertFalse(wrong.isLocked)

    step = flow.respond(ChallengeAnswer.Pin("2580"), wrong)
    val credentials = step.credentials.req("expected tokens, got $step")
    assertEquals(t[0].exchange(6).response.json["access_token"].stringValue, credentials.accessToken)
    assertEquals(0, transport.remaining)
    val logged = h.loggedEverything()
    assertFalse(logged.contains("2580") || logged.contains("0000"), "PINs never reach the flow log or the logger")
  }

  @Test
  fun aLockedPinCanOnlyBeCancelled() = runTest {
    val (h, transport, _) = Harness.replay(listOf("PinIT.aLockedPinCanOnlyBeCancelled"), client)
    val (flow, challenge) = loginToPinStep(h, "rita", ChallengeType.Pin)
    assertTrue(challenge.error == null && !challenge.isLocked)

    var step = flow.respond(ChallengeAnswer.Pin("0001"), challenge)
    var pin = step.require(ChallengeType.Pin)
    assertEquals(ChallengeError.Code.INVALID_CREDENTIAL, pin.error?.code)
    assertEquals(2, pin.retry?.remaining)
    step = flow.respond(ChallengeAnswer.Pin("0002"), pin)
    pin = step.require(ChallengeType.Pin)
    assertEquals(1, pin.retry?.remaining, "the last attempt")

    step = flow.respond(ChallengeAnswer.Pin("0009"), pin)
    val locked = step.require(ChallengeType.Pin)
    assertEquals(ChallengeError.Code.CREDENTIAL_LOCKED, locked.error?.code)
    assertTrue(locked.isLocked)
    assertEquals(0, locked.retry?.remaining)

    flow.cancel()
    assertEquals(0, transport.remaining, "action=cancel was sent")
  }

  @Test
  fun peteSetsAPinInBand() = runTest {
    val (h, transport, _) = Harness.replay(listOf("PinIT.peteSetsAPinInBand"), client)
    val (flow, challenge) = loginToPinStep(h, "pete", ChallengeType.PinSetup)
    assertTrue(challenge.id == "native-configure-pin" && challenge.required && challenge.type.isRequiredAction)
    assertEquals(4, challenge.pinSetupParams?.length)

    var step = flow.respond(ChallengeAnswer.PinSetup("", ""), challenge)
    val missing = step.require(ChallengeType.PinSetup)
    assertEquals(ChallengeError.Code.MISSING_CREDENTIAL, missing.error?.code)

    step = flow.respond(ChallengeAnswer.PinSetup("1357", "1358"), missing)
    val mismatch = step.require(ChallengeType.PinSetup)
    assertEquals(ChallengeError.Code.PIN_MISMATCH, mismatch.error?.code)

    step = flow.respond(ChallengeAnswer.PinSetup("1111", "1111"), mismatch)
    val weak = step.require(ChallengeType.PinSetup)
    assertEquals(ChallengeError.Code.WEAK_PIN, weak.error?.code)

    step = flow.respond(ChallengeAnswer.PinSetup("12", "12"), weak)
    val format = step.require(ChallengeType.PinSetup)
    assertEquals(ChallengeError.Code.INVALID_FORMAT, format.error?.code)

    step = flow.respond(ChallengeAnswer.PinSetup("2580", "2580"), format)
    assertNotNull(step.credentials)
    assertEquals(0, transport.remaining)
    val logged = h.loggedEverything()
    assertFalse(logged.contains("2580") || logged.contains("1357"))
  }

  @Test
  fun aPinAnswerIsRefusedForAnotherType() = runTest {
    val (h, _, _) = Harness.replay(listOf("PinIT.peteSetsAPinInBand"), client)
    val (flow, challenge) = loginToPinStep(h, "pete", ChallengeType.PinSetup)
    val error = expectError { flow.respond(ChallengeAnswer.Pin("2580"), challenge) }
    assertEquals(NativeAuthError.Code.UNSUPPORTED_CHALLENGE, error.code)
  }
}
