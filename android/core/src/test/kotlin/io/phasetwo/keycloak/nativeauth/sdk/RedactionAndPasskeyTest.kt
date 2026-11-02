package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeEndpointClient
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringArray
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.logging.Redactor
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.support.Harness
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.require
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import java.net.URI
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Twin of `RedactionAndPasskeyTests.swift`. */
class RedactionAndPasskeyTest {
  private val issuer = URI("https://idp.example.com/realms/demo")

  @Test
  fun formJsonAndHeaderRedaction() {
    val form = Redactor.redactForm(listOf("username" to "alice", "password" to "secret", "totp" to "123456", "auth_session" to "eyJ"))
    assertEquals(listOf("alice", "***", "***", "***"), form.map { it.second })
    // Phase 2b fields: the new password pair, the email verification code, recovery codes.
    val phase2b = Redactor.redactForm(listOf("password_confirm" to "secret", "code" to "123456", "recovery_code" to "ABCD-EFGH", "accepted" to "true"))
    assertEquals(listOf("***", "***", "***", "true"), phase2b.map { it.second })
    for (answer in listOf(ChallengeAnswer.UpdatePassword("s3cret", "s3cret"), ChallengeAnswer.VerifyEmail("123456"), ChallengeAnswer.Terms(true))) {
      for ((name, value) in Redactor.redactForm(answer.formFields)) if (name != "accepted") assertEquals("***", value, "$name must be masked")
    }
    val json = Redactor.redactJson(
      j("""{"authorization_code":"c","auth_session":"s","challenges":[{"params":{"signature":"x","rp_id":"localhost"}}],"access_token":"t"}"""),
    )
    assertEquals("***", json["authorization_code"].stringValue)
    assertEquals("***", json["auth_session"].stringValue)
    assertEquals("***", json["access_token"].stringValue)
    assertEquals("***", json["challenges"][0]["params"]["signature"].stringValue)
    assertEquals("localhost", json["challenges"][0]["params"]["rp_id"].stringValue)
    assertEquals(
      mapOf("Authorization" to "Bearer ***", "DPoP" to "***", "Accept" to "application/json"),
      Redactor.redactHeaders(mapOf("Authorization" to "Bearer abc", "DPoP" to "eyJ", "Accept" to "application/json")),
    )
    // Phase 3 (spec/03 §4.15, §7): enrolment token, device-signed JWTs, confirm token, device token.
    val push = Redactor.redactJson(
      j(
        """{"enrollment_token":"eyJ","token":"eyJ","confirmToken":"eyJ","pushProviderId":"0123abcd","publicKeyJwk":{"x":"keep"},
          "challenges":[{"params":{"enrollment_token":"eyJ","device_api_base":"https://idp/push-mfa","cid":"c1"}}]}""",
      ),
    )
    for (key in listOf("enrollment_token", "token", "confirmToken", "pushProviderId")) assertEquals("***", push[key].stringValue, "$key must be masked")
    assertEquals("keep", push["publicKeyJwk"]["x"].stringValue)
    assertEquals("***", push["challenges"][0]["params"]["enrollment_token"].stringValue)
    assertEquals("https://idp/push-mfa", push["challenges"][0]["params"]["device_api_base"].stringValue)
    assertTrue(Redactor.redactForm(ChallengeAnswer.PushEnrollment("eyJ.device.jwt").formFields).all { it.second == "***" })
    assertEquals(listOf("resend"), Redactor.redactForm(ChallengeAnswer.PushResend.formFields).map { it.second }, "actions are not secrets")
  }

  @Test
  fun flowLogNeverContainsSecrets() = runTest {
    val h = Harness(issuer, "c", ScriptedTransport({ ScriptedTransport.json(200, """{"authorization_code":"CODE-SECRET","auth_session":"SESSION-SECRET"}""") }))
    val client = ChallengeEndpointClient(URI("$issuer/native-auth/challenge"), h.sdk.transport, null)
    client.post(listOf("auth_session" to "SESSION-SECRET", "challenge_type" to "password", "challenge_id" to "e", "password" to "PASSWORD-SECRET"))
    val entry = h.observer.entries.first()
    val everything = (entry.requestBody ?: "") + (entry.responseBody ?: "") + h.logger.lines.joinToString("")
    for (secret in listOf("PASSWORD-SECRET", "SESSION-SECRET", "CODE-SECRET")) assertFalse(everything.contains(secret), "$secret leaked")
    assertTrue(entry.requestBody!!.contains("challenge_type=password"))
    assertEquals(200, entry.statusCode)
  }

  @Test
  fun cancellationIsPasskeyCancelledAndLeavesTheFlowPending() = runTest {
    val transport = ScriptedTransport(
      {
        ScriptedTransport.json(
          200,
          """{"protocol_version":"1","authorization_challenge_endpoint":"https://idp.example.com/realms/demo/native-auth/challenge",
            "token_endpoint":"https://idp.example.com/realms/demo/protocol/openid-connect/token","passkey":{"rp_id":"idp.example.com"}}""",
        )
      },
      {
        ScriptedTransport.json(
          403,
          """{"error":"insufficient_authorization","auth_session":"s","challenges":[
            {"type":"passkey","id":"p","required":false,"params":{"challenge":"AQID","rp_id":"idp.example.com","allow_credentials":[],"discoverable":true}},
            {"type":"username","id":"u","required":false}]}""",
        )
      },
    )
    val h = Harness(issuer, "c", transport)
    val flow = h.sdk.authentication().startLogin()
    val passkey = flow.start().challenges.req().require(ChallengeType.Passkey)

    h.passkeys.fail(NativeAuthError(NativeAuthError.Code.PASSKEY_CANCELLED, errorDescription = "The user cancelled the passkey prompt"))
    val error = expectError { h.sdk.passkeys().assert(passkey.passkeyParams.req()) }
    assertEquals(NativeAuthError.Code.PASSKEY_CANCELLED, error.code)
    assertEquals(NativeLoginFlow.State.AWAITING_ANSWER, flow.currentState, "the user can still pick another challenge")
    assertEquals(listOf("passkey", "username"), flow.pendingChallenges.types())
    assertEquals(2, transport.sent.size, "no request was made for the cancelled ceremony")
    assertTrue(h.passkeys.assertParams.first().discoverable)
  }

  @Test
  fun withoutAPlatformPasskeysAreUnavailable() = runTest {
    val sdk = KeycloakNative.configure(issuer, "c", KeycloakNative.Options(transport = ScriptedTransport({ HttpResponse(500) })))
    val params = PasskeyRegistrationParams.parse(j("""{"challenge":"AQID","rp":{"id":"idp.example.com"},"user":{"id":"dXNlcg","name":"alice"}}""")).req()
    assertEquals(NativeAuthError.Code.PASSKEY_UNAVAILABLE, expectError { sdk.passkeys().register(params) }.code)
  }

  @Test
  fun rpIdMustBeIssuerHostOrParentDomain() {
    fun passkeys(issuer: String, allow: Boolean = false) =
      Harness(URI(issuer), "c", ScriptedTransport({ HttpResponse(500) }), allowRpIdMismatch = allow).sdk.passkeys()
    assertDoesNotThrow { passkeys("https://idp.example.com/realms/demo").checkRpId("idp.example.com") }
    assertDoesNotThrow { passkeys("https://idp.example.com/realms/demo").checkRpId("example.com") }
    assertDoesNotThrow { passkeys("http://localhost:8089/realms/demo").checkRpId("localhost") }
    val mismatch = assertThrows(NativeAuthError::class.java) { passkeys("https://idp.example.com/realms/demo").checkRpId("other.example") }
    assertEquals(NativeAuthError.Code.RP_ID_MISMATCH, mismatch.code)
    assertThrows(NativeAuthError::class.java) { passkeys("https://idp.example.com/realms/demo").checkRpId("ple.com") }
    assertDoesNotThrow { passkeys("http://localhost:8089/realms/demo", allow = true).checkRpId("demo.ngrok.app") }
  }

  @Test
  fun registrationParamsReachThePlatformAndTransportsAreSent() = runTest {
    val h = Harness(issuer, "c", ScriptedTransport({ HttpResponse(500) }))
    val attestation = PasskeyAttestation("id", "cd", "ao", listOf("internal", "hybrid"))
    h.passkeys.enqueue(attestation)
    val params = PasskeyRegistrationParams.parse(j("""{"challenge":"AQID","rp":{"id":"idp.example.com"},"user":{"id":"dXNlcg","name":"alice"}}""")).req()
    assertEquals(attestation, h.sdk.passkeys().register(params))
    assertEquals("alice", h.passkeys.registerParams.first().user.name)
    assertEquals(listOf("internal", "hybrid"), (attestation.jsonFields["transports"] as JsonArray).stringArray)
    assertEquals(JsonPrimitive("id"), attestation.jsonFields["credential_id"])
  }
}
