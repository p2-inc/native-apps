package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeEndpointClient
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeOutcome
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowContext
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.config.NativeAuthMetadata
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.boolValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAssertion
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.support.types
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal fun j(text: String): JsonElement = Json.parseToJsonElement(text)

/** Twin of `ChallengeParsingTests.swift` and `MetadataTests`. */
class ChallengeParsingTest {
  private fun parse(status: Int, json: String) = ChallengeEndpointClient.parse(ScriptedTransport.json(status, json))

  private fun parseError(response: HttpResponse) = assertThrows(NativeAuthError::class.java) { ChallengeEndpointClient.parse(response) }

  private fun challenges(outcome: ChallengeOutcome) = (outcome as? ChallengeOutcome.Challenges)?.set.req("expected challenges")

  @Test
  fun unknownChallengeTypesAreKeptAsUnknown() {
    val set = challenges(
      parse(
        403,
        """{"error":"insufficient_authorization","auth_session":"s","challenges":[
          {"type":"x-vendor-foo","id":"1","required":true,"params":{"k":"v"}},
          {"type":"password","id":"2","required":false},
          {"id":"no-type"}]}""",
      ),
    )
    assertEquals(2, set.challenges.size, "descriptors without type/id are dropped")
    assertEquals(ChallengeType.Unknown("x-vendor-foo"), set.challenges[0].type)
    assertFalse(set.challenges[0].type.isSupported)
    assertEquals("v", set.challenges[0].params["k"].stringValue)
    assertTrue(set.challenges[1].type == ChallengeType.Password && !set.challenges[1].required)
    assertEquals(listOf("password"), FlowStep.Challenges(set.challenges, FlowContext.EMPTY).supportedChallenges.types())
  }

  @Test
  fun http400IsToleratedForInsufficientAuthorization() {
    val set = challenges(
      parse(400, """{"error":"insufficient_authorization","auth_session":"s","expires_in":12,"challenges":[{"type":"username","id":"e1"}],"context":{"client_name":"Demo"}}"""),
    )
    assertTrue(set.authSession == "s" && set.expiresIn == 12 && set.context.clientName == "Demo")
  }

  @Test
  fun successBodyYieldsCodeAndPostLoginSession() {
    val outcome = parse(200, """{"authorization_code":"c","auth_session":"post"}""") as ChallengeOutcome.AuthorizationCode
    assertTrue(outcome.code == "c" && outcome.authSession == "post")
  }

  @Test
  fun errorsKeepServerCodeAndOptionalAuthSession() {
    parseError(ScriptedTransport.json(200, """{"foo":"bar"}"""))

    val invalidRequest = parseError(ScriptedTransport.json(400, """{"error":"invalid_request","error_description":"bad","auth_session":"still"}"""))
    assertEquals("invalid_request", invalidRequest.code)
    assertTrue(invalidRequest.authSession == "still" && invalidRequest.authSessionStillValid)
    assertEquals(400, invalidRequest.statusCode)

    val redirect = parseError(ScriptedTransport.json(403, """{"error":"redirect_to_web","request_uri":"urn:x","expires_in":90}"""))
    assertEquals(NativeAuthError.Code.REDIRECT_TO_WEB, redirect.code)
    assertEquals("urn:x", redirect.details["request_uri"].stringValue)

    val slowDown = parseError(HttpResponse(429, mapOf("Content-Type" to "application/json", "Retry-After" to "7"), """{"error":"slow_down"}""".toByteArray()))
    assertTrue(slowDown.isRetryable && slowDown.retryAfter == 7.0)

    val notJson = parseError(HttpResponse(502, emptyMap(), "<html>".toByteArray()))
    assertTrue(notJson.code == NativeAuthError.Code.INVALID_RESPONSE && notJson.statusCode == 502)
  }

  @Test
  fun typedParamsDecodeSnakeCase() {
    val passkey = Challenge.parse(
      j(
        """{"type":"passkey","id":"e","label":"Sign in","required":false,
          "error":{"code":"invalid_credential","message":"nope"},"retry":{"remaining":2},
          "params":{"challenge":"AQID","rp_id":"localhost","timeout":60000,"user_verification":"required",
            "allow_credentials":[{"type":"public-key","id":"BAUG","transports":["internal","hybrid"]}],"discoverable":false}}""",
      ),
    ).req()
    val p = passkey.passkeyParams.req()
    assertTrue(p.rpId == "localhost" && p.timeoutMilliseconds == 60000 && p.userVerification == "required")
    assertArrayEquals(byteArrayOf(1, 2, 3), p.challengeBytes)
    assertArrayEquals(byteArrayOf(4, 5, 6), p.allowCredentials.first().idBytes)
    assertEquals(listOf("internal", "hybrid"), p.allowCredentials.first().transports)
    assertFalse(p.discoverable)
    assertTrue(passkey.error?.code == "invalid_credential" && passkey.retry?.remaining == 2 && passkey.label == "Sign in")

    val registration = Challenge.parse(
      j(
        """{"type":"passkey_registration","id":"native-passkey-register","params":{
          "challenge":"AQID","rp":{"id":"localhost","name":"Demo"},"user":{"id":"dXNlcg","name":"dave","display_name":"Dave E"},
          "pub_key_cred_params":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
          "authenticator_selection":{"resident_key":"required","require_resident_key":true,"user_verification":"required"},
          "attestation":"none","exclude_credentials":[{"type":"public-key","id":"BAUG"}],"timeout":60000}}""",
      ),
    ).req()
    val r = registration.passkeyRegistrationParams.req()
    assertTrue(r.rp.id == "localhost" && r.rp.name == "Demo")
    assertTrue(r.user.name == "dave" && r.user.displayName == "Dave E")
    assertArrayEquals("user".toByteArray(), r.user.idBytes)
    assertEquals(listOf(-7, -257), r.pubKeyCredParams)
    assertTrue(r.residentKey == "required" && r.requireResidentKey && r.userVerification == "required")
    assertTrue(r.excludeCredentials == listOf("BAUG") && r.attestation == "none")

    val totp = Challenge.parse(
      j("""{"type":"totp","id":"t","params":{"digits":6,"period":30,"algorithm":"HmacSHA1","credential_labels":["Phone"],"credentials":[{"id":"c1","label":"Phone"}]}}"""),
    ).req()
    assertTrue(totp.totpParams?.credentials?.first()?.id == "c1" && totp.totpParams?.digits == 6)
    assertNull(totp.passkeyParams)
  }

  @Test
  fun answersProduceWireFields() {
    assertEquals(listOf("totp", "credential_id"), ChallengeAnswer.Totp("123456", credentialId = "c1").formFields.map { it.first })
    assertEquals(listOf("totp"), ChallengeAnswer.Totp("123456").formFields.map { it.first })
    val assertion = PasskeyAssertion("a", "b", "c", "d", null)
    assertEquals(listOf("credential_id", "client_data_json", "authenticator_data", "signature"), ChallengeAnswer.Passkey(assertion).formFields.map { it.first })
    val attestation = PasskeyAttestation("a", "b", "c", listOf("internal", "hybrid"))
    val fields = ChallengeAnswer.PasskeyRegistration(attestation, label = "My phone").formFields
    assertEquals(listOf("credential_id", "client_data_json", "attestation_object", "transports", "label"), fields.map { it.first })
    assertEquals("internal,hybrid", fields.first { it.first == "transports" }.second)
  }

  @Test
  fun decodesRecordedMetadataAndIgnoresUnknownFields() {
    val response = Transcript.load("NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath").exchange(1).response.httpResponse
    val metadata = NativeAuthMetadata.parse(response.json.req())
    assertTrue(metadata.protocolVersion == "1" && metadata.protocolMajorVersion == 1)
    assertEquals("draft-ietf-oauth-first-party-apps-04", metadata.fipaDraft)
    assertEquals("/realms/demo/native-auth/challenge", metadata.authorizationChallengeEndpoint.path)
    assertEquals("/realms/demo/protocol/openid-connect/token", metadata.tokenEndpoint.path)
    assertFalse(metadata.codeExchange.redirectUriRequired)
    assertEquals("localhost", metadata.passkey?.rpId)
    assertEquals("/realms/demo/native-auth/passkey/register/finish", metadata.passkey?.registerFinishEndpoint?.path)
    assertEquals(
      setOf("otp", "passkey", "passkey_registration", "password", "totp", "username", "update_password", "verify_email", "terms", "recovery_code", "push", "push_enrollment"),
      metadata.challengeTypesSupported.toSet(),
    )
    assertTrue(metadata.supports(ChallengeType.Passkey) && metadata.supports(ChallengeType.Otp) && metadata.supports(ChallengeType.Push))
    assertTrue("ES256" in metadata.dpopSigningAlgValuesSupported, "the challenge endpoint verifies and binds proofs (spec/13 D3)")
    assertEquals("/realms/demo/protocol/openid-connect/auth", metadata.authorizationEndpoint?.path)
    assertEquals(false, metadata.clientAttestation?.required)
    assertTrue(metadata.raw["push"] != null && metadata.push!!.deviceToken == "native" && metadata.push.enabled)
  }

  @Test
  fun minimalDocumentAndExtraFields() {
    val metadata = NativeAuthMetadata.parse(
      j("""{"protocol_version":"1.2","authorization_challenge_endpoint":"https://a/c","token_endpoint":"https://a/t","push":{"enabled":true},"new_field":1}"""),
    )
    assertEquals(1, metadata.protocolMajorVersion)
    assertFalse(metadata.codeExchange.redirectUriRequired)
    assertNull(metadata.passkey)
    assertEquals(true, metadata.raw["push"]["enabled"].boolValue)
    assertNotNull(metadata.push)
    assertThrows(IllegalArgumentException::class.java) { NativeAuthMetadata.parse(j("""{"protocol_version":"1"}""")) }
  }
}
