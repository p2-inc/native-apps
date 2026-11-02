package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.WebAuthnJson
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The Credential Manager JSON bridge (spec/17 §3), against the AndroidOriginIT transcript: the
 * params the server sent become WebAuthn options, and a platform response built from the fields the
 * server accepted converts back to exactly those fields.
 */
class WebAuthnJsonTest {
  private val transcript = Transcript.load("AndroidOriginIT.aPasskeyWithAnAndroidOriginRegistersAndSignsInWhenTheOriginIsAllowed")

  private fun parse(text: String): JsonObject = Json.parseToJsonElement(text).jsonObject

  /** Standard-alphabet, padded base64 of the same bytes: some providers return that. */
  private fun padded(base64url: String): String = Base64.getEncoder().encodeToString(Base64Url.decode(base64url).req())

  @Test
  fun registrationParamsBecomeCreationOptions() {
    val raw = transcript.exchange(5).response.json.req()
    val options = parse(WebAuthnJson.creationOptions(PasskeyRegistrationParams.parse(raw).req()))
    assertEquals(
      parse(
        """
        {"challenge":"${raw["challenge"].stringValue}","rp":{"id":"localhost","name":"Native Auth Demo"},
         "user":{"id":"${raw["user"]["id"].stringValue}","name":"bob","displayName":"Bob Passwordonly"},
         "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
         "timeout":60000,"attestation":"none","excludeCredentials":[],
         "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required"}}
        """,
      ),
      options,
    )
  }

  @Test
  fun missingNamesFallBackBecauseCredentialManagerRequiresThem() {
    val raw = parse("""{"challenge":"AAAA","rp":{"id":"idp.example.com"},"user":{"id":"dXNlcg","name":"alice"},"pub_key_cred_params":[{"alg":-7}]}""")
    val options = parse(WebAuthnJson.creationOptions(PasskeyRegistrationParams.parse(raw).req()))
    assertEquals("idp.example.com", options["rp"]["name"].stringValue)
    assertEquals("alice", options["user"]["displayName"].stringValue)
    assertFalse("timeout" in options)
    assertFalse("residentKey" in options["authenticatorSelection"]!!.jsonObject)
  }

  @Test
  fun assertionParamsBecomeRequestOptions() {
    val raw = passkeyParams(transcript.exchange(8).response.json)
    val options = parse(WebAuthnJson.requestOptions(PasskeyAssertionParams.parse(raw).req()))
    assertEquals(
      parse(
        """
        {"challenge":"${raw["challenge"].stringValue}","rpId":"localhost","timeout":60000,"userVerification":"required",
         "allowCredentials":[{"type":"public-key","id":"${raw["allow_credentials"][0]["id"].stringValue}","transports":["internal","hybrid"]}]}
        """,
      ),
      options,
    )
  }

  @Test
  fun discoverableRequestHasAnEmptyAllowList() {
    val options = parse(WebAuthnJson.requestOptions(PasskeyAssertionParams.parse(parse("""{"challenge":"AAAA","rp_id":"localhost"}""")).req()))
    assertEquals(JsonArray(emptyList()), options["allowCredentials"])
    assertEquals("preferred", options["userVerification"].stringValue)
  }

  @Test
  fun authenticationResponseBecomesTheFieldsTheServerAccepted() {
    val sent = transcript.form(9)
    val response = """
      {"id":"${sent["credential_id"]}","rawId":"${padded(sent.getValue("credential_id"))}","type":"public-key","authenticatorAttachment":"platform",
       "response":{"clientDataJSON":"${padded(sent.getValue("client_data_json"))}","authenticatorData":"${sent["authenticator_data"]}",
                   "signature":"${sent["signature"]}","userHandle":"${sent["user_handle"]}"},
       "clientExtensionResults":{}}
    """
    val assertion = WebAuthnJson.assertion(response)
    val expected = sent.filterKeys { it in setOf("credential_id", "client_data_json", "authenticator_data", "signature", "user_handle") }
    assertEquals(expected, assertion.formFields.toMap())
  }

  @Test
  fun anEmptyUserHandleIsDropped() {
    val response = """{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AQ","signature":"Ag","userHandle":""}}"""
    assertNull(WebAuthnJson.assertion(response).userHandle)
  }

  @Test
  fun registrationResponseBecomesTheFinishBodyTheServerAccepted() {
    val sent = transcript.exchange(6).request.json.req().jsonObject
    val response = """
      {"id":"${sent["credential_id"].stringValue}","rawId":"${sent["credential_id"].stringValue}","type":"public-key",
       "response":{"clientDataJSON":"${sent["client_data_json"].stringValue}","attestationObject":"${padded(sent["attestation_object"].stringValue.req())}",
                   "transports":["internal","hybrid"]},
       "clientExtensionResults":{"credProps":{"rk":true}}}
    """
    val attestation = WebAuthnJson.attestation(response)
    // The test sent `transports` comma-separated; the SDK sends the array form (spec/03 §6 takes both).
    assertEquals("internal,hybrid", sent["transports"].stringValue)
    assertEquals(JsonArray(listOf(JsonPrimitive("internal"), JsonPrimitive("hybrid"))), attestation.jsonFields["transports"])
    assertEquals(sent.filterKeys { it !in setOf("registration_id", "label", "transports") }, attestation.jsonFields - "transports")
  }

  @Test
  fun malformedResponsesArePasskeyFailed() {
    for (text in listOf("not json", "[]", """{"id":"AQID","response":{}}""", """{"rawId":"*not base64*","response":{"clientDataJSON":"e30","attestationObject":"AQ"}}""")) {
      val error = assertThrows<NativeAuthError> { WebAuthnJson.attestation(text) }
      assertEquals(NativeAuthError.Code.PASSKEY_FAILED, error.code, text)
    }
  }

  private fun passkeyParams(body: JsonElement?): JsonElement =
    (body["challenges"] as JsonArray).first { it["type"] == JsonPrimitive("passkey") }["params"].req()
}
