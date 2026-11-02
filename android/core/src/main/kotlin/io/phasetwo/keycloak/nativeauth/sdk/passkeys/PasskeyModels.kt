package io.phasetwo.keycloak.nativeauth.sdk.passkeys

import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/** The §4.3 wire fields of a WebAuthn assertion, all base64url without padding. */
public data class PasskeyAssertion(
  public val credentialId: String,
  public val clientDataJson: String,
  public val authenticatorData: String,
  public val signature: String,
  /** Present for resident credentials; names the user in discoverable logins. */
  public val userHandle: String?,
) {
  public val formFields: List<Pair<String, String>>
    get() = listOfNotNull(
      "credential_id" to credentialId,
      "client_data_json" to clientDataJson,
      "authenticator_data" to authenticatorData,
      "signature" to signature,
      userHandle?.let { "user_handle" to it },
    )

  public companion object {
    public fun of(credentialId: ByteArray, clientDataJson: ByteArray, authenticatorData: ByteArray, signature: ByteArray, userHandle: ByteArray?): PasskeyAssertion =
      PasskeyAssertion(
        Base64Url.encode(credentialId),
        Base64Url.encode(clientDataJson),
        Base64Url.encode(authenticatorData),
        Base64Url.encode(signature),
        userHandle?.let(Base64Url::encode),
      )
  }
}

/** The §4.4 / §6 wire fields of a WebAuthn registration (attestation), base64url without padding. */
public data class PasskeyAttestation(
  public val credentialId: String,
  public val clientDataJson: String,
  public val attestationObject: String,
  /** e.g. `["internal", "hybrid"]` for platform passkeys. */
  public val transports: List<String>,
) {
  public val formFields: List<Pair<String, String>>
    get() = listOf(
      "credential_id" to credentialId,
      "client_data_json" to clientDataJson,
      "attestation_object" to attestationObject,
      "transports" to transports.joinToString(","),
    )

  /** The §6 `finish` JSON body (without `registration_id` and `label`). */
  public val jsonFields: Map<String, JsonElement>
    get() = linkedMapOf(
      "credential_id" to JsonPrimitive(credentialId),
      "client_data_json" to JsonPrimitive(clientDataJson),
      "attestation_object" to JsonPrimitive(attestationObject),
      "transports" to JsonArray(transports.map(::JsonPrimitive)),
    )

  public companion object {
    public fun of(credentialId: ByteArray, clientDataJson: ByteArray, attestationObject: ByteArray, transports: List<String>): PasskeyAttestation =
      PasskeyAttestation(Base64Url.encode(credentialId), Base64Url.encode(clientDataJson), Base64Url.encode(attestationObject), transports)
  }
}

/** Result of a §6 registration. */
public data class RegisteredPasskey(public val credentialId: String, public val label: String?)

/**
 * The platform half of the passkey bridge (spec/05 §3.2): produce an assertion or an attestation from
 * the server's params. The `android` module provides one over Credential Manager; tests inject a
 * mock. Cancellation must surface as `passkey_cancelled`, never as a flow failure.
 */
public interface PasskeyPlatform {
  public suspend fun assert(params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Boolean): PasskeyAssertion

  public suspend fun register(params: PasskeyRegistrationParams): PasskeyAttestation
}
