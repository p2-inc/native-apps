package io.phasetwo.keycloak.nativeauth.sdk.passkeys

import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringArray
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Converts between the spec/03 §4.3/§4.4 passkey params (snake_case) and the WebAuthn JSON that
 * platform APIs take and return (Credential Manager's `requestJson` / `authenticationResponseJson` /
 * `registrationResponseJson`, spec/17 §3): `PublicKeyCredentialRequestOptionsJSON` and
 * `…CreationOptionsJSON` out, `AuthenticationResponseJSON` and `RegistrationResponseJSON` back. Pure
 * JSON, so it lives in `core` and is tested on the JVM.
 */
public object WebAuthnJson {
  /** `PublicKeyCredentialRequestOptionsJSON` for a §4.3 assertion. */
  public fun requestOptions(params: PasskeyAssertionParams): String =
    obj(
      "challenge" to JsonPrimitive(params.challenge),
      "rpId" to JsonPrimitive(params.rpId),
      "timeout" to params.timeoutMilliseconds?.let(::JsonPrimitive),
      "userVerification" to JsonPrimitive(params.userVerification),
      "allowCredentials" to JsonArray(
        params.allowCredentials.map { credential ->
          obj(
            "type" to JsonPrimitive(credential.type),
            "id" to JsonPrimitive(credential.id),
            "transports" to credential.transports.takeIf { it.isNotEmpty() }?.let { list -> JsonArray(list.map(::JsonPrimitive)) },
          )
        },
      ),
    ).toString()

  /**
   * `PublicKeyCredentialCreationOptionsJSON` for a §4.4 / §6 registration. Credential Manager requires
   * `rp.name` and `user.displayName`, which the server may omit: they fall back to the RP id and the
   * user name.
   */
  public fun creationOptions(params: PasskeyRegistrationParams): String =
    obj(
      "challenge" to JsonPrimitive(params.challenge),
      "rp" to obj("id" to JsonPrimitive(params.rp.id), "name" to JsonPrimitive(params.rp.name ?: params.rp.id)),
      "user" to obj(
        "id" to JsonPrimitive(params.user.id),
        "name" to JsonPrimitive(params.user.name),
        "displayName" to JsonPrimitive(params.user.displayName ?: params.user.name),
      ),
      "pubKeyCredParams" to JsonArray(params.pubKeyCredParams.map { obj("type" to JsonPrimitive("public-key"), "alg" to JsonPrimitive(it)) }),
      "timeout" to params.timeoutMilliseconds?.let(::JsonPrimitive),
      "attestation" to JsonPrimitive(params.attestation),
      "excludeCredentials" to JsonArray(params.excludeCredentials.map { obj("type" to JsonPrimitive("public-key"), "id" to JsonPrimitive(it)) }),
      "authenticatorSelection" to obj(
        "residentKey" to params.residentKey?.let(::JsonPrimitive),
        "requireResidentKey" to JsonPrimitive(params.requireResidentKey),
        "userVerification" to JsonPrimitive(params.userVerification),
        "authenticatorAttachment" to params.authenticatorAttachment?.let(::JsonPrimitive),
      ),
    ).toString()

  /** The §4.3 form fields from an `AuthenticationResponseJSON`; `passkey_failed` when it is malformed. */
  public fun assertion(authenticationResponseJson: String): PasskeyAssertion {
    val json = parse(authenticationResponseJson)
    val response = json["response"]
    return PasskeyAssertion(
      credentialId = field(json["rawId"].stringValue ?: json["id"].stringValue, "rawId"),
      clientDataJson = field(response["clientDataJSON"].stringValue, "clientDataJSON"),
      authenticatorData = field(response["authenticatorData"].stringValue, "authenticatorData"),
      signature = field(response["signature"].stringValue, "signature"),
      userHandle = response["userHandle"].stringValue?.takeIf { it.isNotEmpty() }?.let { field(it, "userHandle") },
    )
  }

  /** The §4.4 / §6 fields from a `RegistrationResponseJSON`; `passkey_failed` when it is malformed. */
  public fun attestation(registrationResponseJson: String): PasskeyAttestation {
    val json = parse(registrationResponseJson)
    val response = json["response"]
    return PasskeyAttestation(
      credentialId = field(json["rawId"].stringValue ?: json["id"].stringValue, "rawId"),
      clientDataJson = field(response["clientDataJSON"].stringValue, "clientDataJSON"),
      attestationObject = field(response["attestationObject"].stringValue, "attestationObject"),
      transports = response["transports"].stringArray.orEmpty(),
    )
  }

  private fun parse(text: String): JsonElement =
    parseJsonOrNull(text)?.takeIf { it is JsonObject } ?: throw failed("the platform returned a response that is not a JSON object")

  /** Validates and normalizes to unpadded base64url: providers are not consistent about padding. */
  private fun field(value: String?, name: String): String {
    val bytes = value?.let(Base64Url::decode) ?: throw failed("the platform response has no valid $name")
    return Base64Url.encode(bytes)
  }

  private fun failed(description: String) = NativeAuthError(NativeAuthError.Code.PASSKEY_FAILED, errorDescription = description)

  private fun obj(vararg pairs: Pair<String, JsonElement?>): JsonObject =
    JsonObject(linkedMapOf(*pairs.mapNotNull { (key, value) -> value?.let { key to it } }.toTypedArray()))
}
