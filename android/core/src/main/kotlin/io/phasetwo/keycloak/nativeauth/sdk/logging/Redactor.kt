package io.phasetwo.keycloak.nativeauth.sdk.logging

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Masks secrets before anything reaches a log or the app's flow log: `auth_session`, codes, tokens,
 * passwords, OTPs, WebAuthn assertion/attestation material, push enrolment / confirm / device tokens
 * (spec/05 §3.3). The same key list as the iOS SDK's `Redactor`.
 */
public object Redactor {
  public const val MASK: String = "***"

  /** Form fields, JSON keys and header names (case-insensitive) whose values are never shown. */
  public val sensitiveKeys: Set<String> = setOf(
    "auth_session", "password", "password_confirm", "totp", "otp", "recovery_code",
    "authorization_code", "code", "code_verifier",
    "access_token", "refresh_token", "id_token", "token", "client_secret", "registration_id",
    "request_uri",
    "signature", "authenticator_data", "client_data_json", "attestation_object",
    "authorization", "dpop", "dpop-nonce",
    // Push MFA (spec/03 §4.15, §7): the realm-signed enrolment token, the device-signed JWTs
    // (`token`, above), the confirm token and the APNs / FCM device token.
    "enrollment_token", "confirmtoken", "confirm_token", "pushproviderid", "push_provider_id", "device_token",
  )

  public fun isSensitive(key: String): Boolean {
    val k = key.lowercase()
    // Extension parameters (spec/03 §2.3) carry deployment data such as device or risk signals.
    return k in sensitiveKeys || k.startsWith("x_")
  }

  public fun redactForm(fields: List<Pair<String, String>>): List<Pair<String, String>> =
    fields.map { (name, value) -> name to if (isSensitive(name)) MASK else value }

  /** Keeps the scheme ("Bearer ***") so a log still shows which kind of credential was sent. */
  public fun redactHeaders(headers: Map<String, String>): Map<String, String> =
    headers.mapValues { (name, value) ->
      if (!isSensitive(name)) value
      else value.indexOf(' ').let { space -> if (space >= 0) value.substring(0, space) + " " + MASK else MASK }
    }

  public fun redactJson(json: JsonElement): JsonElement = when (json) {
    is JsonObject -> JsonObject(json.mapValues { (key, value) -> if (isSensitive(key)) JsonPrimitive(MASK) else redactJson(value) })
    is JsonArray -> JsonArray(json.map(::redactJson))
    else -> json
  }
}
