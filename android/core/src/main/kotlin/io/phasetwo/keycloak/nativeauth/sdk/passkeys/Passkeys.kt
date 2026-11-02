package io.phasetwo.keycloak.nativeauth.sdk.passkeys

import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Passkey operations (spec/05 §2.2): platform assertion/registration for challenge params, and the §6
 * authenticated "add a passkey after login" sequence.
 */
public class Passkeys internal constructor(
  private val platform: PasskeyPlatform,
  private val issuerHost: String,
  private val allowRpIdMismatch: Boolean,
  private val registration: PasskeyRegistrationClient,
  private val logger: NativeAuthLogger,
) {
  /** Runs the platform assertion for a `passkey` challenge (allow-list or discoverable). */
  public suspend fun assert(params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Boolean = false): PasskeyAssertion {
    checkRpId(params.rpId)
    return platform.assert(params, preferImmediatelyAvailableCredentials)
  }

  /** Runs the platform registration for a `passkey_registration` challenge or §6 options. */
  public suspend fun register(params: PasskeyRegistrationParams): PasskeyAttestation {
    checkRpId(params.rp.id)
    return platform.register(params)
  }

  /**
   * spec/03 §6: options → platform registration → finish. Errors: `invalid_token` (401),
   * `insufficient_authorization` (403: the login is older than the realm's registration max age; step
   * up with the returned `auth_session`), `invalid_request` (400), `passkey_cancelled`.
   */
  public suspend fun registerNewPasskey(label: String?, credentials: Credentials): RegisteredPasskey {
    val options = registration.options(credentials)
    val attestation = register(options.params)
    return registration.finish(credentials, options.registrationId, attestation, label)
  }

  /**
   * The RP ID must be the issuer host or a registrable suffix of it (`example.com` for
   * `idp.example.com`), otherwise the platform would refuse the Digital Asset Links association
   * anyway. Overridable for development only (spec/12).
   */
  internal fun checkRpId(rpId: String) {
    val host = issuerHost.lowercase()
    val rp = rpId.lowercase()
    if (host.isEmpty() || host == rp || host.endsWith(".$rp")) return
    if (allowRpIdMismatch) {
      logger.log(LogLevel.WARNING) { "Passkey rp_id '$rpId' does not match issuer host '$issuerHost' (allowed by allowRpIdMismatch)" }
      return
    }
    throw NativeAuthError(
      NativeAuthError.Code.RP_ID_MISMATCH,
      errorDescription = "Passkey rp_id '$rpId' is not the issuer host '$issuerHost' or a parent domain of it; set allowRpIdMismatch for development setups",
    )
  }
}

/** `POST /native-auth/passkey/register/options` and `/finish` with the user's access token. */
internal class PasskeyRegistrationClient(
  private val issuer: URI,
  private val metadata: MetadataClient,
  private val transport: Transport,
  private val dpop: DPoPSigner?,
) {
  class Options(val registrationId: String, val params: PasskeyRegistrationParams, val raw: JsonElement)

  suspend fun options(credentials: Credentials): Options {
    val url = metadata.metadata().passkey?.registerOptionsEndpoint ?: URI.create("$issuer/native-auth/passkey/register/options")
    val response = send("POST", url, null, null, credentials)
    val json = response.json
    if (response.statusCode != 200 || json == null) throw error(response)
    val registrationId = json["registration_id"].stringValue
    val params = PasskeyRegistrationParams.parse(json)
    if (registrationId == null || params == null) {
      throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = 200, errorDescription = "Registration options are incomplete", details = json)
    }
    return Options(registrationId, params, json)
  }

  suspend fun finish(credentials: Credentials, registrationId: String, attestation: PasskeyAttestation, label: String?): RegisteredPasskey {
    val url = metadata.metadata().passkey?.registerFinishEndpoint ?: URI.create("$issuer/native-auth/passkey/register/finish")
    val body = LinkedHashMap(attestation.jsonFields)
    body["registration_id"] = JsonPrimitive(registrationId)
    if (!label.isNullOrEmpty()) body["label"] = JsonPrimitive(label)
    val response = send("POST", url, JsonObject(body).serialized().toByteArray(StandardCharsets.UTF_8), "application/json", credentials)
    val json = response.json
    if ((response.statusCode != 201 && response.statusCode != 200) || json == null) throw error(response)
    val credentialId = json["credential_id"].stringValue
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = response.statusCode, errorDescription = "finish response without credential_id", details = json)
    return RegisteredPasskey(credentialId, json["label"].stringValue)
  }

  private suspend fun send(method: String, url: URI, body: ByteArray?, contentType: String?, credentials: Credentials): HttpResponse {
    var response = transport.send(request(method, url, body, contentType, credentials))
    val nonce = if (dpop != null && credentials.isDPoPBound) DPoPSigner.nonceChallenge(response) else null
    if (nonce != null) {
      dpop!!.setNonce(nonce, url)
      response = transport.send(request(method, url, body, contentType, credentials))
    }
    return response
  }

  private suspend fun request(method: String, url: URI, body: ByteArray?, contentType: String?, credentials: Credentials): HttpRequest {
    val headers = linkedMapOf("Accept" to "application/json")
    if (contentType != null) headers["Content-Type"] = contentType
    headers["Authorization"] = "${credentials.authorizationScheme} ${credentials.accessToken}"
    if (credentials.isDPoPBound) dpop?.proof(method, url, credentials.accessToken)?.let { headers["DPoP"] = it }
    return HttpRequest(method, url, headers, body)
  }

  private fun error(response: HttpResponse): NativeAuthError = when (response.statusCode) {
    401 -> NativeAuthError.from(response, fallbackCode = NativeAuthError.Code.INVALID_TOKEN)
    403 -> NativeAuthError.from(response, fallbackCode = NativeAuthError.Code.INSUFFICIENT_AUTHORIZATION)
    else -> NativeAuthError.from(response)
  }
}
