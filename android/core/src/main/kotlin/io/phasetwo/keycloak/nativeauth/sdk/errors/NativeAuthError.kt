package io.phasetwo.keycloak.nativeauth.sdk.errors

import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.intValue
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import kotlinx.serialization.json.JsonElement

/**
 * The single error type of the SDK (spec/05 §2.3). Apps branch on [code], never on messages. Server
 * codes are the `error` values of spec/03 §3.5 / §6; SDK-local codes are listed in [Code] as well.
 * The same codes as the iOS SDK's `NativeAuthError`.
 */
public class NativeAuthError(
  public val code: String,
  public val statusCode: Int? = null,
  public val errorDescription: String? = null,
  /** A still-valid `auth_session` returned with the error (spec/03 §3.5), if any. */
  public val authSession: String? = null,
  /** Raw JSON body of the error response, when there was one. */
  public val details: JsonElement? = null,
  public val isNetworkError: Boolean = false,
  /** `true` for transient conditions (network, `slow_down`, `server_error`). */
  public val isRetryable: Boolean = false,
  /** `Retry-After` in seconds for `slow_down`. */
  public val retryAfter: Double? = null,
  cause: Throwable? = null,
) : Exception(errorDescription ?: code, cause) {

  /** Stable codes. Server-issued codes are passed through unchanged, so this list is not closed. */
  public object Code {
    // spec/03 §3.5 (challenge endpoint)
    public const val INVALID_REQUEST: String = "invalid_request"
    public const val INVALID_SESSION: String = "invalid_session"
    public const val INVALID_DPOP_PROOF: String = "invalid_dpop_proof"
    public const val INVALID_CLIENT: String = "invalid_client"
    public const val ACCESS_DENIED: String = "access_denied"
    public const val SLOW_DOWN: String = "slow_down"
    public const val CLIENT_ATTESTATION_REQUIRED: String = "client_attestation_required"
    public const val SERVER_ERROR: String = "server_error"

    /**
     * spec/03 §3.4: surfaces as `FlowStep.RedirectToWeb`; this code only appears when the body could
     * not be parsed into a `RedirectToWebRequest`.
     */
    public const val REDIRECT_TO_WEB: String = "redirect_to_web"

    // spec/03 §6 (bearer-authenticated endpoints) and the token endpoint
    public const val INVALID_TOKEN: String = "invalid_token"
    public const val INSUFFICIENT_AUTHORIZATION: String = "insufficient_authorization"
    public const val INVALID_GRANT: String = "invalid_grant"

    // SDK-local
    public const val NETWORK_ERROR: String = "network_error"
    public const val INVALID_RESPONSE: String = "invalid_response"
    public const val METADATA_UNAVAILABLE: String = "metadata_unavailable"
    public const val UNSUPPORTED_CHALLENGE: String = "unsupported_challenge"
    public const val FLOW_STATE: String = "flow_state"

    /** A caller-supplied extra field or parameter repeats a name the protocol or the answer uses. */
    public const val INVALID_PARAMETER: String = "invalid_parameter"
    public const val PASSKEY_CANCELLED: String = "passkey_cancelled"
    public const val PASSKEY_FAILED: String = "passkey_failed"
    public const val PASSKEY_UNAVAILABLE: String = "passkey_unavailable"
    public const val RP_ID_MISMATCH: String = "rp_id_mismatch"
    public const val CREDENTIALS_NOT_FOUND: String = "credentials_not_found"
    public const val REAUTHENTICATION_REQUIRED: String = "reauthentication_required"

    /** The secure store failed (the iOS SDK's `keychain_error`, kept for one code set). */
    public const val KEYCHAIN_ERROR: String = "keychain_error"

    /** A store item that needs user authentication was not unlocked (cancelled or failed). */
    public const val KEYCHAIN_AUTHENTICATION_FAILED: String = "keychain_authentication_failed"
    public const val DPOP_KEY_ERROR: String = "dpop_key_error"

    /** `WebFallback`: the user closed the browser (not a flow failure, the app may retry). */
    public const val WEB_FALLBACK_CANCELLED: String = "web_fallback_cancelled"
    public const val WEB_FALLBACK_FAILED: String = "web_fallback_failed"
  }

  public val authSessionStillValid: Boolean get() = authSession != null

  /** `max_age` from a §6 `insufficient_authorization` body: the freshness a step-up must satisfy. */
  public val maxAge: Int? get() = details["max_age"].intValue

  override fun toString(): String = buildString {
    append("NativeAuthError(").append(code)
    statusCode?.let { append(" http=").append(it) }
    errorDescription?.let { append(" \"").append(it).append('"') }
    append(')')
  }

  public companion object {
    internal fun network(error: Throwable): NativeAuthError = NativeAuthError(
      code = Code.NETWORK_ERROR,
      errorDescription = error.message ?: error.toString(),
      isNetworkError = true,
      isRetryable = true,
      cause = error,
    )

    /** Maps a JSON error body from any endpoint to an error, keeping the server's `error` code. */
    public fun from(response: HttpResponse, fallbackCode: String = Code.INVALID_RESPONSE): NativeAuthError {
      val json = parseJsonOrNull(response.body)
      val code = json["error"].stringValue ?: fallbackCode
      return NativeAuthError(
        code = code,
        statusCode = response.statusCode,
        errorDescription = json["error_description"].stringValue
          ?: if (json == null) "HTTP ${response.statusCode} without a JSON body" else null,
        authSession = json["auth_session"].stringValue,
        details = json,
        isRetryable = code == Code.SLOW_DOWN || code == Code.SERVER_ERROR || response.statusCode >= 500,
        retryAfter = response.header("Retry-After")?.trim()?.toDoubleOrNull(),
      )
    }
  }
}
