package io.phasetwo.keycloak.nativeauth.sdk.challenge

import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.arrayValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.intValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import kotlinx.serialization.json.JsonElement

/** A parsed `403 insufficient_authorization` body (spec/03 §3.2). */
internal class ChallengeSet(
  val authSession: String,
  val expiresIn: Int?,
  val protocolVersion: String?,
  val challenges: List<Challenge>,
  val context: FlowContext,
  val raw: JsonElement,
)

internal sealed class ChallengeOutcome {
  class AuthorizationCode(val code: String, val authSession: String?) : ChallengeOutcome()
  class Challenges(val set: ChallengeSet) : ChallengeOutcome()
  class RedirectToWeb(val request: RedirectToWebRequest) : ChallengeOutcome()
}

/**
 * Form-encoded transport to `POST /native-auth/challenge` (spec/05 §3.1): attaches a DPoP proof when
 * configured, retries once on `use_dpop_nonce`, parses 200 / 403 / 400 and maps everything else to
 * [NativeAuthError].
 */
internal class ChallengeEndpointClient(
  private val endpoint: URI,
  private val transport: Transport,
  private val dpop: DPoPSigner?,
) {
  suspend fun post(fields: List<Pair<String, String>>): ChallengeOutcome = parse(send(fields))

  /** Sends and returns the raw response (used by `cancel`, whose expected answer is an error). */
  suspend fun send(fields: List<Pair<String, String>>): HttpResponse {
    var response = transport.send(request(fields))
    val nonce = if (dpop != null) DPoPSigner.nonceChallenge(response) else null
    if (nonce != null) {
      dpop!!.setNonce(nonce, endpoint)
      response = transport.send(request(fields))
    }
    return response
  }

  private suspend fun request(fields: List<Pair<String, String>>): HttpRequest {
    val headers = linkedMapOf("Accept" to "application/json", "Content-Type" to FormEncoding.CONTENT_TYPE)
    dpop?.proof("POST", endpoint, accessToken = null)?.let { headers["DPoP"] = it }
    return HttpRequest("POST", endpoint, headers, FormEncoding.encode(fields))
  }

  companion object {
    fun parse(response: HttpResponse): ChallengeOutcome {
      val json = response.json ?: throw NativeAuthError(
        NativeAuthError.Code.INVALID_RESPONSE,
        statusCode = response.statusCode,
        errorDescription = "Challenge endpoint answered HTTP ${response.statusCode} without a JSON body",
      )
      if (response.statusCode == 200) {
        val code = json["authorization_code"].stringValue
          ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = 200, errorDescription = "200 without authorization_code", details = json)
        return ChallengeOutcome.AuthorizationCode(code, json["auth_session"].stringValue)
      }
      val error = json["error"].stringValue
      val challenges = json["challenges"].arrayValue
      // 403 per draft-04; 400 tolerated for older servers (spec/03 §3.2).
      if (error == NativeAuthError.Code.INSUFFICIENT_AUTHORIZATION && (response.statusCode == 403 || response.statusCode == 400) && challenges != null) {
        val authSession = json["auth_session"].stringValue
          ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = response.statusCode, errorDescription = "Challenge response without auth_session", details = json)
        return ChallengeOutcome.Challenges(
          ChallengeSet(
            authSession = authSession,
            expiresIn = json["expires_in"].intValue,
            protocolVersion = json["protocol_version"].stringValue,
            challenges = challenges.mapNotNull(Challenge::parse),
            context = FlowContext(json["context"]),
            raw = json,
          ),
        )
      }
      if (error == NativeAuthError.Code.REDIRECT_TO_WEB) {
        RedirectToWebRequest.parse(json)?.let { return ChallengeOutcome.RedirectToWeb(it) }
      }
      throw NativeAuthError.from(response)
    }
  }
}
