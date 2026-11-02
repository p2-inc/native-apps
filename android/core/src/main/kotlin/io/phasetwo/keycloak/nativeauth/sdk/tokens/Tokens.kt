package io.phasetwo.keycloak.nativeauth.sdk.tokens

import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.doubleValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.time.Instant
import kotlin.time.Duration
import kotlinx.serialization.json.JsonElement

/** Tokens obtained from the realm's token endpoint plus the post-login `auth_session` (spec/05 §6). */
public class Credentials(
  public val accessToken: String,
  /** `Bearer`, or `DPoP` when the server bound the token to the SDK's key. */
  public val tokenType: String = "Bearer",
  public val refreshToken: String?,
  public val idToken: String?,
  public val scope: String?,
  expiresAt: Instant,
  /** [Instant.MAX] for an offline token (`refresh_expires_in: 0`). */
  refreshExpiresAt: Instant?,
  issuedAt: Instant = Instant.now(),
  /**
   * Post-login value from the success body (spec/03 §3.1), kept for step-up (spec/03 §5). The SDK
   * presents it only when a step-up flow is started.
   */
  public val authSession: String?,
) {
  // Whole seconds, so a stored copy compares equal.
  public val expiresAt: Instant = wholeSeconds(expiresAt)
  public val refreshExpiresAt: Instant? = refreshExpiresAt?.let(::wholeSeconds)
  public val issuedAt: Instant = wholeSeconds(issuedAt)

  public fun isExpired(at: Instant = Instant.now(), leeway: Duration = Duration.ZERO): Boolean =
    !at.plusMillis(leeway.inWholeMilliseconds).isBefore(expiresAt)

  /** Scheme for the `Authorization` header of resource requests. */
  public val authorizationScheme: String get() = if (tokenType.equals("DPoP", ignoreCase = true)) "DPoP" else "Bearer"

  public val isDPoPBound: Boolean get() = authorizationScheme == "DPoP"

  /** Unverified claims, for display only. */
  public val idTokenClaims: JsonElement? get() = idToken?.let(Jwt::decodePayload)
  public val accessTokenClaims: JsonElement? get() = Jwt.decodePayload(accessToken)

  public fun copy(
    accessToken: String = this.accessToken,
    tokenType: String = this.tokenType,
    refreshToken: String? = this.refreshToken,
    idToken: String? = this.idToken,
    scope: String? = this.scope,
    expiresAt: Instant = this.expiresAt,
    refreshExpiresAt: Instant? = this.refreshExpiresAt,
    issuedAt: Instant = this.issuedAt,
    authSession: String? = this.authSession,
  ): Credentials = Credentials(accessToken, tokenType, refreshToken, idToken, scope, expiresAt, refreshExpiresAt, issuedAt, authSession)

  public fun withAuthSession(authSession: String?): Credentials = copy(authSession = authSession)

  override fun equals(other: Any?): Boolean =
    other is Credentials && other.accessToken == accessToken && other.tokenType == tokenType && other.refreshToken == refreshToken &&
      other.idToken == idToken && other.scope == scope && other.expiresAt == expiresAt && other.refreshExpiresAt == refreshExpiresAt &&
      other.issuedAt == issuedAt && other.authSession == authSession

  override fun hashCode(): Int = accessToken.hashCode()

  /** Never prints a token. */
  override fun toString(): String = "Credentials(tokenType=$tokenType, expiresAt=$expiresAt, scope=$scope)"

  private companion object {
    fun wholeSeconds(instant: Instant): Instant = if (instant == Instant.MAX) instant else Instant.ofEpochSecond(instant.epochSecond)
  }
}

/**
 * The standard Keycloak token endpoints (spec/05 §2.2): exchange, refresh, revoke, logout. DPoP proofs
 * are attached when the SDK has a key; whether the server binds is read from `token_type`.
 */
public class Tokens internal constructor(
  private val clientId: String,
  private val issuer: URI,
  private val metadata: MetadataClient,
  private val transport: Transport,
  private val dpop: DPoPSigner?,
) {
  /**
   * `grant_type=authorization_code` without `redirect_uri` unless metadata says otherwise (spec/03
   * §3.1, spec/09 Q1). A code issued by the browser flow (`WebFallback`) always sends the
   * `redirect_uri` it was issued for.
   */
  public suspend fun exchange(code: String, codeVerifier: String, authSession: String? = null, redirectUri: String? = null): Credentials {
    val document = metadata.metadata()
    val fields = mutableListOf(
      "grant_type" to "authorization_code",
      "client_id" to clientId,
      "code" to code,
      "code_verifier" to codeVerifier,
    )
    if (redirectUri != null) {
      fields += "redirect_uri" to redirectUri
    } else if (document.codeExchange.redirectUriRequired) {
      val required = document.codeExchange.redirectUri
        ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "Metadata requires redirect_uri but names none")
      fields += "redirect_uri" to required
    }
    return parseTokenResponse(post(document.tokenEndpoint, fields), authSession)
  }

  /** `grant_type=refresh_token`; keeps the stored `auth_session`. */
  public suspend fun refresh(credentials: Credentials): Credentials {
    val refreshToken = credentials.refreshToken
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_GRANT, errorDescription = "No refresh token")
    val document = metadata.metadata()
    val response = post(document.tokenEndpoint, listOf("grant_type" to "refresh_token", "client_id" to clientId, "refresh_token" to refreshToken))
    return parseTokenResponse(response, credentials.authSession)
  }

  /** RFC 7009 revocation (`/protocol/openid-connect/revoke`). */
  public suspend fun revoke(token: String, tokenTypeHint: String? = "refresh_token") {
    val fields = listOfNotNull("client_id" to clientId, "token" to token, tokenTypeHint?.let { "token_type_hint" to it })
    val response = post(oidcEndpoint("revoke"), fields, withProof = false)
    if (response.statusCode !in 200..299) throw NativeAuthError.from(response)
  }

  /** RP-initiated logout with the refresh token (`/protocol/openid-connect/logout`). */
  public suspend fun logout(refreshToken: String) {
    val response = post(oidcEndpoint("logout"), listOf("client_id" to clientId, "refresh_token" to refreshToken), withProof = false)
    if (response.statusCode !in 200..299) throw NativeAuthError.from(response)
  }

  internal fun oidcEndpoint(name: String): URI = URI.create("$issuer/protocol/openid-connect/$name")

  private suspend fun post(url: URI, fields: List<Pair<String, String>>, withProof: Boolean = true): HttpResponse {
    var response = transport.send(request(url, fields, withProof))
    val nonce = if (withProof && dpop != null) DPoPSigner.nonceChallenge(response) else null
    if (nonce != null) {
      dpop!!.setNonce(nonce, url)
      response = transport.send(request(url, fields, withProof = true))
    }
    return response
  }

  private suspend fun request(url: URI, fields: List<Pair<String, String>>, withProof: Boolean): HttpRequest {
    val headers = linkedMapOf("Accept" to "application/json", "Content-Type" to FormEncoding.CONTENT_TYPE)
    if (withProof) dpop?.proof("POST", url, accessToken = null)?.let { headers["DPoP"] = it }
    return HttpRequest("POST", url, headers, FormEncoding.encode(fields))
  }

  internal companion object {
    fun parseTokenResponse(response: HttpResponse, authSession: String?, now: Instant = Instant.now()): Credentials {
      val json = response.json
      if (response.statusCode != 200 || json == null) throw NativeAuthError.from(response, fallbackCode = NativeAuthError.Code.INVALID_GRANT)
      val accessToken = json["access_token"].stringValue
        ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = 200, errorDescription = "Token response without access_token", details = json)
      val expiresIn = json["expires_in"].doubleValue ?: 300.0
      val refreshExpiresIn = json["refresh_expires_in"].doubleValue
      return Credentials(
        accessToken = accessToken,
        tokenType = json["token_type"].stringValue ?: "Bearer",
        refreshToken = json["refresh_token"].stringValue,
        idToken = json["id_token"].stringValue,
        scope = json["scope"].stringValue,
        expiresAt = now.plusMillis((expiresIn * 1000).toLong()),
        refreshExpiresAt = refreshExpiresIn?.let { if (it > 0) now.plusMillis((it * 1000).toLong()) else Instant.MAX },
        issuedAt = now,
        authSession = authSession,
      )
    }
  }
}
