package io.phasetwo.keycloak.nativeauth.sdk.web

import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.RedirectToWebRequest
import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import java.net.URI

/**
 * The platform half of the browser fallback (spec/03 §3.4): open [url] in the browser and hand back
 * the callback URL. The `android` module provides one over Auth Tab / Custom Tabs; tests inject a
 * mock. The user closing the browser must surface as `web_fallback_cancelled`.
 *
 * [redirectUri] is the request's `redirect_uri`, always with a scheme. Where iOS only needs the
 * callback scheme, Android's Auth Tab needs the host and path too when the redirect is an `https` App
 * Link.
 */
public fun interface WebAuthenticationPresenter {
  public suspend fun authenticate(url: URI, redirectUri: URI): URI
}

/**
 * Completes a `redirect_to_web` step (spec/03 §3.4, spec/05 §2.2): opens the realm's authorization
 * endpoint with `client_id` + `request_uri` in the browser, checks `state` on the callback, and
 * exchanges the code with the native flow's PKCE verifier and the `redirect_uri` of the request.
 */
public class WebFallback internal constructor(
  private val clientId: String,
  private val issuer: URI,
  private val metadata: MetadataClient,
  private val presenter: WebAuthenticationPresenter?,
  private val tokens: Tokens,
  private val logger: NativeAuthLogger,
) {
  /** The URL the browser is sent to (exposed for apps that want to open it themselves). */
  public suspend fun authorizationUrl(request: RedirectToWebRequest): URI {
    val endpoint = metadata.metadata().authorizationEndpoint ?: URI.create("$issuer/protocol/openid-connect/auth")
    val query = FormEncoding.encode(listOf("client_id" to clientId, "request_uri" to request.requestUri)).toString(Charsets.UTF_8)
    val separator = if (endpoint.rawQuery == null) "?" else "&"
    return URI.create(endpoint.toString() + separator + query)
  }

  /**
   * Runs the browser and exchanges the code. [flow] is the flow that produced the step (its PKCE
   * verifier signs the exchange). Errors: `web_fallback_cancelled`, `web_fallback_failed`,
   * `invalid_response` (state mismatch / no code), the server's `error` from the callback, and token
   * endpoint errors.
   */
  public suspend fun complete(request: RedirectToWebRequest, flow: NativeLoginFlow): Credentials = complete(request, flow.pkce.verifier)

  public suspend fun complete(request: RedirectToWebRequest, codeVerifier: String): Credentials {
    val redirectUri = request.callbackScheme?.let { URI(request.redirectUri) }
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "redirect_uri '${request.redirectUri}' has no scheme", details = request.raw)
    val presenter = presenter
      ?: throw NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_FAILED, errorDescription = "No WebAuthenticationPresenter is configured")
    val url = authorizationUrl(request)
    logger.log(LogLevel.INFO) { "Opening the browser for ${request.reason ?: "redirect_to_web"}" }
    val callback = presenter.authenticate(url, redirectUri)
    val code = code(callback, request.state)
    return tokens.exchange(code, codeVerifier, redirectUri = request.redirectUri)
  }

  internal companion object {
    /** Extracts `code` from the callback, enforcing `state` and surfacing an OAuth `error`. */
    fun code(callback: URI, expectedState: String?): String {
      val items = callback.rawQuery?.let { FormEncoding.decode(it.toByteArray(Charsets.UTF_8)) }.orEmpty()
      fun value(name: String) = items.firstOrNull { it.first == name }?.second
      value("error")?.let { throw NativeAuthError(it, errorDescription = value("error_description") ?: "The browser flow failed") }
      if (expectedState != null && value("state") != expectedState) {
        throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "state on the callback does not match the redirect_to_web request")
      }
      return value("code")?.takeIf { it.isNotEmpty() }
        ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "Callback without a code")
    }
  }
}
