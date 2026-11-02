package io.phasetwo.keycloak.nativeauth.sdk.transport

import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonElement

/** One HTTP request as the SDK builds it. [headers] are sent verbatim; [body] is already encoded. */
public class HttpRequest(
  public val method: String,
  public val url: URI,
  public val headers: Map<String, String> = emptyMap(),
  public val body: ByteArray? = null,
) {
  /**
   * The URL-encoded form fields when [body] is `application/x-www-form-urlencoded` (used by the
   * logger and tests), in the order they were encoded.
   */
  public val formFields: List<Pair<String, String>>?
    get() {
      val body = body ?: return null
      val type = header("Content-Type")?.lowercase() ?: return null
      if (!type.startsWith("application/x-www-form-urlencoded")) return null
      return FormEncoding.decode(body)
    }

  /** The header [name], matched case-insensitively. */
  public fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

  override fun toString(): String = "$method $url"
}

/** One HTTP response. Header names are matched case-insensitively through [header]. */
public class HttpResponse(
  public val statusCode: Int,
  public val headers: Map<String, String> = emptyMap(),
  public val body: ByteArray = ByteArray(0),
) {
  public fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

  public val bodyText: String get() = String(body, StandardCharsets.UTF_8)

  /** The body parsed as JSON; `null` when it is empty or not JSON. */
  public val json: JsonElement? get() = parseJsonOrNull(body)

  /**
   * RFC 9449 §8: the server wants a fresh nonce in the proof (`400`/`401 use_dpop_nonce` with a
   * `DPoP-Nonce` header). Modules outside core retry the request with it.
   */
  public val dpopNonceChallenge: String?
    get() {
      if (statusCode != 400 && statusCode != 401) return null
      if (json["error"].stringValue != "use_dpop_nonce") return null
      return header("DPoP-Nonce")
    }

  override fun toString(): String = "HTTP $statusCode (${body.size} bytes)"
}

/**
 * Transport abstraction: production uses an `HttpURLConnection` transport; tests replay recorded
 * transcripts. HTTP status codes are never turned into errors here.
 */
public fun interface Transport {
  public suspend fun send(request: HttpRequest): HttpResponse
}

/** `application/x-www-form-urlencoded` with the RFC 3986 unreserved set (space → `%20`), as the iOS SDK. */
public object FormEncoding {
  public const val CONTENT_TYPE: String = "application/x-www-form-urlencoded; charset=utf-8"

  public fun encode(fields: List<Pair<String, String>>): ByteArray =
    fields.joinToString("&") { (name, value) -> "${escape(name)}=${escape(value)}" }.toByteArray(StandardCharsets.UTF_8)

  /** Percent-encodes everything outside `A-Z a-z 0-9 - . _ ~`. */
  public fun escape(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

  public fun decode(body: ByteArray): List<Pair<String, String>> {
    val text = String(body, StandardCharsets.UTF_8)
    if (text.isEmpty()) return emptyList()
    return text.split('&').filter { it.isNotEmpty() }.map { pair ->
      val eq = pair.indexOf('=')
      if (eq < 0) unescape(pair) to "" else unescape(pair.substring(0, eq)) to unescape(pair.substring(eq + 1))
    }
  }

  private fun unescape(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)
}
