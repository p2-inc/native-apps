package io.phasetwo.keycloak.nativeauth.sdk.transport

import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.logging.Redactor
import java.net.URI
import java.time.Instant
import java.util.UUID

/**
 * A redacted record of one exchange, for the example app's Diagnostics flow log (spec/06 §1) and for
 * apps that want to show "what happened". Values are masked by [Redactor] before this is built.
 */
public data class FlowLogEntry(
  public val id: UUID,
  public val timestamp: Instant,
  public val method: String,
  public val url: URI,
  public val requestHeaders: Map<String, String>,
  /** Redacted form fields (`name=value`, one per line) or JSON for JSON bodies. */
  public val requestBody: String?,
  public val statusCode: Int?,
  public val responseHeaders: Map<String, String>,
  /** Redacted response JSON (pretty-printed) or a size note. */
  public val responseBody: String?,
  public val durationMilliseconds: Long,
  /** [NativeAuthError.code] when the transport failed. */
  public val errorCode: String?,
)

/** Receives every exchange the SDK makes, on the caller's coroutine (not the main thread). */
public fun interface FlowObserver {
  public fun record(entry: FlowLogEntry)
}

/** Wraps a transport, feeds the logger (debug) and the observer with redacted entries. */
internal class ObservingTransport(
  private val base: Transport,
  private val logger: NativeAuthLogger,
  private val observer: FlowObserver?,
) : Transport {
  override suspend fun send(request: HttpRequest): HttpResponse {
    val started = Instant.now()
    val startedNanos = System.nanoTime()
    logger.log(LogLevel.DEBUG) { "→ ${Redactor.describe(request)}" }
    try {
      val response = base.send(request)
      logger.log(LogLevel.DEBUG) { "← ${Redactor.describe(response)}" }
      observer?.record(entry(request, response, null, started, startedNanos))
      return response
    } catch (error: NativeAuthError) {
      logger.log(LogLevel.WARNING) { "✗ ${request.method} ${request.url}: ${error.code}" }
      observer?.record(entry(request, null, error, started, startedNanos))
      throw error
    }
  }

  private fun entry(request: HttpRequest, response: HttpResponse?, error: NativeAuthError?, started: Instant, startedNanos: Long): FlowLogEntry {
    val fields = request.formFields
    val body = request.body
    val requestBody = when {
      fields != null -> Redactor.redactForm(fields).joinToString("\n") { (name, value) -> "$name=$value" }
      body != null -> parseJsonOrNull(body)?.let { Redactor.redactJson(it).serialized(prettyPrinted = true) } ?: "(${body.size} bytes)"
      else -> null
    }
    val responseBody = response?.let { r ->
      r.json?.let { Redactor.redactJson(it).serialized(prettyPrinted = true) } ?: if (r.body.isEmpty()) null else "(${r.body.size} bytes)"
    }
    return FlowLogEntry(
      id = UUID.randomUUID(),
      timestamp = started,
      method = request.method,
      url = request.url,
      requestHeaders = Redactor.redactHeaders(request.headers),
      requestBody = requestBody,
      statusCode = response?.statusCode,
      responseHeaders = response?.let { Redactor.redactHeaders(it.headers) }.orEmpty(),
      responseBody = responseBody,
      durationMilliseconds = (System.nanoTime() - startedNanos) / 1_000_000,
      errorCode = error?.code,
    )
  }
}
