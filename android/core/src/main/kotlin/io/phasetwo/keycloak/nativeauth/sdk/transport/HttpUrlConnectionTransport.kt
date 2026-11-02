package io.phasetwo.keycloak.nativeauth.sdk.transport

import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import java.io.IOException
import java.net.HttpURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * `HttpURLConnection` transport, the default on Android and the JVM (no extra dependency). Network
 * failures become [NativeAuthError] with `code == network_error`; HTTP status codes are never turned
 * into errors here. No caches, no redirects (the protocol has none), no cookies unless the app
 * installed a process-wide `CookieHandler`.
 */
public class HttpUrlConnectionTransport(
  private val connectTimeoutMillis: Int = 30_000,
  private val readTimeoutMillis: Int = 30_000,
) : Transport {
  override suspend fun send(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
    val connection = try {
      request.url.toURL().openConnection() as HttpURLConnection
    } catch (e: IOException) {
      throw NativeAuthError.network(e)
    } catch (e: IllegalArgumentException) {
      throw NativeAuthError(NativeAuthError.Code.INVALID_REQUEST, errorDescription = "Not a URL: ${request.url}", cause = e)
    }
    try {
      connection.requestMethod = request.method
      connection.instanceFollowRedirects = false
      connection.useCaches = false
      connection.connectTimeout = connectTimeoutMillis
      connection.readTimeout = readTimeoutMillis
      for ((name, value) in request.headers) connection.setRequestProperty(name, value)
      val body = request.body
      if (body != null) {
        connection.doOutput = true
        connection.setFixedLengthStreamingMode(body.size)
        connection.outputStream.use { it.write(body) }
      }
      val status = connection.responseCode
      val stream = if (status >= 400) connection.errorStream else connection.inputStream
      val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
      // The status line is listed under a null name.
      val headers = connection.headerFields.entries
        .mapNotNull { (name, values) -> name?.let { it to values.joinToString(", ") } }
        .toMap()
      HttpResponse(status, headers, bytes)
    } catch (e: IOException) {
      throw NativeAuthError.network(e)
    } finally {
      connection.disconnect()
    }
  }
}
