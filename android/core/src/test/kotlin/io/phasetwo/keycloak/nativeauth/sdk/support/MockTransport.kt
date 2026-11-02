package io.phasetwo.keycloak.nativeauth.sdk.support

import io.phasetwo.keycloak.nativeauth.sdk.logging.Redactor
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Replays transcript exchanges in order. Every request the SDK sends must match the next recorded
 * request: same method and path, the same form field names, and the same values except for masked
 * (`***`) and per-run fields. A mismatch throws [Mismatch] so the test fails with a message. Same
 * rules as the iOS SDK's `MockTransport.swift`, so a re-recorded transcript fails both SDKs alike.
 */
class MockTransport(exchanges: List<Transcript.Exchange>) : Transport {
  class Mismatch(message: String) : AssertionError(message)

  private val queue = ArrayDeque(exchanges)
  private val sentRequests = mutableListOf<HttpRequest>()

  val sent: List<HttpRequest> @Synchronized get() = sentRequests.toList()
  val remaining: Int @Synchronized get() = queue.size

  override suspend fun send(request: HttpRequest): HttpResponse {
    val expected = synchronized(this) {
      sentRequests += request
      queue.removeFirstOrNull()
    } ?: throw Mismatch("unexpected request ${request.method} ${request.url.path}: transcript exhausted")
    match(request, expected.request, expected.seq)
    return expected.response.httpResponse
  }

  companion object {
    /** Fields whose value legitimately differs per run (PKCE, device ids): presence is still required. */
    val volatileFormFields: Set<String> = setOf("code_challenge", "device_id", "nonce")

    /** JSON fields that carry a per-run key (the rotated push device key, spec/03 §7). */
    val volatileJsonFields: Set<String> = setOf("publicKeyJwk")

    fun match(actual: HttpRequest, expected: Transcript.Request, seq: Int) {
      val prefix = "exchange #$seq ${expected.method} ${expected.path}: "
      if (actual.method != expected.method || actual.url.path != expected.path) {
        throw Mismatch(prefix + "SDK sent ${actual.method} ${actual.url.path}")
      }
      expected.headers?.get("Authorization")?.let { authorization ->
        val scheme = authorization.substringBefore(' ')
        val sent = actual.header("Authorization")
        if (sent == null || !sent.startsWith("$scheme ")) throw Mismatch(prefix + "expected an Authorization header with scheme $scheme")
      }
      expected.form?.let { form ->
        val fields = actual.formFields ?: throw Mismatch(prefix + "expected a form body")
        val actualForm = LinkedHashMap<String, String>().apply { fields.forEach { (name, value) -> putIfAbsent(name, value) } }
        for ((name, value) in form) {
          val sent = actualForm[name] ?: throw Mismatch(prefix + "missing form field $name")
          if (value == Redactor.MASK || name in volatileFormFields) continue
          if (sent != value) {
            val show = { v: String -> if (Redactor.isSensitive(name)) Redactor.MASK else v }
            throw Mismatch(prefix + "field $name: SDK sent '${show(sent)}', recorded '${show(value)}'")
          }
        }
        val extra = actualForm.keys - form.keys
        if (extra.isNotEmpty()) throw Mismatch(prefix + "SDK sent fields the test did not: ${extra.sorted()}")
      }
      (expected.json as? JsonObject)?.let { json ->
        val body = actual.body ?: throw Mismatch(prefix + "expected a JSON body")
        val actualJson = runCatching { Json.parseToJsonElement(String(body, Charsets.UTF_8)) }.getOrNull() as? JsonObject
          ?: throw Mismatch(prefix + "expected a JSON body")
        for ((key, value) in json) {
          val sent = actualJson[key] ?: throw Mismatch(prefix + "missing JSON field $key")
          val recorded = (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
          if (key == "transports" && recorded != null && sent is JsonArray) {
            if (sent.joinToString(",") { (it as JsonPrimitive).content } != recorded) throw Mismatch(prefix + "transports differ")
            continue
          }
          // Masked by the recorder (device-signed JWTs, spec/03 §7) or per-run: presence is enough.
          if (recorded == Redactor.MASK || key in volatileJsonFields) continue
          if (sent != value) throw Mismatch(prefix + "JSON field $key differs")
        }
      }
    }
  }
}
