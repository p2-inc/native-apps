package io.phasetwo.keycloak.nativeauth.sdk.support

import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import java.io.File
import java.net.URI
import java.nio.charset.StandardCharsets
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * A recorded integration-test transcript (`keycloak-native-auth/demo/transcripts/ *.json`, written by
 * `TranscriptRecorder.java`): the contract fixtures. The SDK must produce the recorded requests and
 * understand the recorded responses. Twin of the iOS SDK's `Transcript.swift`.
 */
@Serializable
data class Transcript(
  val test: String,
  @SerialName("base_url") val baseUrl: String,
  @SerialName("keycloak_image") val keycloakImage: String? = null,
  val exchanges: List<Exchange>,
) {
  @Serializable
  data class Exchange(val seq: Int, val request: Request, val response: Response)

  @Serializable
  data class Request(
    val method: String,
    val path: String,
    val headers: Map<String, String>? = null,
    val form: Map<String, String>? = null,
    val json: JsonElement? = null,
    val body: String? = null,
  ) {
    /** The request as the integration test sent it (masked values stay `***`). */
    fun toHttpRequest(baseUrl: String): HttpRequest {
      val body = when {
        form != null -> FormEncoding.encode(form.toList())
        json != null -> json.toString().toByteArray(StandardCharsets.UTF_8)
        else -> this.body?.toByteArray(StandardCharsets.UTF_8)
      }
      return HttpRequest(method, URI.create(baseUrl + path), headers.orEmpty(), body)
    }
  }

  @Serializable
  data class Response(
    val status: Int,
    val headers: Map<String, String>? = null,
    val json: JsonElement? = null,
    val body: String? = null,
  ) {
    val httpResponse: HttpResponse
      get() = HttpResponse(status, headers.orEmpty(), (json?.toString() ?: body ?: "").toByteArray(StandardCharsets.UTF_8))
  }

  /** The realm the test ran against. */
  val issuer: URI get() = URI.create("$baseUrl/realms/demo")

  fun exchange(seq: Int): Exchange = exchanges.first { it.seq == seq }

  fun exchanges(range: IntRange): List<Exchange> = exchanges.filter { it.seq in range }

  /** The form of request [seq] (secrets are `***`). */
  fun form(seq: Int): Map<String, String> = exchange(seq).request.form.orEmpty()

  companion object {
    private val json = Json { ignoreUnknownKeys = true }

    /** `KEYCLOAK_NATIVE_TRANSCRIPTS`, else the directory the Gradle test task passes in. */
    val directory: File
      get() = File(
        System.getenv("KEYCLOAK_NATIVE_TRANSCRIPTS")
          ?: System.getProperty("keycloak.native.transcripts")
          ?: error("no transcript directory: run through Gradle or set KEYCLOAK_NATIVE_TRANSCRIPTS"),
      )

    fun load(name: String): Transcript = parse(File(directory, "$name.json"))

    fun parse(file: File): Transcript = json.decodeFromString(serializer(), file.readText())

    fun all(): List<File> = directory.listFiles { f -> f.name.endsWith(".json") }.orEmpty().sortedBy { it.name }
  }
}
