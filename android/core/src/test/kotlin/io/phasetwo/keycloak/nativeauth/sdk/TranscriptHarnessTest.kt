package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.support.MockTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.Transcript
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import java.net.URI
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows

/**
 * The replay harness itself (spec/17 §5), before any SDK code drives it: every committed transcript
 * parses, every recorded request is accepted when replayed as recorded, and the matching rules
 * reject what the iOS harness rejects.
 */
class TranscriptHarnessTest {

  private val passwordLogin = "NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri"

  @TestFactory
  fun everyTranscriptReplaysAsRecorded(): List<DynamicTest> {
    val files = Transcript.all()
    assertTrue(files.size >= 70, "found ${files.size} transcripts in ${Transcript.directory}")
    return files.map { file ->
      DynamicTest.dynamicTest(file.nameWithoutExtension) {
        val transcript = Transcript.parse(file)
        assertEquals(file.nameWithoutExtension, transcript.test)
        assertTrue(transcript.exchanges.isNotEmpty())
        val transport = MockTransport(transcript.exchanges)
        runTest {
          for (exchange in transcript.exchanges) {
            val response = transport.send(exchange.request.toHttpRequest(transcript.baseUrl))
            assertEquals(exchange.response.status, response.statusCode)
          }
        }
        assertEquals(0, transport.remaining)
      }
    }
  }

  /** The first challenge request of the password login, as the SDK would send it. */
  private fun firstChallenge(edit: (MutableMap<String, String>) -> Unit = {}): Pair<Transcript, HttpRequest> {
    val transcript = Transcript.load(passwordLogin)
    val exchange = transcript.exchanges.first { it.request.form?.containsKey("client_id") == true && it.request.path.endsWith("/native-auth/challenge") }
    val form = exchange.request.form!!.toMutableMap().also(edit)
    val request = HttpRequest(
      "POST", URI.create(transcript.baseUrl + exchange.request.path),
      mapOf("Content-Type" to FormEncoding.CONTENT_TYPE, "Accept" to "application/json"),
      FormEncoding.encode(form.toList()),
    )
    return transcript to request
  }

  private fun matchFirst(request: HttpRequest, transcript: Transcript) {
    val exchange = transcript.exchanges.first { it.request.form?.containsKey("client_id") == true && it.request.path.endsWith("/native-auth/challenge") }
    MockTransport.match(request, exchange.request, exchange.seq)
  }

  @Test
  fun perRunFieldsMayDiffer() {
    val (transcript, request) = firstChallenge { it["code_challenge"] = "a-different-pkce-challenge" }
    matchFirst(request, transcript)
  }

  @Test
  fun aChangedValueIsRejected() {
    val (transcript, request) = firstChallenge { it["client_id"] = "someone-else" }
    val e = assertThrows<MockTransport.Mismatch> { matchFirst(request, transcript) }
    assertTrue(e.message!!.contains("field client_id"), e.message)
  }

  @Test
  fun anExtraFieldIsRejected() {
    val (transcript, request) = firstChallenge { it["x_extra"] = "1" }
    val e = assertThrows<MockTransport.Mismatch> { matchFirst(request, transcript) }
    assertTrue(e.message!!.contains("x_extra"), e.message)
  }

  @Test
  fun aMissingFieldIsRejected() {
    val (transcript, request) = firstChallenge { it.remove("scope") }
    val e = assertThrows<MockTransport.Mismatch> { matchFirst(request, transcript) }
    assertTrue(e.message!!.contains("missing form field scope"), e.message)
  }

  @Test
  fun anotherPathIsRejected() {
    val (transcript, request) = firstChallenge()
    val elsewhere = HttpRequest(request.method, URI.create(transcript.baseUrl + "/realms/demo/other"), request.headers, request.body)
    assertThrows<MockTransport.Mismatch> { matchFirst(elsewhere, transcript) }
  }

  @Test
  fun anExhaustedTranscriptRejectsTheNextRequest() = runTest {
    val (_, request) = firstChallenge()
    assertThrows<MockTransport.Mismatch> { MockTransport(emptyList()).send(request) }
  }

  @Test
  fun formEncodingUsesTheUnreservedSet() {
    assertEquals("a%20b%2Bc~d.e_f-g%2A%3D%26", FormEncoding.escape("a b+c~d.e_f-g*=&"))
    assertEquals(listOf("k" to "a b+c", "e" to ""), FormEncoding.decode(FormEncoding.encode(listOf("k" to "a b+c", "e" to ""))))
  }
}
