package io.phasetwo.keycloak.nativeauth.sdk.ui

import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The default screens rendered on a device: a username → password login against a scripted server,
 * checking the autofill content types password managers rely on and the read-only username on the
 * password screen.
 */
@RunWith(AndroidJUnit4::class)
class NativeLoginScreenTest {
  @get:Rule val compose = createComposeRule()

  private class Scripted(vararg handlers: (HttpRequest) -> HttpResponse) : Transport {
    private val handlers = ArrayDeque(handlers.toList())
    val sent = mutableListOf<HttpRequest>()

    override suspend fun send(request: HttpRequest): HttpResponse {
      val handler = synchronized(this) {
        sent += request
        if (handlers.size > 1) handlers.removeFirst() else handlers.first()
      }
      return handler(request)
    }
  }

  private fun json(status: Int, body: String) = HttpResponse(status, mapOf("Content-Type" to "application/json"), body.toByteArray())

  private fun contentType(type: ContentType) = SemanticsMatcher.expectValue(SemanticsProperties.ContentType, type)

  @Test
  fun usernameThenPasswordWithAutofillContentTypes() {
    val claims = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"preferred_username":"alice"}""".toByteArray())
    val jwt = "eyJhbGciOiJub25lIn0.$claims."
    val transport = Scripted(
      { json(200, """{"protocol_version":"1","authorization_challenge_endpoint":"https://idp.example.com/realms/demo/native-auth/challenge","token_endpoint":"https://idp.example.com/realms/demo/protocol/openid-connect/token"}""") },
      { json(403, """{"error":"insufficient_authorization","auth_session":"s1","expires_in":500,"challenges":[{"type":"username","id":"u","required":true,"params":{}}]}""") },
      { json(403, """{"error":"insufficient_authorization","auth_session":"s2","expires_in":500,"challenges":[{"type":"password","id":"p","required":true,"params":{"username_known":true}}],"context":{"username":"alice"}}""") },
      { json(200, """{"authorization_code":"code","auth_session":"post"}""") },
      { json(200, """{"access_token":"$jwt","token_type":"Bearer","expires_in":300,"refresh_token":"r","id_token":"$jwt","scope":"openid"}""") },
    )
    val kc = KeycloakNative.configure(URI("https://idp.example.com/realms/demo"), "c", KeycloakNative.Options(dpop = DPoPMode.DISABLED, transport = transport))
    val flow = kc.authentication().startLogin()
    val results = mutableListOf<NativeLoginResult>()
    compose.setContent { NativeLoginScreen(kc, flow, onResult = { results += it }, offerSavedPasswords = false) }

    compose.waitUntil(5_000) { compose.onAllNodesWithTag("username").fetchSemanticsNodes().isNotEmpty() }
    compose.onNodeWithTag("username").assert(contentType(ContentType.Username)).performTextInput("alice")
    compose.onNodeWithText("Continue").performClick()

    compose.waitUntil(5_000) { compose.onAllNodesWithTag("password").fetchSemanticsNodes().isNotEmpty() }
    compose.onNodeWithTag("autofillUsername").assertIsDisplayed().assert(contentType(ContentType.Username)).assertTextContains("alice")
    compose.onNodeWithTag("password").assert(contentType(ContentType.Password)).performTextInput("s3cret")
    compose.onNodeWithText("Sign in").performClick()

    compose.waitUntil(5_000) { results.isNotEmpty() }
    assertTrue(results.single() is NativeLoginResult.Authorized)
    assertEquals("s3cret", transport.sent[3].formFields?.firstOrNull { it.first == "password" }?.second)
  }
}
