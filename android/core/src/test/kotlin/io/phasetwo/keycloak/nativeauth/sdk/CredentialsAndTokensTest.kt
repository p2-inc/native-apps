package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.credentials.CredentialsManager
import io.phasetwo.keycloak.nativeauth.sdk.credentials.InMemorySecureStore
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.logging.NoopLogger
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.expectError
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Twin of `CredentialsAndTokensTests.swift`. */
class CredentialsAndTokensTest {
  @Test
  fun tokenResponseBecomesCredentials() {
    val now = Instant.ofEpochSecond(1_000)
    val response = ScriptedTransport.json(
      200, """{"access_token":"a","refresh_token":"r","id_token":"i","token_type":"Bearer","expires_in":300,"refresh_expires_in":1800,"scope":"openid"}""",
    )
    val credentials = Tokens.parseTokenResponse(response, authSession = "s", now = now)
    assertTrue(credentials.accessToken == "a" && credentials.refreshToken == "r" && credentials.idToken == "i")
    assertEquals(now.plusSeconds(300), credentials.expiresAt)
    assertEquals(now.plusSeconds(1800), credentials.refreshExpiresAt)
    assertTrue(credentials.authSession == "s" && credentials.authorizationScheme == "Bearer")
    assertFalse(credentials.isExpired(now.plusSeconds(299)))
    assertTrue(credentials.isExpired(now.plusSeconds(299), leeway = 5.seconds))
  }

  @Test
  fun offlineRefreshTokensNeverExpire() {
    val response = ScriptedTransport.json(200, """{"access_token":"a","expires_in":60,"refresh_expires_in":0}""")
    assertEquals(Instant.MAX, Tokens.parseTokenResponse(response, null).refreshExpiresAt)
  }

  @Test
  fun errorsPropagateServerCodes() {
    val error = assertThrows(NativeAuthError::class.java) {
      Tokens.parseTokenResponse(ScriptedTransport.json(400, """{"error":"invalid_grant","error_description":"Code not valid"}"""), null)
    }
    assertTrue(error.code == "invalid_grant" && error.errorDescription == "Code not valid")
    val stepUp = assertThrows(NativeAuthError::class.java) {
      Tokens.parseTokenResponse(ScriptedTransport.json(400, """{"error":"insufficient_authorization","auth_session":"s2"}"""), null)
    }
    assertTrue(stepUp.code == "insufficient_authorization" && stepUp.authSession == "s2")
  }

  @Test
  fun credentialsNeverPrintTokens() {
    assertFalse(credentials(60).toString().contains("\"a\"") || credentials(60).toString().contains("=a,"))
  }

  private fun manager(store: InMemorySecureStore, transport: Transport): CredentialsManager {
    val issuer = URI("https://idp.example.com/realms/demo")
    val metadata = MetadataClient(issuer, ScriptedTransport({ ScriptedTransport.json(200, ScriptedTransport.METADATA_JSON) }), 60.seconds)
    return CredentialsManager(store, "k", Tokens("c", issuer, metadata, transport, null), NoopLogger)
  }

  private fun credentials(expiresIn: Long) =
    Credentials("a", refreshToken = "r", idToken = null, scope = null, expiresAt = Instant.now().plusSeconds(expiresIn), refreshExpiresAt = null, authSession = "post")

  @Test
  fun storeRoundTripAndClear() = runTest {
    val manager = manager(InMemorySecureStore(), ScriptedTransport({ HttpResponse(500) }))
    assertNull(manager.stored())
    assertEquals(NativeAuthError.Code.CREDENTIALS_NOT_FOUND, expectError { manager.credentials() }.code)

    val credentials = credentials(600)
    manager.store(credentials)
    assertEquals(credentials, manager.stored())
    assertTrue(manager.hasValid(minTtl = 500.seconds) && !manager.hasValid(minTtl = 600.seconds))
    assertEquals(credentials, manager.credentials(), "valid credentials are returned without a network call")
    manager.clear()
    assertNull(manager.stored())
    assertNull(manager.authSession())
  }

  @Test
  fun offlineExpiryRoundTrips() = runTest {
    val manager = manager(InMemorySecureStore(), ScriptedTransport({ HttpResponse(500) }))
    val offline = credentials(600).copy(refreshExpiresAt = Instant.MAX)
    manager.store(offline)
    assertEquals(offline, manager.stored())
  }

  @Test
  fun corruptStorageIsCleared() = runTest {
    val store = InMemorySecureStore()
    store.set("k", "garbage".toByteArray())
    assertNull(manager(store, ScriptedTransport({ HttpResponse(500) })).stored())
    assertNull(store.data("k"))
  }

  @Test
  fun concurrentCallersShareOneRefresh() = runTest {
    val transport = ScriptedTransport({ request ->
      assertTrue(request.formFields.orEmpty().contains("grant_type" to "refresh_token"))
      ScriptedTransport.json(200, """{"access_token":"new","refresh_token":"r2","expires_in":300}""")
    })
    val manager = manager(InMemorySecureStore(), transport)
    manager.store(credentials(-10))
    val all = List(3) { async { manager.credentials() } }.awaitAll()
    assertTrue(all.all { it.accessToken == "new" && it.authSession == "post" })
    assertEquals(1, transport.sent.size)
  }

  @Test
  fun reauthenticationRequiredMapping() = runTest {
    val store = InMemorySecureStore()
    val stepUp = manager(store, ScriptedTransport({ ScriptedTransport.json(400, """{"error":"insufficient_authorization","auth_session":"s2"}""") }))
    stepUp.store(credentials(-10))
    val error = expectError { stepUp.credentials() }
    assertTrue(error.code == NativeAuthError.Code.REAUTHENTICATION_REQUIRED && error.authSession == "s2")
    assertNotNull(stepUp.stored(), "kept: the server offered a step-up session")

    val gone = manager(store, ScriptedTransport({ ScriptedTransport.json(400, """{"error":"invalid_grant"}""") }))
    val error2 = expectError { gone.credentials() }
    assertTrue(error2.code == NativeAuthError.Code.REAUTHENTICATION_REQUIRED && error2.authSession == null)
    assertNull(gone.stored(), "cleared: the session behind the refresh token is gone")
  }

  @Test
  fun logoutClearsEvenWhenTheServerFails() = runTest {
    val transport = ScriptedTransport({ throw NativeAuthError("network_error", isNetworkError = true) })
    val manager = manager(InMemorySecureStore(), transport)
    manager.store(credentials(100))
    manager.logout()
    assertTrue(transport.sent.size == 1 && transport.sent.first().url.path == "/realms/demo/protocol/openid-connect/logout")
    assertNull(manager.stored())
  }
}
