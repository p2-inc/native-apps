package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPassword
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import java.net.URI
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Password-manager support: the SDK entry points around a [SavedPasswordPlatform]. */
class SavedPasswordTest {
  private val issuer = URI("https://idp.example.com/realms/demo")

  private class RecordingPlatform(private val picked: SavedPassword) : SavedPasswordPlatform {
    val saved = mutableListOf<SavedPassword>()

    override suspend fun pick(): SavedPassword = picked

    override suspend fun save(password: SavedPassword) {
      saved += password
    }
  }

  private fun sdk(platform: SavedPasswordPlatform?) =
    KeycloakNative.configure(issuer, "c", KeycloakNative.Options(transport = ScriptedTransport({ HttpResponse(500) }), savedPasswordPlatform = platform))

  @Test
  fun pickAndSaveGoThroughTheConfiguredPlatform() = runTest {
    val platform = RecordingPlatform(SavedPassword("alice", "s3cret"))
    val sdk = sdk(platform)
    assertEquals(SavedPassword("alice", "s3cret"), sdk.pickSavedPassword())
    sdk.savePassword("bob", "hunter2")
    assertEquals(listOf(SavedPassword("bob", "hunter2")), platform.saved)
  }

  @Test
  fun withoutAPlatformBothAreUnavailable() = runTest {
    val sdk = sdk(null)
    assertEquals(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, assertThrows<NativeAuthError> { sdk.pickSavedPassword() }.code)
    assertEquals(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, assertThrows<NativeAuthError> { sdk.savePassword("a", "b") }.code)
  }

  @Test
  fun theDescriptionLeavesThePasswordOut() {
    val description = SavedPassword("alice", "s3cret").toString()
    assertFalse("s3cret" in description, description)
  }
}
