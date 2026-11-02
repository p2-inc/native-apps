package io.phasetwo.keycloak.nativeauth.sdk.credentials

import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Secure-store-backed credential storage with serialized refresh (spec/05 §2.2, §6). */
public class CredentialsManager internal constructor(
  private val store: SecureStore,
  private val key: String,
  private val tokens: Tokens,
  private val logger: NativeAuthLogger,
  private val leeway: Duration = 30.seconds,
) {
  @Serializable
  private data class Stored(
    val accessToken: String,
    val tokenType: String,
    val refreshToken: String? = null,
    val idToken: String? = null,
    val scope: String? = null,
    val expiresAt: Long,
    val refreshExpiresAt: Long? = null,
    val issuedAt: Long,
    val authSession: String? = null,
  )

  private val mutex = Mutex()
  private var refreshing: CompletableDeferred<Credentials>? = null

  public suspend fun store(credentials: Credentials) {
    val stored = with(credentials) {
      Stored(accessToken, tokenType, refreshToken, idToken, scope, expiresAt.epochSecond, refreshExpiresAt?.epochSecond, issuedAt.epochSecond, authSession)
    }
    store.set(key, json.encodeToString(Stored.serializer(), stored).toByteArray(StandardCharsets.UTF_8))
  }

  /** The stored credentials as they are, possibly expired; `null` when none. */
  public suspend fun stored(): Credentials? {
    val data = store.data(key) ?: return null
    return try {
      val s = json.decodeFromString(Stored.serializer(), String(data, StandardCharsets.UTF_8))
      Credentials(
        s.accessToken, s.tokenType, s.refreshToken, s.idToken, s.scope,
        Instant.ofEpochSecond(s.expiresAt), s.refreshExpiresAt?.let(::instantOrMax), Instant.ofEpochSecond(s.issuedAt), s.authSession,
      )
    } catch (e: IllegalArgumentException) {
      logger.log(LogLevel.WARNING) { "Stored credentials are unreadable; clearing them" }
      runCatching { store.remove(key) }
      null
    }
  }

  public suspend fun hasValid(minTtl: Duration = Duration.ZERO): Boolean {
    val credentials = stored() ?: return false
    return !credentials.isExpired(leeway = leeway + minTtl)
  }

  /** The stored post-login `auth_session`, kept for step-up (spec/03 §5). */
  public suspend fun authSession(): String? = stored()?.authSession

  /**
   * Valid credentials, refreshing (once, even under concurrent callers) when the access token is
   * within `leeway + minTtl` of expiry. Throws `credentials_not_found` when nothing is stored and
   * `reauthentication_required` (with `authSession` when the server returned one) when the refresh
   * is refused.
   */
  public suspend fun credentials(minTtl: Duration = Duration.ZERO): Credentials {
    val current = stored() ?: throw NativeAuthError(NativeAuthError.Code.CREDENTIALS_NOT_FOUND, errorDescription = "No stored credentials")
    if (!current.isExpired(leeway = leeway + minTtl)) return current
    val (pending, owner) = mutex.withLock {
      refreshing?.let { it to false } ?: (CompletableDeferred<Credentials>().also { refreshing = it } to true)
    }
    if (!owner) return pending.await()
    try {
      val refreshed = refresh(current)
      pending.complete(refreshed)
      return refreshed
    } catch (e: Throwable) {
      pending.completeExceptionally(e)
      throw e
    } finally {
      mutex.withLock { refreshing = null }
    }
  }

  private suspend fun refresh(current: Credentials): Credentials {
    try {
      val refreshed = tokens.refresh(current)
      store(refreshed)
      return refreshed
    } catch (error: NativeAuthError) {
      when (error.code) {
        NativeAuthError.Code.INVALID_GRANT -> {
          // The session behind the refresh token is gone (logout, expiry, revocation).
          runCatching { clear() }
          throw NativeAuthError(
            NativeAuthError.Code.REAUTHENTICATION_REQUIRED, statusCode = error.statusCode, errorDescription = error.errorDescription,
            details = error.details, cause = error,
          )
        }
        NativeAuthError.Code.INSUFFICIENT_AUTHORIZATION ->
          // spec/03 §5: the returned auth_session feeds Authentication.continueAfterTokenChallenge.
          throw NativeAuthError(
            NativeAuthError.Code.REAUTHENTICATION_REQUIRED, statusCode = error.statusCode, errorDescription = error.errorDescription,
            authSession = error.authSession, details = error.details, cause = error,
          )
        else -> throw error
      }
    }
  }

  public suspend fun clear() {
    store.remove(key)
  }

  /**
   * Best-effort server-side logout (RP-initiated logout with the refresh token) followed by [clear].
   * Server and network failures are logged, not thrown: the local state is cleared regardless.
   */
  public suspend fun logout() {
    val refreshToken = runCatching { stored() }.getOrNull()?.refreshToken
    if (refreshToken != null) {
      try {
        tokens.logout(refreshToken)
      } catch (e: CancellationException) {
        throw e
      } catch (e: Exception) {
        logger.log(LogLevel.WARNING) { "Server logout failed: $e" }
      }
    }
    runCatching { clear() }
  }

  private companion object {
    val json = Json { ignoreUnknownKeys = true }

    fun instantOrMax(epochSecond: Long): Instant = if (epochSecond >= Instant.MAX.epochSecond) Instant.MAX else Instant.ofEpochSecond(epochSecond)
  }
}
