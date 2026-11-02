package io.phasetwo.keycloak.nativeauth.sdk.dpop

import io.phasetwo.keycloak.nativeauth.sdk.credentials.SecureStore
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcPublicJwk
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import java.net.URI
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * Owns the DPoP key (created on first use, persisted through the [SecureStore]), builds proofs and
 * remembers server nonces per origin. Proofs are sent on challenge and token requests whether or not
 * the server binds; `token_type` says which happened.
 */
internal class DPoPSigner(
  private val mode: DPoPMode,
  private val store: SecureStore,
  private val storeKey: String,
  private val logger: NativeAuthLogger,
  private val hardware: HardwareDPoPKeys? = null,
) {
  @Serializable
  private data class Persisted(val kind: String, val key: String, val publicKey: String? = null)

  private val mutex = Mutex()
  private var key: DPoPKey? = null
  private val nonces = mutableMapOf<String, String>()

  /** `null` when DPoP is disabled. */
  suspend fun proof(method: String, url: URI, accessToken: String?, extraClaims: Map<String, JsonElement> = emptyMap()): String? {
    if (mode == DPoPMode.DISABLED) return null
    val key = currentKey()
    val nonce = mutex.withLock { nonces[DPoPProofBuilder.origin(url)] }
    return DPoPProofBuilder(key).proof(method, url, accessToken = accessToken, nonce = nonce, extraClaims = extraClaims)
  }

  suspend fun publicJwk(): EcPublicJwk? = if (mode == DPoPMode.DISABLED) null else currentKey().publicJwk

  /** The key itself (created on first use), for device-signed JWTs (spec/03 §7, spec/14 D9). */
  suspend fun currentKey(): DPoPKey = mutex.withLock { loadOrCreateKey() }

  /**
   * A fresh key of the configured kind, not yet in use: the caller registers it with the server
   * (signing that request with the current key) and then calls [commitRotation].
   */
  fun prepareRotation(): DPoPKey = makeKey().first

  /**
   * Makes [newKey] (from [prepareRotation]) the DPoP key from now on. Tokens bound to the previous key
   * stop matching proofs: the caller re-authenticates.
   */
  suspend fun commitRotation(newKey: DPoPKey) = mutex.withLock {
    val persisted = persisted(newKey)
    store.set(storeKey, encode(persisted))
    logger.log(LogLevel.INFO) { "Rotated DPoP key (${persisted.kind}), jkt=${newKey.publicJwk.thumbprint}" }
    key = newKey
  }

  suspend fun setNonce(nonce: String, url: URI) = mutex.withLock {
    nonces[DPoPProofBuilder.origin(url)] = nonce
  }

  suspend fun reset() = mutex.withLock {
    key = null
    store.remove(storeKey)
  }

  private suspend fun loadOrCreateKey(): DPoPKey {
    key?.let { return it }
    val persisted = store.data(storeKey)?.let { runCatching { json.decodeFromString(Persisted.serializer(), String(it, StandardCharsets.UTF_8)) }.getOrNull() }
    if (persisted != null) {
      try {
        val restored = restore(persisted)
        key = restored
        return restored
      } catch (e: Exception) {
        logger.log(LogLevel.WARNING) { "Stored DPoP key could not be restored (${persisted.kind}); creating a new one" }
      }
    }
    val (created, record) = makeKey()
    store.set(storeKey, encode(record))
    logger.log(LogLevel.INFO) { "Created DPoP key (${record.kind}), jkt=${created.publicJwk.thumbprint}" }
    key = created
    return created
  }

  private fun restore(persisted: Persisted): DPoPKey {
    val bytes = Base64Url.decode(persisted.key) ?: error("not base64url")
    return when (persisted.kind) {
      HARDWARE -> (hardware ?: error("no hardware key store configured")).restore(bytes)
      else -> SoftwareDPoPKey.restore(bytes, Base64Url.decode(persisted.publicKey ?: error("no public key")) ?: error("not base64url"))
    }
  }

  private fun makeKey(): Pair<DPoPKey, Persisted> {
    val key: DPoPKey = when (mode) {
      DPoPMode.DISABLED -> throw NativeAuthError(NativeAuthError.Code.DPOP_KEY_ERROR, errorDescription = "DPoP is disabled")
      DPoPMode.SOFTWARE -> SoftwareDPoPKey()
      DPoPMode.HARDWARE -> {
        val hardware = hardware?.takeIf { it.isAvailable }
          ?: throw NativeAuthError(NativeAuthError.Code.DPOP_KEY_ERROR, errorDescription = "No hardware-backed key store is available")
        try {
          hardware.create()
        } catch (e: Exception) {
          throw NativeAuthError(NativeAuthError.Code.DPOP_KEY_ERROR, errorDescription = "Hardware key creation failed: ${e.message}", cause = e)
        }
      }
      DPoPMode.AUTOMATIC -> hardware?.takeIf { it.isAvailable }?.let { runCatching { it.create() }.getOrNull() } ?: SoftwareDPoPKey()
    }
    return key to persisted(key)
  }

  private fun persisted(key: DPoPKey): Persisted = when (key) {
    is HardwareDPoPKey -> Persisted(HARDWARE, Base64Url.encode(key.reference))
    is SoftwareDPoPKey -> Persisted(SOFTWARE, Base64Url.encode(key.encodedPrivateKey), Base64Url.encode(key.encodedPublicKey))
    else -> throw NativeAuthError(NativeAuthError.Code.DPOP_KEY_ERROR, errorDescription = "Unsupported key type for rotation")
  }

  private fun encode(persisted: Persisted): ByteArray = json.encodeToString(Persisted.serializer(), persisted).toByteArray(StandardCharsets.UTF_8)

  companion object {
    const val SOFTWARE = "software"
    const val HARDWARE = "hardware"
    private val json = Json { ignoreUnknownKeys = true }

    /** RFC 9449 §8: `400 use_dpop_nonce` + `DPoP-Nonce` header (also `401` on resource servers). */
    fun nonceChallenge(response: HttpResponse): String? = response.dpopNonceChallenge
  }
}
