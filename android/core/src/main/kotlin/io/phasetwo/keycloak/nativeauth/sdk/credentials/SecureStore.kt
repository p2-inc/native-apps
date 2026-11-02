package io.phasetwo.keycloak.nativeauth.sdk.credentials

import java.util.concurrent.ConcurrentHashMap

/**
 * Byte storage for credentials and the DPoP key reference. The `android` module provides a Keystore
 * backed store (spec/17 §2). The functions suspend so a store can wait for user authentication
 * (`BiometricPrompt`) before it unwraps an item.
 */
public interface SecureStore {
  public suspend fun data(key: String): ByteArray?

  public suspend fun set(key: String, data: ByteArray)

  public suspend fun remove(key: String)
}

/** Process-local store for tests, previews and the JVM. */
public class InMemorySecureStore : SecureStore {
  private val items = ConcurrentHashMap<String, ByteArray>()

  override suspend fun data(key: String): ByteArray? = items[key]?.copyOf()

  override suspend fun set(key: String, data: ByteArray) {
    items[key] = data.copyOf()
  }

  override suspend fun remove(key: String) {
    items.remove(key)
  }

  public val keys: Set<String> get() = items.keys.toSet()
}
