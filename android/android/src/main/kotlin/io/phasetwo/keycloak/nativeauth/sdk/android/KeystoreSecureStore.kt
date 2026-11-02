package io.phasetwo.keycloak.nativeauth.sdk.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.phasetwo.keycloak.nativeauth.sdk.credentials.SecureStore
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import java.io.File
import java.io.FileNotFoundException
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * A [SecureStore] of small files sealed with an AES-256-GCM key that lives in the Android Keystore
 * (spec/17 §3), the analogue of the iOS `KeychainStore`. Files sit in `noBackupFilesDir`, so they
 * never reach a backup or another device, where the key would not exist anyway. Each file is
 * `IV || ciphertext`, with the item key as associated data so a file cannot be swapped for another.
 *
 * An item that can no longer be opened (the Keystore key was invalidated or replaced) is deleted and
 * reads as absent, which sends the user through a fresh login. Other failures are `keychain_error`.
 */
public class KeystoreSecureStore(
  context: Context,
  /** Separates stores of several SDK instances (one per issuer and client, for instance). */
  namespace: String = "default",
) : SecureStore {
  private val directory = File(context.noBackupFilesDir, "keycloak-native/${fileName(namespace)}")
  private val keyAlias = "io.phasetwo.keycloak.nativeauth.store.$namespace"
  private val mutex = Mutex()

  override suspend fun data(key: String): ByteArray? = io {
    val file = AtomicFile(file(key))
    val sealed = try {
      file.readFully()
    } catch (_: FileNotFoundException) {
      return@io null
    }
    try {
      open(key, sealed)
    } catch (_: AEADBadTagException) {
      file.delete()
      null
    } catch (_: KeyPermanentlyInvalidatedException) {
      file.delete()
      null
    }
  }

  override suspend fun set(key: String, data: ByteArray): Unit = io {
    val sealed = seal(key, data)
    directory.mkdirs()
    val file = AtomicFile(file(key))
    val stream = file.startWrite()
    try {
      stream.write(sealed)
      file.finishWrite(stream)
    } catch (e: Exception) {
      file.failWrite(stream)
      throw e
    }
  }

  override suspend fun remove(key: String): Unit = io {
    AtomicFile(file(key)).delete()
  }

  /** Runs [block] serialized and off the main thread; maps failures to `keychain_error`. */
  private suspend fun <T> io(block: () -> T): T = mutex.withLock {
    withContext(Dispatchers.IO) {
      try {
        block()
      } catch (e: NativeAuthError) {
        throw e
      } catch (e: Exception) {
        throw NativeAuthError(NativeAuthError.Code.KEYCHAIN_ERROR, errorDescription = "Secure storage failed: ${e.message}", cause = e)
      }
    }
  }

  private fun file(key: String) = File(directory, fileName(key))

  private fun seal(key: String, data: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION).apply {
      init(Cipher.ENCRYPT_MODE, secretKey())
      updateAAD(key.toByteArray(StandardCharsets.UTF_8))
    }
    return cipher.iv + cipher.doFinal(data)
  }

  private fun open(key: String, sealed: ByteArray): ByteArray {
    if (sealed.size < IV_BYTES) throw AEADBadTagException("truncated item")
    val cipher = Cipher.getInstance(TRANSFORMATION).apply {
      init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES))
      updateAAD(key.toByteArray(StandardCharsets.UTF_8))
    }
    return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
  }

  private fun secretKey(): SecretKey {
    val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    (store.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
    val spec = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .build()
    return try {
      KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply { init(spec) }.generateKey()
    } catch (e: GeneralSecurityException) {
      throw NativeAuthError(NativeAuthError.Code.KEYCHAIN_ERROR, errorDescription = "Could not create the storage key: ${e.message}", cause = e)
    }
  }

  private companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val IV_BYTES = 12
    const val TAG_BITS = 128

    /** Item keys can hold any character; file names get a fixed-length hash instead. */
    fun fileName(key: String): String =
      Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(key.toByteArray(StandardCharsets.UTF_8)))
  }
}
