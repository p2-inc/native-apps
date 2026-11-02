package io.phasetwo.keycloak.nativeauth.sdk.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcPublicJwk
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.UUID
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** The Keystore-backed DPoP key and secure store on a device or emulator (spec/17 §5). */
@RunWith(AndroidJUnit4::class)
class KeystoreTest {
  private val context = InstrumentationRegistry.getInstrumentation().targetContext

  @Test
  fun dpopKeySignsVerifiableRawSignaturesAndRestoresFromItsReference() {
    val keys = KeystoreDPoPKeys(context)
    assertTrue(keys.isAvailable)
    val key = keys.create()
    try {
      val message = "header.payload".toByteArray()
      val raw = key.sign(message)
      assertEquals(64, raw.size)
      val verifier = Signature.getInstance("SHA256withECDSA").apply {
        initVerify(publicKey(key.publicJwk))
        update(message)
      }
      assertTrue(verifier.verify(rawToDer(raw)))

      val restored = keys.restore(key.reference)
      assertEquals(key.publicJwk, restored.publicJwk)
      assertEquals("ES256", restored.algorithm)
    } finally {
      keys.delete(key.reference)
    }
  }

  @Test
  fun storeRoundTripsOverwritesAndRemoves() = runTest {
    val store = KeystoreSecureStore(context, namespace = "test-${UUID.randomUUID()}")
    assertNull(store.data("credentials"))
    store.set("credentials", "one".toByteArray())
    assertArrayEquals("one".toByteArray(), store.data("credentials"))
    store.set("credentials", "two".toByteArray())
    assertArrayEquals("two".toByteArray(), store.data("credentials"))
    store.remove("credentials")
    assertNull(store.data("credentials"))
    store.remove("credentials")
  }

  @Test
  fun namespacesAreSeparate() = runTest {
    val a = KeystoreSecureStore(context, namespace = "test-a-${UUID.randomUUID()}")
    val b = KeystoreSecureStore(context, namespace = "test-b-${UUID.randomUUID()}")
    a.set("k", "a".toByteArray())
    assertNull(b.data("k"))
  }

  @Test
  fun aTamperedOrSwappedItemReadsAsAbsent() = runTest {
    val namespace = "test-${UUID.randomUUID()}"
    val store = KeystoreSecureStore(context, namespace)
    store.set("first", "secret".toByteArray())
    store.set("second", "other".toByteArray())
    val directory = File(context.noBackupFilesDir, "keycloak-native/${fileName(namespace)}")

    // A file copied under another item's name fails the associated-data check.
    File(directory, fileName("first")).copyTo(File(directory, fileName("second")), overwrite = true)
    assertNull(store.data("second"))
    assertArrayEquals("secret".toByteArray(), store.data("first"))

    val file = File(directory, fileName("first"))
    file.writeBytes(file.readBytes().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
    assertNull(store.data("first"))
    assertTrue(!file.exists())
  }

  private fun fileName(key: String) =
    Base64Url.encode(java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray()))

  private fun publicKey(jwk: EcPublicJwk): ECPublicKey {
    val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    val point = ECPoint(BigInteger(1, Base64Url.decode(jwk.x)), BigInteger(1, Base64Url.decode(jwk.y)))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey
  }

  private fun rawToDer(raw: ByteArray): ByteArray {
    fun integer(bytes: ByteArray): ByteArray {
      val value = BigInteger(1, bytes).toByteArray()
      return byteArrayOf(0x02, value.size.toByte()) + value
    }
    val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
    return byteArrayOf(0x30, body.size.toByte()) + body
  }
}
