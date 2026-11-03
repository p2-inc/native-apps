package io.phasetwo.keycloak.nativeauth.sdk.android

import android.content.pm.PackageManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.phasetwo.keycloak.nativeauth.sdk.dpop.HardwareDPoPKey
import io.phasetwo.keycloak.nativeauth.sdk.dpop.HardwareDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcPublicJwk
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcdsaSignature
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * DPoP keys in the Android Keystore (spec/17 §3): EC P-256, sign-only, the private key never leaves
 * the secure hardware. StrongBox is used when the device has one, else the TEE. The analogue of the
 * iOS Secure Enclave key; pass it as `KeycloakNative.Options.hardwareKeys`.
 */
public class KeystoreDPoPKeys(context: Context) : HardwareDPoPKeys {
  private val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

  override val isAvailable: Boolean
    get() = runCatching { keyStore() }.isSuccess

  override fun create(): HardwareDPoPKey {
    val alias = "$ALIAS_PREFIX${UUID.randomUUID()}"
    if (hasStrongBox) {
      try {
        generate(alias, strongBox = true)
        return restore(alias)
      } catch (_: StrongBoxUnavailableException) {
        // Advertised but not usable for this key (for instance busy): fall back to the TEE.
      }
    }
    generate(alias, strongBox = false)
    return restore(alias)
  }

  override fun restore(reference: ByteArray): HardwareDPoPKey = restore(String(reference, StandardCharsets.UTF_8))

  /** Deletes a key [create] made; the signer forgets its reference when the credentials are cleared. */
  public fun delete(reference: ByteArray) {
    keyStore().deleteEntry(String(reference, StandardCharsets.UTF_8))
  }

  private fun restore(alias: String): HardwareDPoPKey {
    val store = keyStore()
    val entry = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
      ?: throw IllegalStateException("no Keystore key '$alias'")
    return KeystoreDPoPKey(alias, entry.privateKey, entry.certificate.publicKey as ECPublicKey)
  }

  private fun generate(alias: String, strongBox: Boolean) {
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setIsStrongBoxBacked(strongBox)
      .build()
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply { initialize(spec) }.generateKeyPair()
  }

  private class KeystoreDPoPKey(alias: String, private val privateKey: PrivateKey, publicKey: ECPublicKey) : HardwareDPoPKey {
    override val reference: ByteArray = alias.toByteArray(StandardCharsets.UTF_8)
    override val algorithm: String get() = "ES256"
    override val publicJwk: EcPublicJwk = EcPublicJwk.of(publicKey)

    // Keystore returns DER; the JWS wants raw r || s.
    override fun sign(message: ByteArray): ByteArray =
      EcdsaSignature.derToRaw(
        Signature.getInstance("SHA256withECDSA").run {
          initSign(privateKey)
          update(message)
          sign()
        },
      )
  }

  private companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val ALIAS_PREFIX = "io.phasetwo.keycloak.nativeauth.dpop."

    fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
  }
}
