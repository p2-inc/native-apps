package io.phasetwo.keycloak.nativeauth.sdk.dpop

import io.phasetwo.keycloak.nativeauth.sdk.jose.EcPublicJwk
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcdsaSignature
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/** A signing key for DPoP proofs (RFC 9449). ES256 only for now (spec/03 §8 prefers it). */
public interface DPoPKey {
  /** JWS `alg`. */
  public val algorithm: String
  public val publicJwk: EcPublicJwk

  /** ECDSA over SHA-256, returned as the JWS raw `r || s` (64 bytes). */
  public fun sign(message: ByteArray): ByteArray
}

/**
 * JCA P-256 key in process memory. Used on the JVM, in tests and when no hardware-backed key store is
 * available; persisted (PKCS#8 + X.509 encodings) by the signer through the `SecureStore`.
 */
public class SoftwareDPoPKey private constructor(private val keyPair: KeyPair) : DPoPKey {
  public constructor() : this(
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair(),
  )

  /** PKCS#8 encoding of the private key. */
  public val encodedPrivateKey: ByteArray get() = keyPair.private.encoded

  /** X.509 SubjectPublicKeyInfo encoding of the public key. */
  public val encodedPublicKey: ByteArray get() = keyPair.public.encoded

  override val algorithm: String get() = "ES256"
  override val publicJwk: EcPublicJwk = EcPublicJwk.of(keyPair.public as ECPublicKey)

  override fun sign(message: ByteArray): ByteArray {
    val der = Signature.getInstance("SHA256withECDSA").run {
      initSign(keyPair.private)
      update(message)
      sign()
    }
    return EcdsaSignature.derToRaw(der)
  }

  public companion object {
    public fun restore(encodedPrivateKey: ByteArray, encodedPublicKey: ByteArray): SoftwareDPoPKey {
      val factory = KeyFactory.getInstance("EC")
      return SoftwareDPoPKey(
        KeyPair(factory.generatePublic(X509EncodedKeySpec(encodedPublicKey)), factory.generatePrivate(PKCS8EncodedKeySpec(encodedPrivateKey))),
      )
    }
  }
}

/** A key whose private part stays in platform hardware; [reference] restores it on the same device. */
public interface HardwareDPoPKey : DPoPKey {
  /** An opaque, device-bound handle (an Android Keystore alias, for instance). */
  public val reference: ByteArray
}

/**
 * The platform key store behind [DPoPMode.HARDWARE] and [DPoPMode.AUTOMATIC]: the `android` module
 * provides one over Android Keystore (StrongBox when available, spec/17 §2).
 */
public interface HardwareDPoPKeys {
  public val isAvailable: Boolean

  public fun create(): HardwareDPoPKey

  public fun restore(reference: ByteArray): HardwareDPoPKey
}

/** Which key the SDK uses for DPoP proofs (spec/05 §3.1). */
public enum class DPoPMode {
  /** No `DPoP` headers at all. */
  DISABLED,
  SOFTWARE,

  /** [HardwareDPoPKeys] only; fails with `dpop_key_error` when none is configured or available. */
  HARDWARE,

  /** Hardware when available (device), software otherwise (JVM, CI). */
  AUTOMATIC,
}
