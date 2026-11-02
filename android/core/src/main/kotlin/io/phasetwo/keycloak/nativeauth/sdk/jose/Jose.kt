package io.phasetwo.keycloak.nativeauth.sdk.jose

import io.phasetwo.keycloak.nativeauth.sdk.json.jsonObjectOf
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.util.Base64
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * RFC 4648 §5 base64url without padding: the encoding of every binary value on the wire (spec/03
 * conventions).
 */
public object Base64Url {
  private val encoder = Base64.getUrlEncoder().withoutPadding()

  public fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

  public fun encode(text: String): String = encode(text.toByteArray(StandardCharsets.UTF_8))

  /** Accepts unpadded and padded input, and the standard alphabet; `null` for anything else. */
  public fun decode(text: String): ByteArray? {
    val normalized = text.replace('+', '-').replace('/', '_').trimEnd('=')
    if (normalized.length % 4 == 1) return null
    return try {
      Base64.getUrlDecoder().decode(normalized)
    } catch (_: IllegalArgumentException) {
      null
    }
  }
}

internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

internal fun sha256(text: String): ByteArray = sha256(text.toByteArray(StandardCharsets.UTF_8))

/** PKCE S256 pair (RFC 7636). One per login flow. */
public data class Pkce(public val verifier: String) {
  /** The S256 challenge for [verifier] (RFC 7636 §4.2). */
  public val challenge: String = Base64Url.encode(sha256(verifier))

  public companion object {
    public const val METHOD: String = "S256"
    private val random = SecureRandom()

    /** 32 random bytes, base64url: a 43-character verifier. */
    public fun generate(): Pkce = Pkce(Base64Url.encode(ByteArray(32).also(random::nextBytes)))
  }
}

/** A P-256 public key as a JWK (RFC 7518 §6.2) with its RFC 7638 thumbprint. */
public data class EcPublicJwk(public val x: String, public val y: String) {
  public val kty: String get() = "EC"
  public val crv: String get() = "P-256"

  /**
   * RFC 7638: SHA-256 over the canonical JSON `{"crv","kty","x","y"}` (lexicographic keys, no
   * whitespace), base64url.
   */
  public val thumbprint: String
    get() = Base64Url.encode(sha256("{\"crv\":\"$crv\",\"kty\":\"$kty\",\"x\":\"$x\",\"y\":\"$y\"}"))

  public val json: JsonObject
    get() = jsonObjectOf("kty" to JsonPrimitive(kty), "crv" to JsonPrimitive(crv), "x" to JsonPrimitive(x), "y" to JsonPrimitive(y))

  public companion object {
    /** The affine coordinates of [key], each left-padded to 32 bytes. */
    public fun of(key: ECPublicKey): EcPublicJwk =
      EcPublicJwk(Base64Url.encode(unsigned32(key.w.affineX)), Base64Url.encode(unsigned32(key.w.affineY)))
  }
}

/** A big-endian, unsigned, 32-byte encoding of [value] (a P-256 coordinate or scalar). */
internal fun unsigned32(value: BigInteger): ByteArray {
  val bytes = value.toByteArray()
  return when {
    bytes.size == 32 -> bytes
    bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
    bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
    else -> throw IllegalArgumentException("not a P-256 value")
  }
}

/**
 * ECDSA signature conversions: JCA's `SHA256withECDSA` (and Android Keystore) produce ASN.1 DER,
 * a JWS needs the raw `r || s` (RFC 7518 §3.4), 64 bytes for P-256.
 */
public object EcdsaSignature {
  public fun derToRaw(der: ByteArray): ByteArray {
    var i = 0
    fun readLength(): Int {
      val first = der[i++].toInt() and 0xff
      if (first < 0x80) return first
      var length = 0
      repeat(first and 0x7f) { length = (length shl 8) or (der[i++].toInt() and 0xff) }
      return length
    }
    require(der[i++] == 0x30.toByte()) { "not a DER SEQUENCE" }
    readLength()
    fun readInteger(): BigInteger {
      require(der[i++] == 0x02.toByte()) { "not a DER INTEGER" }
      val length = readLength()
      return BigInteger(1, der.copyOfRange(i, i + length)).also { i += length }
    }
    val r = readInteger()
    val s = readInteger()
    return unsigned32(r) + unsigned32(s)
  }

  public fun rawToDer(raw: ByteArray): ByteArray {
    require(raw.size == 64) { "a P-256 signature is 64 bytes" }
    fun integer(bytes: ByteArray): ByteArray {
      val value = BigInteger(1, bytes).toByteArray()  // minimal two's complement, sign byte when needed
      return byteArrayOf(0x02, value.size.toByte()) + value
    }
    val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
    return byteArrayOf(0x30, body.size.toByte()) + body
  }
}

/**
 * Unverified JWT payload access for display and expiry bookkeeping. The SDK never relies on these
 * claims for a security decision; tokens are validated by the server that issued them.
 */
public object Jwt {
  public fun decodePayload(jwt: String): JsonElement? = part(jwt, 1)

  public fun decodeHeader(jwt: String): JsonElement? = part(jwt, 0)

  private fun part(jwt: String, index: Int): JsonElement? {
    val parts = jwt.split('.')
    if (parts.size != 3) return null
    return Base64Url.decode(parts[index])?.let(::parseJsonOrNull)
  }
}
