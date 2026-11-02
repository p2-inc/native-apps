package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.credentials.InMemorySecureStore
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPProofBuilder
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.dpop.SoftwareDPoPKey
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcPublicJwk
import io.phasetwo.keycloak.nativeauth.sdk.jose.EcdsaSignature
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.jose.Pkce
import io.phasetwo.keycloak.nativeauth.sdk.json.boolValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.intValue
import io.phasetwo.keycloak.nativeauth.sdk.json.isNull
import io.phasetwo.keycloak.nativeauth.sdk.json.longValue
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.logging.NoopLogger
import io.phasetwo.keycloak.nativeauth.sdk.support.ScriptedTransport
import io.phasetwo.keycloak.nativeauth.sdk.support.req
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import io.phasetwo.keycloak.nativeauth.sdk.transport.FormEncoding
import java.math.BigInteger
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Twin of `PKCEAndJOSETests.swift` and `DPoPTests.swift`. */
class JoseAndDPoPTest {
  @Test
  fun pkceRfc7636AppendixBVector() {
    val pkce = Pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkce.challenge)
    assertEquals("S256", Pkce.METHOD)
  }

  @Test
  fun generatedVerifiersAre43CharsAndUnique() {
    val a = Pkce.generate()
    val b = Pkce.generate()
    assertEquals(43, a.verifier.length)
    assertNotEquals(a.verifier, b.verifier)
    assertTrue(a.verifier.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" })
  }

  @Test
  fun base64UrlRfc4648Vectors() {
    for ((plain, encoded) in listOf("" to "", "f" to "Zg", "fo" to "Zm8", "foo" to "Zm9v", "foob" to "Zm9vYg", "fooba" to "Zm9vYmE", "foobar" to "Zm9vYmFy")) {
      assertEquals(encoded, Base64Url.encode(plain))
      assertArrayEquals(plain.toByteArray(), Base64Url.decode(encoded))
    }
  }

  @Test
  fun base64UrlUsesTheUrlSafeAlphabetWithoutPadding() {
    val bytes = byteArrayOf(0xfb.toByte(), 0xff.toByte(), 0xbf.toByte(), 0x3e, 0x3f)
    val encoded = Base64Url.encode(bytes)
    assertFalse(encoded.contains('+') || encoded.contains('/') || encoded.contains('='))
    assertArrayEquals(bytes, Base64Url.decode(encoded))
    assertArrayEquals(bytes, Base64Url.decode(java.util.Base64.getEncoder().encodeToString(bytes)), "padded standard input is accepted")
    assertNull(Base64Url.decode("a"))
    assertNull(Base64Url.decode("not*valid"))
  }

  /** RFC 9449 §4.1 example key; its thumbprint is the `jkt` used throughout that RFC (§6.1). */
  @Test
  fun rfc7638ThumbprintOfRfc9449ExampleKey() {
    val jwk = EcPublicJwk("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
    assertEquals("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", jwk.thumbprint)
  }

  @Test
  fun jwkCoordinatesAre32BytesEach() {
    repeat(20) {
      val jwk = SoftwareDPoPKey().publicJwk
      assertTrue(jwk.kty == "EC" && jwk.crv == "P-256")
      assertEquals(32, Base64Url.decode(jwk.x)?.size)
      assertEquals(32, Base64Url.decode(jwk.y)?.size)
    }
  }

  @Test
  fun unverifiedJwtPayloadDecoding() {
    val payload = Base64Url.encode("{\"sub\":\"alice\",\"exp\":1760000000}")
    val jwt = "eyJhbGciOiJub25lIn0.$payload.sig"
    assertEquals("alice", Jwt.decodePayload(jwt)["sub"].stringValue)
    assertEquals(1_760_000_000, Jwt.decodePayload(jwt)["exp"].intValue)
    assertEquals("none", Jwt.decodeHeader(jwt)["alg"].stringValue)
    assertNull(Jwt.decodePayload("garbage"))
  }

  @Test
  fun formDecodeRoundTripsAndAcceptsPlus() {
    val fields = FormEncoding.decode(FormEncoding.encode(listOf("a" to "x y", "b" to "1&2")))
    assertEquals(listOf("a", "b"), fields.map { it.first })
    assertEquals(listOf("x y", "1&2"), fields.map { it.second })
    assertEquals("x y", FormEncoding.decode("a=x+y".toByteArray()).first().second)
  }

  @Test
  fun jsonValuesNavigateStrictly() {
    val json = parseJsonOrNull("""{"a":[1,2,{"b":true}],"s":"x","n":null,"f":1.5,"t":"true"}""").req()
    assertEquals(true, json["a"][2]["b"].boolValue)
    assertEquals(1, json["a"][0].intValue)
    assertNull(json["a"][9])
    assertNull(json["f"].intValue)
    assertTrue(json["n"].isNull)
    assertEquals("x", json["s"].stringValue)
    assertNull(json["t"].boolValue, "a string is not a Boolean")
    assertNull(json["s"].longValue)
    assertNull(json["missing"])
    assertEquals("""{"a":[1,2,{"b":true}],"f":1.5,"n":null,"s":"x","t":"true"}""", json.serialized())
  }

  @Test
  fun ecdsaSignatureConversionRoundTrips() {
    val raw = ByteArray(64) { (it + 1).toByte() }.also { it[0] = 0x80.toByte(); it[32] = 0 }  // high bit set; leading zero
    assertArrayEquals(raw, EcdsaSignature.derToRaw(EcdsaSignature.rawToDer(raw)))
  }

  @Test
  fun proofHasRfc9449ShapeAndVerifiableSignature() {
    val key = SoftwareDPoPKey()
    val proof = DPoPProofBuilder(key).proof(
      "post",
      URI("https://idp.example.com:8443/realms/demo/protocol/openid-connect/token?x=1#frag"),
      issuedAt = Instant.ofEpochSecond(1_760_000_000),
      jti = "abc",
    )
    val parts = proof.split('.')
    assertEquals(3, parts.size)
    val header = Base64Url.decode(parts[0])?.let(::parseJsonOrNull).req()
    assertEquals("dpop+jwt", header["typ"].stringValue)
    assertEquals("ES256", header["alg"].stringValue)
    assertEquals("EC", header["jwk"]["kty"].stringValue)
    assertEquals(key.publicJwk.x, header["jwk"]["x"].stringValue)
    assertNull(header["jwk"]["d"], "private material never leaves the key")

    val payload = Base64Url.decode(parts[1])?.let(::parseJsonOrNull).req()
    assertEquals("POST", payload["htm"].stringValue)
    assertEquals("https://idp.example.com:8443/realms/demo/protocol/openid-connect/token", payload["htu"].stringValue)
    assertEquals(1_760_000_000, payload["iat"].intValue)
    assertEquals("abc", payload["jti"].stringValue)
    assertNull(payload["ath"])
    assertNull(payload["nonce"])

    // Verify with JCA from the JWK alone.
    val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    val point = ECPoint(BigInteger(1, Base64Url.decode(header["jwk"]["x"].stringValue!!)), BigInteger(1, Base64Url.decode(header["jwk"]["y"].stringValue!!)))
    val publicKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
    val verifier = Signature.getInstance("SHA256withECDSA").apply {
      initVerify(publicKey)
      update("${parts[0]}.${parts[1]}".toByteArray())
    }
    assertTrue(verifier.verify(EcdsaSignature.rawToDer(Base64Url.decode(parts[2]).req())))
  }

  /** RFC 9449 §7.1: `ath` for the example access token. */
  @Test
  fun accessTokenHashAndNonce() {
    val proof = DPoPProofBuilder(SoftwareDPoPKey()).proof(
      "GET", URI("https://resource.example.org/protectedresource"), accessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", nonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v",
    )
    val payload = Jwt.decodePayload(proof).req()
    assertEquals("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", payload["ath"].stringValue)
    assertEquals("eyJ7S_zG.eyJH0-Z.HX4w-7v", payload["nonce"].stringValue)
    assertEquals("https://resource.example.org/protectedresource", payload["htu"].stringValue)
  }

  @Test
  fun softwareKeyPersistsAndRestores() {
    val key = SoftwareDPoPKey()
    val restored = SoftwareDPoPKey.restore(key.encodedPrivateKey, key.encodedPublicKey)
    assertEquals(key.publicJwk, restored.publicJwk)
  }

  @Test
  fun signerCreatesOnceAndReloadsFromStore() = runTest {
    val store = InMemorySecureStore()
    val jwk1 = DPoPSigner(DPoPMode.SOFTWARE, store, "k", NoopLogger).publicJwk()
    val jwk2 = DPoPSigner(DPoPMode.SOFTWARE, store, "k", NoopLogger).publicJwk()
    assertEquals(jwk1, jwk2)
    assertEquals(setOf("k"), store.keys)
    assertNull(DPoPSigner(DPoPMode.DISABLED, store, "d", NoopLogger).proof("POST", URI("https://x/y"), null))
  }

  @Test
  fun automaticModeFallsBackToSoftwareWithoutHardware() = runTest {
    val store = InMemorySecureStore()
    val proof = DPoPSigner(DPoPMode.AUTOMATIC, store, "k", NoopLogger).proof("POST", URI("https://x/y"), null).req()
    assertEquals(3, proof.split('.').size)
    assertEquals("software", parseJsonOrNull(store.data("k").req())["kind"].stringValue)
  }

  @Test
  fun nonceChallengeDetection() {
    assertEquals("n1", DPoPSigner.nonceChallenge(ScriptedTransport.json(400, """{"error":"use_dpop_nonce"}""", mapOf("DPoP-Nonce" to "n1"))))
    assertNull(DPoPSigner.nonceChallenge(ScriptedTransport.json(400, """{"error":"invalid_request"}""")))
  }

  @Test
  fun tokenRequestRetriesOnceWithServerNonce() = runTest {
    val transport = ScriptedTransport(
      { ScriptedTransport.json(400, """{"error":"use_dpop_nonce"}""", mapOf("DPoP-Nonce" to "server-nonce")) },
      { request ->
        assertEquals("server-nonce", Jwt.decodePayload(request.header("DPoP")!!)["nonce"].stringValue)
        ScriptedTransport.json(200, """{"access_token":"t","token_type":"DPoP","expires_in":60}""")
      },
    )
    val issuer = URI("https://idp.example.com/realms/demo")
    val metadata = MetadataClient(issuer, ScriptedTransport({ ScriptedTransport.json(200, ScriptedTransport.METADATA_JSON) }), 60.seconds)
    val signer = DPoPSigner(DPoPMode.SOFTWARE, InMemorySecureStore(), "k", NoopLogger)
    val credentials = Tokens("c", issuer, metadata, transport, signer).exchange("code", "v")
    assertTrue(credentials.isDPoPBound)
    assertEquals("DPoP", credentials.authorizationScheme)
    assertEquals(2, transport.sent.size)
  }
}
