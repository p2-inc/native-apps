package io.phasetwo.keycloak.nativeauth.sdk.dpop

import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.sha256
import io.phasetwo.keycloak.nativeauth.sdk.json.jsonObjectOf
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Builds RFC 9449 proof JWTs: header `{typ: dpop+jwt, alg, jwk}`, payload `{jti, htm, htu, iat,
 * ath?, nonce?}` (spec/03 §8) plus any extra claims a profile wants (`sub`, `deviceId` for the push
 * device API, spec/03 §7.1).
 */
public class DPoPProofBuilder(public val key: DPoPKey) {
  public fun proof(
    method: String,
    url: URI,
    accessToken: String? = null,
    nonce: String? = null,
    issuedAt: Instant = Instant.now(),
    jti: String = UUID.randomUUID().toString(),
    extraClaims: Map<String, JsonElement> = emptyMap(),
  ): String {
    val header = jsonObjectOf("typ" to JsonPrimitive("dpop+jwt"), "alg" to JsonPrimitive(key.algorithm), "jwk" to key.publicJwk.json)
    val payload = linkedMapOf<String, JsonElement>(
      "jti" to JsonPrimitive(jti),
      "htm" to JsonPrimitive(method.uppercase()),
      "htu" to JsonPrimitive(htu(url)),
      "iat" to JsonPrimitive(issuedAt.epochSecond),
    )
    if (accessToken != null) payload["ath"] = JsonPrimitive(Base64Url.encode(sha256(accessToken)))
    if (nonce != null) payload["nonce"] = JsonPrimitive(nonce)
    for ((claim, value) in extraClaims) payload.putIfAbsent(claim, value)
    return signJws(header, JsonObject(payload), key)
  }

  public companion object {
    /** `htu`: scheme, host, port and path only, no query or fragment (RFC 9449 §4.2). */
    public fun htu(url: URI): String = origin(url) + (url.rawPath ?: "")

    internal fun origin(url: URI): String = "${url.scheme}://${url.host}" + if (url.port >= 0) ":${url.port}" else ""
  }
}

/**
 * Signs an arbitrary JWS with a [DPoPKey] (`typ: JWT`): the device-signed enrolment and login JWTs of
 * the push device API (spec/03 §7) use the same key as the proofs (spec/14 D9).
 */
public object DeviceJwt {
  public fun sign(claims: Map<String, JsonElement>, key: DPoPKey): String =
    signJws(jsonObjectOf("typ" to JsonPrimitive("JWT"), "alg" to JsonPrimitive(key.algorithm)), JsonObject(claims), key)
}

private fun signJws(header: JsonObject, payload: JsonObject, key: DPoPKey): String {
  val signingInput = Base64Url.encode(header.serialized()) + "." + Base64Url.encode(payload.serialized())
  return signingInput + "." + Base64Url.encode(key.sign(signingInput.toByteArray(StandardCharsets.UTF_8)))
}
