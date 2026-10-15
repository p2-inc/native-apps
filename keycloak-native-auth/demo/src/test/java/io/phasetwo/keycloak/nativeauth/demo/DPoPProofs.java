package io.phasetwo.keycloak.nativeauth.demo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

/**
 * A DPoP key for the integration tests (RFC 9449): one ES256 key pair, proofs with {@code jti},
 * {@code htm}, {@code htu}, {@code iat} and optionally {@code ath}. Mirrors what the SDK's
 * {@code DPoPProofBuilder} sends.
 */
final class DPoPProofs {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private final KeyPair keyPair;

  DPoPProofs() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      keyPair = kpg.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private String x() {
    return coordinate(((ECPublicKey) keyPair.getPublic()).getW().getAffineX());
  }

  private String y() {
    return coordinate(((ECPublicKey) keyPair.getPublic()).getW().getAffineY());
  }

  private static String coordinate(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    int offset = raw.length > 32 ? raw.length - 32 : 0;
    System.arraycopy(raw, offset, fixed, 32 - (raw.length - offset), raw.length - offset);
    return B64URL.encodeToString(fixed);
  }

  String jwk() {
    return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x() + "\",\"y\":\"" + y() + "\"}";
  }

  /** RFC 7638 thumbprint, which is what the server stores as {@code jkt}. */
  String thumbprint() {
    String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x() + "\",\"y\":\"" + y() + "\"}";
    return B64URL.encodeToString(sha256(canonical.getBytes(StandardCharsets.UTF_8)));
  }

  String proof(String method, String url) {
    return proof(method, url, null);
  }

  String proof(String method, String url, String accessToken) {
    return proof(method, url, accessToken, java.util.Map.of());
  }

  /**
   * A proof with extra claims — the ba-itsys device API wants {@code sub} and {@code deviceId}
   * (spec/03 §7.1).
   */
  String proof(String method, String url, String accessToken, java.util.Map<String, String> extraClaims) {
    String header = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":" + jwk() + "}";
    StringBuilder payload =
        new StringBuilder("{\"jti\":\"")
            .append(UUID.randomUUID())
            .append("\",\"htm\":\"")
            .append(method)
            .append("\",\"htu\":\"")
            .append(url)
            .append("\",\"iat\":")
            .append(System.currentTimeMillis() / 1000);
    if (accessToken != null) {
      payload.append(",\"ath\":\"").append(B64URL.encodeToString(sha256(accessToken.getBytes(StandardCharsets.US_ASCII)))).append('"');
    }
    for (java.util.Map.Entry<String, String> e : extraClaims.entrySet()) {
      payload.append(",\"").append(e.getKey()).append("\":\"").append(e.getValue()).append('"');
    }
    payload.append('}');
    return sign(header, payload.toString());
  }

  /** Signs an arbitrary JSON payload as an ES256 JWS with {@code typ: JWT} (device enrolment / login tokens, spec/03 §7). */
  String signJwt(String payloadJson) {
    return sign("{\"typ\":\"JWT\",\"alg\":\"ES256\"}", payloadJson);
  }

  String sign(String headerJson, String payloadJson) {
    String signingInput =
        B64URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8))
            + "."
            + B64URL.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(keyPair.getPrivate());
      signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + "." + B64URL.encodeToString(derToRaw(signature.sign()));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** DER ECDSA signature → JWS raw {@code r || s} (32 + 32 bytes). */
  static byte[] derToRaw(byte[] der) {
    int offset = 2;
    if ((der[1] & 0x80) != 0) offset += der[1] & 0x7f;
    byte[] out = new byte[64];
    for (int i = 0; i < 2; i++) {
      if (der[offset++] != 0x02) throw new IllegalArgumentException("not a DER ECDSA signature");
      int len = der[offset++];
      int skip = 0;
      while (len - skip > 32) skip++;
      System.arraycopy(der, offset + skip, out, i * 32 + (32 - (len - skip)), len - skip);
      offset += len;
    }
    return out;
  }
}
