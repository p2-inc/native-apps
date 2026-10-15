package io.phasetwo.keycloak.nativeauth.apns;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * APNs token-based provider authentication: an ES256 JWT with {@code kid} = the key id and {@code
 * iss} = the team id, signed with the {@code .p8} key, reused for up to 50 minutes (Apple allows
 * an hour and refuses tokens refreshed more often than every 20 minutes).
 */
final class ApnsProviderToken {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  static final long REUSE_SECONDS = 50 * 60;

  private final PrivateKey key;
  private final String keyId;
  private final String teamId;
  private volatile String cached;
  private volatile long cachedAt;

  ApnsProviderToken(String pkcs8Pem, String keyId, String teamId) {
    this.key = parsePkcs8(pkcs8Pem);
    this.keyId = keyId;
    this.teamId = teamId;
  }

  /** The current token (minted now when none is cached or the cached one is older than 50 min). */
  String current() {
    long now = System.currentTimeMillis() / 1000;
    String token = cached;
    if (token == null || now - cachedAt >= REUSE_SECONDS) {
      synchronized (this) {
        if (cached == null || now - cachedAt >= REUSE_SECONDS) {
          cached = mint(now);
          cachedAt = now;
        }
        token = cached;
      }
    }
    return token;
  }

  String mint(long issuedAt) {
    String header = "{\"alg\":\"ES256\",\"kid\":\"" + keyId + "\"}";
    String payload = "{\"iss\":\"" + teamId + "\",\"iat\":" + issuedAt + "}";
    String signingInput = B64URL.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + B64URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(key);
      signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + "." + B64URL.encodeToString(derToRaw(signature.sign()));
    } catch (Exception e) {
      throw new IllegalStateException("Cannot sign the APNs provider token", e);
    }
  }

  static PrivateKey parsePkcs8(String pem) {
    String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    try {
      return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    } catch (Exception e) {
      throw new IllegalArgumentException("The APNs key is not a PKCS#8 EC private key (.p8)", e);
    }
  }

  /** DER ECDSA signature → JWS raw {@code r || s} (32 + 32 bytes). */
  static byte[] derToRaw(byte[] der) {
    int offset = 2;
    if ((der[1] & 0x80) != 0) offset += der[1] & 0x7f;
    byte[] raw = new byte[64];
    for (int part = 0; part < 2; part++) {
      if (der[offset++] != 0x02) throw new IllegalArgumentException("not a DER ECDSA signature");
      int length = der[offset++];
      int start = offset;
      offset += length;
      // Strip a leading zero (sign byte) or left-pad to 32 bytes.
      int copy = Math.min(length, 32);
      System.arraycopy(der, start + length - copy, raw, part * 32 + (32 - copy), copy);
    }
    return raw;
  }
}
