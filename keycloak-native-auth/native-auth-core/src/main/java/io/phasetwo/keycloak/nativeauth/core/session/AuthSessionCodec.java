package io.phasetwo.keycloak.nativeauth.core.session;

import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.util.TokenUtil;

/**
 * Encodes/decodes the opaque {@code auth_session} value as a compact JWE (spec/02 D5).
 *
 * <p>Algorithm: {@code alg=dir}, {@code enc=A128GCM|A192GCM|A256GCM} depending on the AES key size
 * (Keycloak's realm {@code aes-generated} key is 128-bit by default, 256-bit when the provider is
 * configured with {@code secretSize=32}). This reuses {@link TokenUtil#jweDirectEncode}, i.e. exactly
 * the construction Keycloak itself uses for the {@code KC_RESTART} cookie, so no new crypto code is
 * introduced. The JWE header carries the {@code kid} so key rotation keeps old sessions decryptable
 * while the previous key is still present (passive).
 */
public final class AuthSessionCodec {

  private final AuthSessionKeys keys;

  public AuthSessionCodec(AuthSessionKeys keys) {
    this.keys = keys;
  }

  public String encode(AuthSessionClaims claims) {
    AuthSessionKeys.ActiveKey active = keys.activeKey();
    try {
      byte[] content = NativeAuthJson.writeBytes(claims);
      return TokenUtil.jweDirectEncode(active.kid(), active.key(), null, content);
    } catch (JWEException e) {
      throw new IllegalStateException("Unable to encrypt auth_session", e);
    }
  }

  public AuthSessionClaims decode(String token) throws InvalidAuthSessionException {
    if (token == null || token.isBlank()) {
      throw new InvalidAuthSessionException("auth_session missing");
    }
    String kid;
    try {
      kid = new JWE(token).getHeader().getKeyId();
    } catch (RuntimeException e) {
      throw new InvalidAuthSessionException("auth_session is not a JWE", e);
    }
    if (kid == null) {
      throw new InvalidAuthSessionException("auth_session has no kid");
    }
    SecretKey key = keys.keyById(kid);
    if (key == null) {
      throw new InvalidAuthSessionException("auth_session key no longer available");
    }
    byte[] content;
    try {
      content = TokenUtil.jweDirectVerifyAndDecode(key, null, token);
    } catch (JWEException | RuntimeException e) {
      throw new InvalidAuthSessionException("auth_session cannot be decrypted", e);
    }
    AuthSessionClaims claims;
    try {
      claims = NativeAuthJson.read(content, AuthSessionClaims.class);
    } catch (IOException e) {
      throw new InvalidAuthSessionException("auth_session payload malformed", e);
    }
    if (!AuthSessionClaims.TYPE.equals(claims.getTyp())
        || claims.getRootSessionId() == null
        || claims.getTabId() == null
        || claims.getClientId() == null) {
      throw new InvalidAuthSessionException("auth_session payload incomplete");
    }
    return claims;
  }

  /**
   * Log-safe reference to a token: the first 8 hex characters of its SHA-256 (spec/07 §3). Never log
   * the token itself.
   */
  public static String hashPrefix(String token) {
    if (token == null) return "null";
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest, 0, 4);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
