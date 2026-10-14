package io.phasetwo.keycloak.nativeauth.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEHeader;

class AuthSessionCodecTest {

  private static SecretKey aesKey(int bytes) {
    byte[] raw = new byte[bytes];
    new SecureRandom().nextBytes(raw);
    return new SecretKeySpec(raw, "AES");
  }

  private static AuthSessionKeys keys(String kid, SecretKey key) {
    return new AuthSessionKeys() {
      @Override
      public ActiveKey activeKey() {
        return new ActiveKey(kid, key);
      }

      @Override
      public SecretKey keyById(String id) {
        return kid.equals(id) ? key : null;
      }
    };
  }

  private static AuthSessionClaims claims() {
    return new AuthSessionClaims()
        .setRootSessionId("root-1")
        .setTabId("tab-1")
        .setClientId("demo-ios")
        .setIat(1_760_000_000L);
  }

  @BeforeAll
  static void crypto() {
    CryptoIntegration.init(AuthSessionCodecTest.class.getClassLoader());
  }

  @Test
  void roundTripWith128BitKey() throws Exception {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    String token = codec.encode(claims());
    assertEquals(5, token.split("\\.").length, "compact JWE has five parts");
    JWEHeader header = (JWEHeader) new JWE(token).getHeader();
    assertEquals(JWEConstants.DIRECT, header.getAlgorithm());
    assertEquals(JWEConstants.A128GCM, header.getEncryptionAlgorithm());
    assertEquals("k1", header.getKeyId());

    AuthSessionClaims decoded = codec.decode(token);
    assertEquals("root-1", decoded.getRootSessionId());
    assertEquals("tab-1", decoded.getTabId());
    assertEquals("demo-ios", decoded.getClientId());
    assertEquals(1_760_000_000L, decoded.getIat());
    assertNull(decoded.getJkt());
  }

  @Test
  void usesA256GcmWith256BitKey() throws Exception {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k256", aesKey(32)));
    String token = codec.encode(claims());
    assertEquals(JWEConstants.A256GCM, ((JWEHeader) new JWE(token).getHeader()).getEncryptionAlgorithm());
    assertEquals("root-1", codec.decode(token).getRootSessionId());
  }

  @Test
  void payloadIsNotReadableWithoutTheKey() {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    String token = codec.encode(claims());
    String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[3]));
    assertFalse(payload.contains("root-1"));
    assertFalse(payload.contains("demo-ios"));
  }

  @Test
  void tamperedTokenIsRejected() {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    String token = codec.encode(claims());
    String[] parts = token.split("\\.");
    char c = parts[3].charAt(0);
    parts[3] = (c == 'A' ? 'B' : 'A') + parts[3].substring(1);
    String tampered = String.join(".", parts);
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode(tampered));
  }

  @Test
  void tokenFromAnotherKeyIsRejected() {
    AuthSessionCodec a = new AuthSessionCodec(keys("k1", aesKey(16)));
    AuthSessionCodec b = new AuthSessionCodec(keys("k1", aesKey(16)));
    String token = a.encode(claims());
    assertThrows(InvalidAuthSessionException.class, () -> b.decode(token));
  }

  @Test
  void unknownKidIsRejected() {
    AuthSessionCodec a = new AuthSessionCodec(keys("old", aesKey(16)));
    AuthSessionCodec b = new AuthSessionCodec(keys("new", aesKey(16)));
    String token = a.encode(claims());
    InvalidAuthSessionException e =
        assertThrows(InvalidAuthSessionException.class, () -> b.decode(token));
    assertTrue(e.getMessage().contains("key"));
  }

  @Test
  void garbageIsRejected() {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode("not-a-jwe"));
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode(""));
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode(null));
  }

  @Test
  void hashPrefixIsStableAndShort() {
    String token = "eyJ.something";
    assertEquals(8, AuthSessionCodec.hashPrefix(token).length());
    assertEquals(AuthSessionCodec.hashPrefix(token), AuthSessionCodec.hashPrefix(token));
    assertNotEquals(AuthSessionCodec.hashPrefix(token), AuthSessionCodec.hashPrefix(token + "x"));
  }

  @Test
  void postLoginShapeRoundTripsAndIsDistinguishable() throws Exception {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    long now = org.keycloak.common.util.Time.currentTime();
    String token =
        codec.encode(
            new AuthSessionClaims()
                .setUserSessionId("user-session-1")
                .setClientId("demo-ios")
                .setIat(now)
                .setExp(now + 3600));
    AuthSessionClaims decoded = codec.decode(token);
    assertTrue(decoded.isPostLogin());
    assertEquals("user-session-1", decoded.getUserSessionId());
    assertNull(decoded.getRootSessionId());
    assertEquals(now + 3600, decoded.getExp());
    assertFalse(codec.decode(codec.encode(claims())).isPostLogin());
  }

  @Test
  void expiredPostLoginTokenIsRejected() {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    long now = org.keycloak.common.util.Time.currentTime();
    String token =
        codec.encode(
            new AuthSessionClaims()
                .setUserSessionId("user-session-1")
                .setClientId("demo-ios")
                .setIat(now - 10)
                .setExp(now - 1));
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode(token));
  }

  @Test
  void payloadWithNeitherShapeIsRejected() {
    AuthSessionCodec codec = new AuthSessionCodec(keys("k1", aesKey(16)));
    String token = codec.encode(new AuthSessionClaims().setClientId("demo-ios").setIat(1L));
    assertThrows(InvalidAuthSessionException.class, () -> codec.decode(token));
  }
}
