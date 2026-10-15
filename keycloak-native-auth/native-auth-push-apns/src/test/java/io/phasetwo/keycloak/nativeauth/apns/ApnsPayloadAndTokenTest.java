package io.phasetwo.keycloak.nativeauth.apns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

class ApnsPayloadAndTokenTest {

  static KeyPair keyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    return kpg.generateKeyPair();
  }

  static String pem(KeyPair kp) {
    return "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(kp.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
  }

  @Test
  void providerTokenIsAnEs256JwtSignedByThePemKeyAndReusedForFiftyMinutes() throws Exception {
    KeyPair kp = keyPair();
    ApnsProviderToken token = new ApnsProviderToken(pem(kp), "KEYID12345", "TEAM123456");
    String jwt = token.current();
    String[] parts = jwt.split("\\.");
    assertEquals(3, parts.length);
    JsonNode header = JsonSerialization.readValue(Base64.getUrlDecoder().decode(parts[0]), JsonNode.class);
    JsonNode payload = JsonSerialization.readValue(Base64.getUrlDecoder().decode(parts[1]), JsonNode.class);
    assertEquals("ES256", header.get("alg").asText());
    assertEquals("KEYID12345", header.get("kid").asText());
    assertEquals("TEAM123456", payload.get("iss").asText());
    assertTrue(payload.get("iat").asLong() > 0);
    // Raw r||s signature verifies against the public key once converted back to DER.
    byte[] raw = Base64.getUrlDecoder().decode(parts[2]);
    assertEquals(64, raw.length);
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(kp.getPublic());
    verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
    assertTrue(verifier.verify(rawToDer(raw)));
    assertEquals(jwt, token.current(), "cached");
    assertNotEquals(jwt, token.mint(payload.get("iat").asLong() + 1), "a new mint differs");
  }

  @Test
  void payloadCarriesTheBaItsysFieldsAndAVisibleTimeSensitiveAlertWithoutUserIdentity() throws Exception {
    String json = ApnsPayload.build("confirm.jwt.value", "cid-1", "cred-1", "demo-web", 1, 1);
    JsonNode node = JsonSerialization.readValue(json, JsonNode.class);
    assertEquals("confirm.jwt.value", node.get("confirmToken").asText());
    assertEquals("cid-1", node.get("cid").asText());
    assertEquals("cred-1", node.get("credId").asText());
    assertEquals(1, node.get("typ").asInt());
    assertEquals(1, node.get("ver").asInt());
    JsonNode aps = node.get("aps");
    assertEquals("time-sensitive", aps.get("interruption-level").asText());
    assertEquals(1, aps.get("mutable-content").asInt());
    assertEquals(ApnsPayload.CATEGORY, aps.get("category").asText());
    assertEquals(ApnsPayload.TITLE_KEY, aps.get("alert").get("title-loc-key").asText());
    assertEquals("demo-web", aps.get("alert").get("loc-args").get(0).asText());
    assertFalse(json.contains("alice"), "no username in the payload");
  }

  /** JWS raw r||s → DER, for verification with java.security. */
  static byte[] rawToDer(byte[] raw) {
    byte[] r = trim(java.util.Arrays.copyOfRange(raw, 0, 32));
    byte[] s = trim(java.util.Arrays.copyOfRange(raw, 32, 64));
    byte[] der = new byte[6 + r.length + s.length];
    der[0] = 0x30;
    der[1] = (byte) (4 + r.length + s.length);
    der[2] = 0x02;
    der[3] = (byte) r.length;
    System.arraycopy(r, 0, der, 4, r.length);
    der[4 + r.length] = 0x02;
    der[5 + r.length] = (byte) s.length;
    System.arraycopy(s, 0, der, 6 + r.length, s.length);
    return der;
  }

  private static byte[] trim(byte[] value) {
    int i = 0;
    while (i < value.length - 1 && value[i] == 0) i++;
    byte[] out = java.util.Arrays.copyOfRange(value, i, value.length);
    if ((out[0] & 0x80) != 0) {
      byte[] padded = new byte[out.length + 1];
      System.arraycopy(out, 0, padded, 1, out.length);
      return padded;
    }
    return out;
  }
}
