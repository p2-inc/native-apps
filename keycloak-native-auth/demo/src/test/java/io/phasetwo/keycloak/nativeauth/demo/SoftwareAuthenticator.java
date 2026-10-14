package io.phasetwo.keycloak.nativeauth.demo;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A deterministic, device-less WebAuthn platform authenticator for the integration tests (spec/11
 * D6): one ES256 key pair per instance, resident credential with a fixed user handle, {@code none}
 * attestation, UP+UV flags set, signature counter always 0 (what Apple's passkeys do, and what
 * Keycloak tolerates). It produces exactly the four/three fields the native profile carries
 * (spec/03 §4.3, §4.4), all base64url without padding.
 */
final class SoftwareAuthenticator {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final byte FLAG_UP = 0x01;
  private static final byte FLAG_UV = 0x04;
  private static final byte FLAG_AT = 0x40;

  private final KeyPair keyPair;
  private final byte[] credentialId = new byte[32];
  private final String rpId;
  private final String origin;
  private String userHandle;

  /** @param origin the exact origin Keycloak will compute from the request base URI, e.g. {@code http://localhost:32768} */
  SoftwareAuthenticator(String rpId, String origin) {
    this.rpId = rpId;
    this.origin = origin;
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      this.keyPair = kpg.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    new SecureRandom().nextBytes(credentialId);
  }

  String credentialId() {
    return B64URL.encodeToString(credentialId);
  }

  String userHandle() {
    return userHandle;
  }

  /** {@code navigator.credentials.create()} equivalent: returns credential_id, client_data_json, attestation_object. */
  Map<String, String> register(String challengeB64Url, String userHandleB64Url) {
    this.userHandle = userHandleB64Url;
    byte[] clientData = clientDataJson("webauthn.create", challengeB64Url);
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    authData.write(FLAG_UP | FLAG_UV | FLAG_AT);
    authData.writeBytes(new byte[] {0, 0, 0, 0}); // sign count
    authData.writeBytes(new byte[16]); // AAGUID: all zero like a 'none' attestation platform authenticator
    authData.write(credentialId.length >> 8);
    authData.write(credentialId.length & 0xff);
    authData.writeBytes(credentialId);
    authData.writeBytes(coseKey());

    Map<Object, Object> attestation = new LinkedHashMap<>();
    attestation.put("fmt", "none");
    attestation.put("attStmt", new LinkedHashMap<>());
    attestation.put("authData", authData.toByteArray());

    Map<String, String> result = new LinkedHashMap<>();
    result.put("credential_id", credentialId());
    result.put("client_data_json", B64URL.encodeToString(clientData));
    result.put("attestation_object", B64URL.encodeToString(Cbor.encode(attestation)));
    result.put("transports", "internal,hybrid");
    return result;
  }

  /** {@code navigator.credentials.get()} equivalent (resident credential, so user_handle is included). */
  Map<String, String> assertion(String challengeB64Url) {
    return assertion(challengeB64Url, keyPair);
  }

  /** Same as {@link #assertion} but signed with a key that does not match the registered one. */
  Map<String, String> assertionWithWrongKey(String challengeB64Url) {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      return assertion(challengeB64Url, kpg.generateKeyPair());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private Map<String, String> assertion(String challengeB64Url, KeyPair signingKey) {
    byte[] clientData = clientDataJson("webauthn.get", challengeB64Url);
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    authData.write(FLAG_UP | FLAG_UV);
    authData.writeBytes(new byte[] {0, 0, 0, 0});
    byte[] authenticatorData = authData.toByteArray();

    byte[] signature;
    try {
      Signature sig = Signature.getInstance("SHA256withECDSA");
      sig.initSign(signingKey.getPrivate());
      sig.update(authenticatorData);
      sig.update(sha256(clientData));
      signature = sig.sign(); // DER-encoded, as WebAuthn requires for ES256
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    Map<String, String> result = new LinkedHashMap<>();
    result.put("credential_id", credentialId());
    result.put("client_data_json", B64URL.encodeToString(clientData));
    result.put("authenticator_data", B64URL.encodeToString(authenticatorData));
    result.put("signature", B64URL.encodeToString(signature));
    if (userHandle != null) result.put("user_handle", userHandle);
    return result;
  }

  private byte[] clientDataJson(String type, String challenge) {
    String json =
        "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
    return json.getBytes(StandardCharsets.UTF_8);
  }

  /** COSE_Key for an EC2 P-256 public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}. */
  private byte[] coseKey() {
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    Map<Object, Object> key = new LinkedHashMap<>();
    key.put(1, 2);
    key.put(3, -7);
    key.put(-1, 1);
    key.put(-2, fixed32(pub.getW().getAffineX()));
    key.put(-3, fixed32(pub.getW().getAffineY()));
    return Cbor.encode(key);
  }

  private static byte[] fixed32(BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    int srcPos = Math.max(0, raw.length - 32);
    int len = raw.length - srcPos;
    System.arraycopy(raw, srcPos, out, 32 - len, len);
    return out;
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
