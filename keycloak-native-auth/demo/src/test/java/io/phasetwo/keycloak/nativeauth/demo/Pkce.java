package io.phasetwo.keycloak.nativeauth.demo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** PKCE S256 pair (RFC 7636). */
record Pkce(String verifier, String challenge) {

  static Pkce s256() {
    byte[] raw = new byte[32];
    new SecureRandom().nextBytes(raw);
    String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
