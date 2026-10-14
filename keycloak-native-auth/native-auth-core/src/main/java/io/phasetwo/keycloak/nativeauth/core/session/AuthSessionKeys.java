package io.phasetwo.keycloak.nativeauth.core.session;

import javax.crypto.SecretKey;

/**
 * Supplies the symmetric keys used to encrypt {@code auth_session}. The endpoint backs this with the
 * realm's {@code aes-generated} key (Keycloak {@code KeyUse.ENC}, algorithm {@code AES}), the same key
 * Keycloak uses for its own {@code KC_RESTART} cookie; tests use a fixed in-memory key.
 */
public interface AuthSessionKeys {

  /** Key used for new tokens. */
  ActiveKey activeKey();

  /** Key referenced by {@code kid} of an existing token, or {@code null} if unknown (rotated away). */
  SecretKey keyById(String kid);

  /** The active key plus its {@code kid}. */
  record ActiveKey(String kid, SecretKey key) {}
}
