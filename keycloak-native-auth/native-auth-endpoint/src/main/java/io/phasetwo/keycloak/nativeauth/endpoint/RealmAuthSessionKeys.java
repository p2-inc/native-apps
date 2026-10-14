package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionKeys;
import javax.crypto.SecretKey;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Backs the {@code auth_session} codec with the realm's AES key ({@code aes-generated} provider, the
 * key Keycloak uses for its own {@code KC_RESTART} cookie). Rotating the key keeps old sessions valid
 * as long as the previous key stays enabled.
 */
final class RealmAuthSessionKeys implements AuthSessionKeys {

  private final KeycloakSession session;
  private final RealmModel realm;

  RealmAuthSessionKeys(KeycloakSession session, RealmModel realm) {
    this.session = session;
    this.realm = realm;
  }

  @Override
  public ActiveKey activeKey() {
    KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.ENC, Algorithm.AES);
    if (key == null) {
      throw new IllegalStateException("Realm has no active AES encryption key (aes-generated)");
    }
    return new ActiveKey(key.getKid(), (SecretKey) key.getSecretKey());
  }

  @Override
  public SecretKey keyById(String kid) {
    KeyWrapper key = session.keys().getKey(realm, kid, KeyUse.ENC, Algorithm.AES);
    return key == null ? null : (SecretKey) key.getSecretKey();
  }
}
