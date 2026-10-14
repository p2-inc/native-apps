package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionClaims;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionCodec;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Mints the post-login {@code auth_session} (spec/03 §3.1, §5; spec/11 D4): a JWE pointing at the
 * user session, living as long as the SSO session may, bound to the DPoP key when the login used one.
 */
final class PostLoginAuthSession {

  private PostLoginAuthSession() {}

  static String mint(KeycloakSession session, RealmModel realm, String userSessionId, String clientId, String jkt) {
    long now = Time.currentTime();
    int lifespan = realm.getSsoSessionMaxLifespan() > 0 ? realm.getSsoSessionMaxLifespan() : 36_000;
    return new AuthSessionCodec(new RealmAuthSessionKeys(session, realm))
        .encode(
            new AuthSessionClaims()
                .setUserSessionId(userSessionId)
                .setClientId(clientId)
                .setIat(now)
                .setExp(now + lifespan)
                .setJkt(jkt));
  }
}
