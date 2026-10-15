package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionClaims;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionCodec;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

/**
 * Mints the post-login {@code auth_session} (spec/03 §3.1, §5; spec/11 D4, spec/14 D5): a JWE
 * pointing at the user session, bound to the DPoP key when the login used one. Its {@code exp} is
 * the realm's SSO <em>idle</em> timeout from now (08 Q11: it dies with an idle session), never
 * beyond the session's maximum lifespan; a successful step-up or a §6 refusal mints a fresh one.
 * {@code ChallengeFlowDriver.stepUp} still checks {@code AuthenticationManager.isSessionValid}.
 */
final class PostLoginAuthSession {

  private PostLoginAuthSession() {}

  static String mint(KeycloakSession session, RealmModel realm, String userSessionId, String clientId, String jkt) {
    long now = Time.currentTime();
    return new AuthSessionCodec(new RealmAuthSessionKeys(session, realm))
        .encode(
            new AuthSessionClaims()
                .setUserSessionId(userSessionId)
                .setClientId(clientId)
                .setIat(now)
                .setExp(now + lifespan(session, realm, userSessionId, now))
                .setJkt(jkt));
  }

  /** SSO idle timeout from now, capped by what is left of the SSO max lifespan. */
  static long lifespan(KeycloakSession session, RealmModel realm, String userSessionId, long now) {
    int max = realm.getSsoSessionMaxLifespan() > 0 ? realm.getSsoSessionMaxLifespan() : 36_000;
    int idle = realm.getSsoSessionIdleTimeout() > 0 ? realm.getSsoSessionIdleTimeout() : max;
    long lifespan = Math.min(idle, max);
    UserSessionModel userSession = session.sessions().getUserSession(realm, userSessionId);
    if (userSession != null) {
      long remainingMax = userSession.getStarted() + max - now;
      lifespan = Math.max(1, Math.min(lifespan, remainingMax));
    }
    return lifespan;
  }
}
