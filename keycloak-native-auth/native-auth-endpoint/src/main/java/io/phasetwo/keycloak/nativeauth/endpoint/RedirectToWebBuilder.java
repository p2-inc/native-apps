package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.model.RedirectToWebResponse;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.SessionExpiration;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Builds the {@code redirect_to_web} answer (spec/03 §3.4, spec/13 D2): a pushed authorization
 * request (RFC 9126) stored exactly as Keycloak's {@code ParEndpoint} stores one, so the realm's
 * authorization endpoint accepts {@code client_id + request_uri} from the system browser and runs the
 * browser flow with the native flow's PKCE challenge, scope and a server-chosen {@code state}. Sixth
 * class allowed to use Keycloak-internal APIs (spec/08 R2): the PAR cache key and note names.
 */
final class RedirectToWebBuilder {

  private static final Logger log = Logger.getLogger(RedirectToWebBuilder.class);

  private RedirectToWebBuilder() {}

  /**
   * @return the response body, or {@code null} when the fallback is not possible (no PKCE in the
   *     native request, no usable redirect URI, PAR feature disabled)
   */
  static RedirectToWebResponse tryBuild(
      KeycloakSession session, RealmModel realm, AuthenticationSessionModel authSession, String reason) {
    if (!Profile.isFeatureEnabled(Profile.Feature.PAR)) {
      log.debug("redirect_to_web not possible: PAR feature disabled");
      return null;
    }
    String codeChallenge = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
    if (codeChallenge == null || codeChallenge.isBlank()) {
      log.debug("redirect_to_web not possible: the native request carried no PKCE challenge");
      return null;
    }
    ClientModel client = authSession.getClient();
    String redirectUri = NativeAuthConfig.webFallbackRedirectUri(client);
    if (redirectUri == null) {
      log.debugf("redirect_to_web not possible: client %s has no usable redirect URI", client.getClientId());
      return null;
    }

    Map<String, String> params = new HashMap<>();
    params.put(OAuth2Constants.CLIENT_ID, client.getClientId());
    params.put(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE);
    params.put(OAuth2Constants.REDIRECT_URI, redirectUri);
    String state = SecretGenerator.getInstance().randomString(32);
    params.put(OAuth2Constants.STATE, state);
    params.put(OAuth2Constants.CODE_CHALLENGE, codeChallenge);
    params.put(OAuth2Constants.CODE_CHALLENGE_METHOD, authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM));
    copy(authSession, OAuth2Constants.SCOPE, params, OAuth2Constants.SCOPE);
    copy(authSession, OIDCLoginProtocol.NONCE_PARAM, params, OIDCLoginProtocol.NONCE_PARAM);
    copy(authSession, OIDCLoginProtocol.ACR_PARAM, params, OIDCLoginProtocol.ACR_PARAM);
    copy(authSession, LocaleSelectorProvider.CLIENT_REQUEST_LOCALE, params, OIDCLoginProtocol.UI_LOCALES_PARAM);
    UserModel user = authSession.getAuthenticatedUser();
    if (user != null) {
      params.put(OIDCLoginProtocol.LOGIN_HINT_PARAM, user.getUsername());
    }
    // ParEndpoint's own bookkeeping: creation time, issuing client, DPoP key the code must be bound to.
    params.put(ParEndpoint.PAR_CREATED_TIME, String.valueOf(Time.currentTimeMillis()));
    params.put(ParEndpoint.PAR_CLIENT_ID, client.getClientId());
    String jkt = authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT);
    if (jkt != null) {
      params.put(ParEndpoint.PAR_DPOP_PROOF_JKT, jkt);
    }

    String key = SecretGenerator.getInstance().generateSecureID();
    int expiresIn = realm.getParPolicy().getRequestUriLifespan();
    long storeLifespan = (long) expiresIn + SessionExpiration.getAuthSessionLifespan(realm);
    session.singleUseObjects().put(ParEndpoint.buildCacheKey(realm.getId(), key), storeLifespan, params);
    log.debugf("Issued redirect_to_web request_uri for client %s (%s)", client.getClientId(), reason);

    return (RedirectToWebResponse)
        new RedirectToWebResponse()
            .setRequestUri(ParEndpoint.REQUEST_URI_PREFIX + key)
            .setExpiresIn((long) expiresIn)
            .setRedirectUri(redirectUri)
            .setState(state)
            .setReason(reason)
            .setErrorDescription("Complete the login in a browser: " + reason);
  }

  private static void copy(AuthenticationSessionModel authSession, String note, Map<String, String> params, String param) {
    String value = authSession.getClientNote(note);
    if (value != null && !value.isBlank()) {
      params.put(param, value);
    }
  }
}
