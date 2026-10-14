package io.phasetwo.keycloak.nativeauth.endpoint;

import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Turns a successfully authenticated native authentication session into a user session plus an
 * authorization code (spec/04 §2.2). This is the second of the two classes allowed to touch
 * Keycloak-internal APIs (spec/08 R2); it reproduces what {@code AuthenticationManager
 * .finishedRequiredActions} → {@code redirectAfterSuccessfulFlow} → {@code
 * OIDCLoginProtocol.authenticated} do for a browser, minus cookies and the redirect.
 */
final class CodeIssuer {

  private static final Logger log = Logger.getLogger(CodeIssuer.class);

  /** Outcome of {@link #complete}: either a code or the alias of a required action we cannot serve. */
  record Outcome(String code, String pendingRequiredAction) {}

  private final KeycloakSession session;
  private final RealmModel realm;
  private final ClientConnection connection;
  private final HttpRequest request;
  private final EventBuilder event;

  CodeIssuer(
      KeycloakSession session,
      RealmModel realm,
      ClientConnection connection,
      HttpRequest request,
      EventBuilder event) {
    this.session = session;
    this.realm = realm;
    this.connection = connection;
    this.request = request;
    this.event = event;
  }

  Outcome complete(AuthenticationSessionModel authSession) {
    // Same preamble as AuthenticationProcessor.authenticationComplete():
    new AcrStore(session, authSession).setAuthFlowLevelAuthenticatedToCurrentRequest();
    AuthenticationManager.setClientScopesInSession(session, authSession);

    String nextRequiredAction =
        AuthenticationManager.nextRequiredAction(session, authSession, request, event);
    if (nextRequiredAction != null) {
      // EXTENSION POINT (spec/04 §2.1, §4): a native RequiredActionProvider would emit a JSON
      // challenge here and anything else would become `redirect_to_web` via RedirectToWebBuilder
      // (PAR request_uri). Neither exists in Phase 0, so the caller reports access_denied.
      return new Outcome(null, nextRequiredAction);
    }

    // Note: newer Keycloak versions add LoginProtocol.authenticationComplete(authSession) here to
    // enforce single use of PAR request_uri values. Native requests never carry a PAR request_uri,
    // and the method does not exist in 26.8.x, so there is nothing to call.

    ClientModel client = authSession.getClient();
    // Read everything the code needs before attachSession(), which detaches the auth session tab.
    String nonce = authSession.getClientNote(OIDCLoginProtocol.NONCE_PARAM);
    String scope = authSession.getClientNote(OAuth2Constants.SCOPE);
    String resource = authSession.getClientNote(OAuth2Constants.RESOURCE);
    String codeChallenge = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
    String codeChallengeMethod = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM);
    String dpopJkt = authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT); // null until Phase 4
    String rootSessionId = authSession.getParentSession().getId();
    boolean ssoAuthentication = AuthenticatorUtil.isSSOAuthentication(authSession);
    int authTime =
        Optional.ofNullable(authSession.getClientNote(AuthenticationManager.AUTH_TIME_BROKER))
            .map(Integer::parseInt)
            .orElse(Time.currentTime());

    event.detail(Details.CODE_ID, rootSessionId);
    ClientSessionContext clientSessionCtx =
        AuthenticationProcessor.attachSession(authSession, null, session, realm, connection, event);
    AuthenticatedClientSessionModel clientSession = clientSessionCtx.getClientSession();
    UserSessionModel userSession = clientSession.getUserSession();

    // redirectAfterSuccessfulFlow() equivalents (no identity/remember-me cookies for a native client).
    if (userSession.getState() != UserSessionModel.State.LOGGED_IN) {
      userSession.setState(UserSessionModel.State.LOGGED_IN);
    }
    if (ssoAuthentication) {
      clientSession.setNote(AuthenticationManager.SSO_AUTH, "true");
    } else {
      userSession.setNote(AuthenticationManager.AUTH_TIME, String.valueOf(authTime));
      clientSession.removeNote(AuthenticationManager.SSO_AUTH);
    }
    AuthenticationManager.logSuccess(session, authSession);
    clientSessionCtx.setAttribute(OIDCLoginProtocol.NONCE_PARAM, nonce);

    // OIDCLoginProtocol.authenticated() equivalent for response_type=code.
    String redirectUriParam = NativeAuthConfig.codeRedirectUri(realm, client);
    OAuth2Code codeData =
        new OAuth2Code(
            SecretGenerator.getInstance().generateSecureID(),
            client.getId(),
            Time.currentTime() + realm.getAccessCodeLifespan(),
            nonce,
            scope,
            resource,
            redirectUriParam,
            codeChallenge,
            codeChallengeMethod,
            dpopJkt,
            userSession.getId());
    String code = OAuth2CodeParser.persistCode(session, clientSession, codeData);

    event.session(userSession).user(userSession.getUser());
    log.debugf(
        "Issued native authorization code for user session %s (client %s, redirect_uri mode %s)",
        userSession.getId(), client.getClientId(), NativeAuthConfig.codeRedirectUriMode(realm));
    return new Outcome(code, null);
  }
}
