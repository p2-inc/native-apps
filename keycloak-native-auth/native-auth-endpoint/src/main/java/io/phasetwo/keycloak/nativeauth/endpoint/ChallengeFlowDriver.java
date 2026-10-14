package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.AuthorizationCodeResponse;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeContext;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeResponse;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionClaims;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionCodec;
import io.phasetwo.keycloak.nativeauth.core.session.InvalidAuthSessionException;
import io.phasetwo.keycloak.nativeauth.core.spi.ChallengeEnvelope;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Request lifecycle of {@code POST /native-auth/challenge} (spec/04 §2.1). Together with
 * {@link CodeIssuer} this is where all Keycloak-internal API usage lives (spec/08 R2).
 *
 * <p>Initial request: create a root authentication session + tab for the client (no cookies), copy
 * the OIDC parameters into client notes, run {@code AuthenticationProcessor.authenticateOnly()} over
 * the realm's native flow. Continuation: decrypt {@code auth_session}, load the tab, validate that
 * {@code challenge_id} is one of the executions offered last time, and run that execution's
 * {@code action()} through {@code DefaultAuthenticationFlow.processAction}. The processor's own
 * {@code authenticationAction()} is not used because it insists that the answered execution equals
 * the single "current" one, which would defeat multi-entry {@code challenges[]} (spec/08 Q2).
 */
final class ChallengeFlowDriver {

  private static final Logger log = Logger.getLogger(ChallengeFlowDriver.class);
  private static final Pattern CODE_CHALLENGE = Pattern.compile("^[A-Za-z0-9_-]{43,128}$");
  private static final String DETAIL_NATIVE_PROTOCOL = "native_protocol";
  private static final String DETAIL_CHALLENGE_TYPE = "challenge_type";

  private final KeycloakSession session;
  private final RealmModel realm;
  private final ClientConnection connection;
  private final HttpRequest request;
  private final AuthSessionCodec codec;
  private final AuthenticationSessionManager sessions;

  ChallengeFlowDriver(KeycloakSession session) {
    this.session = session;
    this.realm = session.getContext().getRealm();
    this.connection = session.getContext().getConnection();
    this.request = session.getContext().getHttpRequest();
    this.codec = new AuthSessionCodec(new RealmAuthSessionKeys(session, realm));
    this.sessions = new AuthenticationSessionManager(session);
  }

  Response handle(MultivaluedMap<String, String> form) {
    try {
      String authSessionParam = form.getFirst(Protocol.AUTH_SESSION);
      if (authSessionParam == null || authSessionParam.isBlank()) {
        return start(form);
      }
      return resume(authSessionParam, form);
    } catch (NativeAuthException e) {
      return e.toResponse();
    } catch (RuntimeException e) {
      log.error("Unexpected error in native challenge endpoint", e);
      return Responses.error(
          Response.Status.INTERNAL_SERVER_ERROR, Protocol.ERR_SERVER_ERROR, "Unexpected server error");
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Initial request (spec/03 §2.1)

  private Response start(MultivaluedMap<String, String> form) {
    ClientModel client = requireClient(form.getFirst(Protocol.CLIENT_ID));
    if (!OAuth2Constants.CODE.equals(form.getFirst(Protocol.RESPONSE_TYPE))) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "response_type must be 'code'");
    }
    String codeChallenge = form.getFirst(Protocol.CODE_CHALLENGE);
    String codeChallengeMethod = form.getFirst(Protocol.CODE_CHALLENGE_METHOD);
    checkPkce(client, codeChallenge, codeChallengeMethod);

    EventBuilder event = newEvent(client);
    RootAuthenticationSessionModel root = sessions.createAuthenticationSession(realm, false);
    AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
    authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
    authSession.setRedirectUri(null);
    authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
    authSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, OAuth2Constants.CODE);
    authSession.setClientNote(
        OIDCLoginProtocol.ISSUER,
        Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
    copyNote(form, Protocol.SCOPE, authSession, OAuth2Constants.SCOPE);
    copyNote(form, Protocol.NONCE, authSession, OIDCLoginProtocol.NONCE_PARAM);
    copyNote(form, Protocol.LOGIN_HINT, authSession, OIDCLoginProtocol.LOGIN_HINT_PARAM);
    copyNote(form, Protocol.PROMPT, authSession, OIDCLoginProtocol.PROMPT_PARAM);
    copyNote(form, Protocol.MAX_AGE, authSession, OIDCLoginProtocol.MAX_AGE_PARAM);
    copyNote(form, Protocol.UI_LOCALES, authSession, LocaleSelectorProvider.CLIENT_REQUEST_LOCALE);
    // EXTENSION POINT (step-up, spec/03 §5): acr_values is stored verbatim; mapping it to
    // REQUESTED_LEVEL_OF_AUTHENTICATION / LoA conditions is Phase 2.
    copyNote(form, Protocol.ACR_VALUES, authSession, OIDCLoginProtocol.ACR_PARAM);
    if (codeChallenge != null) {
      authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, codeChallenge);
      authSession.setClientNote(
          OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM,
          codeChallengeMethod == null ? OAuth2Constants.PKCE_METHOD_PLAIN : codeChallengeMethod);
    }
    copyNote(form, Protocol.DEVICE_ID, authSession, NativeRequestContext.CLIENT_NOTE_DEVICE_ID);
    copyNote(form, Protocol.DEVICE_NAME, authSession, NativeRequestContext.CLIENT_NOTE_DEVICE_NAME);
    NativeRequestContext.markNative(authSession, Protocol.VERSION);
    authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, LoginActionsService.AUTHENTICATE_PATH);
    session.getContext().setAuthenticationSession(authSession);

    AuthenticationFlowModel flow = requireFlow(client);
    AuthenticationProcessor processor = processor(authSession, flow, event);
    try {
      Response challenge = processor.authenticateOnly();
      if (challenge != null) {
        return challengeResponse(authSession, challenge);
      }
      return complete(authSession, event);
    } catch (AuthenticationFlowException e) {
      return failed(authSession, event, e);
    } catch (WebApplicationException e) {
      return failed(authSession, event, e);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Continuation request (spec/03 §2.2)

  private Response resume(String token, MultivaluedMap<String, String> form) {
    String ref = AuthSessionCodec.hashPrefix(token);
    AuthSessionClaims claims;
    try {
      claims = codec.decode(token);
    } catch (InvalidAuthSessionException e) {
      log.debugf("auth_session %s rejected: %s", ref, e.getMessage());
      throw invalidSession("auth_session is invalid");
    }
    ClientModel client = realm.getClientByClientId(claims.getClientId());
    if (client == null || !client.isEnabled() || !NativeAuthConfig.isNativeEnabled(client)) {
      throw invalidSession("auth_session is bound to an unknown client");
    }
    String requestedClientId = form.getFirst(Protocol.CLIENT_ID);
    if (requestedClientId != null && !requestedClientId.equals(client.getClientId())) {
      throw invalidSession("client_id does not match auth_session");
    }
    AuthenticationSessionModel authSession =
        sessions.getAuthenticationSessionByIdAndClient(
            realm, claims.getRootSessionId(), client, claims.getTabId());
    if (authSession == null
        || !NativeRequestContext.isNative(authSession)
        || !AuthenticationSessionModel.Action.AUTHENTICATE.name().equals(authSession.getAction())) {
      log.debugf("auth_session %s: authentication session not found or not in progress", ref);
      throw invalidSession("auth_session expired or unknown");
    }
    if (!new ClientSessionCode<>(session, realm, authSession)
        .isActionActive(ClientSessionCode.ActionType.LOGIN)) {
      log.debugf("auth_session %s: login timeout exceeded", ref);
      sessions.removeAuthenticationSession(realm, authSession, false);
      throw invalidSession("auth_session expired");
    }
    session.getContext().setAuthenticationSession(authSession);
    EventBuilder event = newEvent(client);

    if (Protocol.ACTION_CANCEL.equals(form.getFirst(Protocol.ACTION))) {
      event.error(Errors.REJECTED_BY_USER);
      sessions.removeAuthenticationSession(realm, authSession, false);
      throw invalidSession("auth_session cancelled");
    }

    String challengeType = form.getFirst(Protocol.CHALLENGE_TYPE);
    String challengeId = form.getFirst(Protocol.CHALLENGE_ID);
    if (challengeType == null || challengeId == null) {
      throw invalidRequest("challenge_type and challenge_id are required", authSession);
    }
    Map<String, String> pending = NativeRequestContext.pending(authSession);
    String expectedType = pending.get(challengeId);
    if (expectedType == null) {
      throw invalidRequest("challenge_id is not pending", authSession);
    }
    if (ChallengeType.fromWire(challengeType) == null || !expectedType.equals(challengeType)) {
      throw invalidRequest("challenge_type does not match challenge_id", authSession);
    }
    AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(challengeId);
    if (execution == null) {
      throw invalidRequest("challenge_id is unknown", authSession);
    }
    event.detail(DETAIL_CHALLENGE_TYPE, challengeType);
    // Like AuthenticationProcessor.checkClientSession(): every valid request refreshes the login timeout.
    authSession.getParentSession().setTimestamp(Time.currentTime());

    AuthenticationFlowModel flowModel = requireFlow(client);
    AuthenticationProcessor processor = processor(authSession, flowModel, event);
    try {
      processor.validateUser(authSession.getAuthenticatedUser());
      AuthenticationFlow flow = processor.createFlowExecution(flowModel.getId(), execution);
      Response challenge = flow.processAction(challengeId);
      if (challenge != null) {
        return challengeResponse(authSession, challenge);
      }
      if (authSession.getAuthenticatedUser() == null) {
        throw new AuthenticationFlowException(AuthenticationFlowError.UNKNOWN_USER);
      }
      if (!flow.isSuccessful()) {
        throw new AuthenticationFlowException(flow.getFlowExceptions());
      }
      return complete(authSession, event);
    } catch (AuthenticationFlowException e) {
      return failed(authSession, event, e);
    } catch (WebApplicationException e) {
      return failed(authSession, event, e);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Outcomes

  private Response challengeResponse(AuthenticationSessionModel authSession, Response processorResponse) {
    ChallengeEnvelope envelope = NativeRequestContext.envelopeIfPresent(session);
    if (!NativeRequestContext.isMarker(processorResponse) || envelope == null || envelope.isEmpty()) {
      // spec/08 R8: a non-native execution (form authenticator, required action page...) in the flow.
      String execution = authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
      log.errorf(
          "Native flow '%s' produced a non-native response at execution %s (HTTP %d); check the flow configuration",
          NativeAuthConfig.flowAlias(realm, authSession.getClient()),
          execution,
          processorResponse.getStatus());
      sessions.removeAuthenticationSession(realm, authSession, false);
      throw new NativeAuthException(
          Response.Status.INTERNAL_SERVER_ERROR,
          Protocol.ERR_SERVER_ERROR,
          "The native flow contains an execution that cannot produce a native challenge");
    }
    ChallengeResponse body =
        new ChallengeResponse()
            .setAuthSession(mint(authSession))
            .setExpiresIn(expiresIn(authSession))
            .setChallenges(List.copyOf(envelope.challenges()))
            .setContext(context(authSession));
    return Responses.json(Response.Status.FORBIDDEN, body);
  }

  private Response complete(AuthenticationSessionModel authSession, EventBuilder event) {
    CodeIssuer.Outcome outcome =
        new CodeIssuer(session, realm, connection, request, event).complete(authSession);
    if (outcome.pendingRequiredAction() != null) {
      event.detail("required_action", outcome.pendingRequiredAction()).error(Errors.NOT_ALLOWED);
      sessions.removeAuthenticationSession(realm, authSession, false);
      return Responses.error(
          Response.Status.FORBIDDEN,
          Protocol.ERR_ACCESS_DENIED,
          "required_action:"
              + outcome.pendingRequiredAction()
              + " cannot be completed in the native flow (not implemented in Phase 0)");
    }
    event.success();
    // auth_session for step-up (spec/03 §5) is not re-minted in Phase 0: nothing would accept it yet.
    return Responses.json(Response.Status.OK, new AuthorizationCodeResponse(outcome.code(), null));
  }

  private Response failed(AuthenticationSessionModel authSession, EventBuilder event, Exception failure) {
    AuthenticationFlowError error = null;
    if (failure instanceof AuthenticationFlowException afe) {
      error = afe.getError();
      if (error == null && afe.getAfeList() != null && !afe.getAfeList().isEmpty()) {
        error = afe.getAfeList().get(0).getError();
      }
    }
    log.debugf(failure, "Native flow failed with %s", error);
    sessions.removeAuthenticationSession(realm, authSession, false);

    if (error == null) {
      event.error(Errors.INVALID_USER_CREDENTIALS);
      return Responses.error(
          Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, "Authentication failed");
    }
    return switch (error) {
      case USER_DISABLED -> {
        event.error(Errors.USER_DISABLED);
        yield Responses.error(Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, "Account disabled");
      }
      case USER_TEMPORARILY_DISABLED -> {
        event.error(Errors.USER_TEMPORARILY_DISABLED);
        yield Responses.error(
            Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, "Account temporarily locked");
      }
      case EXPIRED_CODE, INVALID_CLIENT_SESSION -> {
        event.error(Errors.SESSION_EXPIRED);
        yield Responses.error(
            Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_SESSION, "auth_session expired");
      }
      case CREDENTIAL_SETUP_REQUIRED -> {
        // EXTENSION POINT: enrolment via native required actions (spec/04 §4) / redirect_to_web.
        event.error(Errors.INVALID_USER_CREDENTIALS);
        yield Responses.error(
            Response.Status.FORBIDDEN,
            Protocol.ERR_ACCESS_DENIED,
            "A required credential is not set up for this account");
      }
      case INTERNAL_ERROR -> {
        event.error(Errors.INVALID_REQUEST);
        yield Responses.error(
            Response.Status.INTERNAL_SERVER_ERROR, Protocol.ERR_SERVER_ERROR, "Authentication flow error");
      }
      default -> {
        event.error(Errors.INVALID_USER_CREDENTIALS);
        yield Responses.error(
            Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, "Authentication failed");
      }
    };
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers

  private AuthenticationProcessor processor(
      AuthenticationSessionModel authSession, AuthenticationFlowModel flow, EventBuilder event) {
    return new AuthenticationProcessor()
        .setAuthenticationSession(authSession)
        .setFlowPath(LoginActionsService.AUTHENTICATE_PATH)
        .setFlowId(flow.getId())
        .setBrowserFlow(false)
        .setConnection(connection)
        .setEventBuilder(event)
        .setRealm(realm)
        .setSession(session)
        .setUriInfo(session.getContext().getUri())
        .setRequest(request);
  }

  private EventBuilder newEvent(ClientModel client) {
    return new EventBuilder(realm, session, connection)
        .event(EventType.LOGIN)
        .client(client)
        .detail(Details.AUTH_METHOD, OIDCLoginProtocol.LOGIN_PROTOCOL)
        .detail(DETAIL_NATIVE_PROTOCOL, Protocol.VERSION);
  }

  private ClientModel requireClient(String clientId) {
    if (clientId == null || clientId.isBlank()) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "client_id is required");
    }
    ClientModel client = realm.getClientByClientId(clientId);
    if (client == null || !client.isEnabled() || !NativeAuthConfig.isNativeEnabled(client)) {
      throw new NativeAuthException(
          Response.Status.UNAUTHORIZED,
          Protocol.ERR_INVALID_CLIENT,
          "Client not found or not enabled for native authentication");
    }
    if (!client.isPublicClient()) {
      throw new NativeAuthException(
          Response.Status.UNAUTHORIZED,
          Protocol.ERR_INVALID_CLIENT,
          "Native authentication requires a public client");
    }
    if (!client.isStandardFlowEnabled()) {
      throw new NativeAuthException(
          Response.Status.UNAUTHORIZED,
          Protocol.ERR_INVALID_CLIENT,
          "Client must have the standard flow enabled to exchange authorization codes");
    }
    return client;
  }

  private void checkPkce(ClientModel client, String codeChallenge, String codeChallengeMethod) {
    String required = OIDCAdvancedConfigWrapper.fromClientModel(client).getPkceCodeChallengeMethod();
    boolean clientRequiresPkce = required != null && !required.isBlank();
    if (codeChallenge == null) {
      if (clientRequiresPkce) {
        throw new NativeAuthException(
            Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "code_challenge is required");
      }
      return;
    }
    if (!CODE_CHALLENGE.matcher(codeChallenge).matches()) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "code_challenge is malformed");
    }
    String method = codeChallengeMethod == null ? OAuth2Constants.PKCE_METHOD_PLAIN : codeChallengeMethod;
    if (!OAuth2Constants.PKCE_METHOD_S256.equals(method) && !OAuth2Constants.PKCE_METHOD_PLAIN.equals(method)) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "unsupported code_challenge_method");
    }
    if (clientRequiresPkce && !required.equals(method)) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST,
          Protocol.ERR_INVALID_REQUEST,
          "client requires code_challenge_method=" + required);
    }
  }

  private AuthenticationFlowModel requireFlow(ClientModel client) {
    AuthenticationFlowModel flow = NativeAuthConfig.flow(realm, client);
    if (flow == null) {
      String alias = NativeAuthConfig.flowAlias(realm, client);
      log.errorf("Native authentication flow '%s' not found in realm '%s'", alias, realm.getName());
      throw new NativeAuthException(
          Response.Status.INTERNAL_SERVER_ERROR,
          Protocol.ERR_SERVER_ERROR,
          "Native authentication flow '" + alias + "' is not configured");
    }
    return flow;
  }

  private String mint(AuthenticationSessionModel authSession) {
    return codec.encode(
        new AuthSessionClaims()
            .setRootSessionId(authSession.getParentSession().getId())
            .setTabId(authSession.getTabId())
            .setClientId(authSession.getClient().getClientId())
            .setIat(Time.currentTime()));
  }

  private long expiresIn(AuthenticationSessionModel authSession) {
    int lifespan =
        realm.getAccessCodeLifespanLogin() > 0
            ? realm.getAccessCodeLifespanLogin()
            : realm.getAccessCodeLifespanUserAction();
    long remaining = lifespan - (Time.currentTime() - authSession.getParentSession().getTimestamp());
    return Math.max(0, remaining);
  }

  private static ChallengeContext context(AuthenticationSessionModel authSession) {
    ChallengeContext ctx = new ChallengeContext();
    ClientModel client = authSession.getClient();
    ctx.setClientName(client.getName() == null || client.getName().isBlank() ? client.getClientId() : client.getName());
    UserModel user = authSession.getAuthenticatedUser();
    if (user != null) {
      ctx.setUsername(user.getUsername());
      String display = ((user.getFirstName() == null ? "" : user.getFirstName()) + " " + (user.getLastName() == null ? "" : user.getLastName())).trim();
      ctx.setDisplayName(display.isEmpty() ? null : display);
    }
    return ctx;
  }

  private static void copyNote(
      MultivaluedMap<String, String> form, String param, AuthenticationSessionModel authSession, String note) {
    String value = form.getFirst(param);
    if (value != null && !value.isBlank()) {
      authSession.setClientNote(note, value);
    }
  }

  private static NativeAuthException invalidSession(String description) {
    return new NativeAuthException(Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_SESSION, description);
  }

  private NativeAuthException invalidRequest(String description, AuthenticationSessionModel authSession) {
    // The session stays valid, so hand back a (fresh) auth_session (spec/03 §3.5).
    return new NativeAuthException(
        Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, description, mint(authSession));
  }
}
