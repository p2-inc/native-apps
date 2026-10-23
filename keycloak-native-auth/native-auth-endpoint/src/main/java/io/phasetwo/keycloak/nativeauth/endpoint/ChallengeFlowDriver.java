package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.AuthorizationCodeResponse;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeContext;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeResponse;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.model.RedirectToWebResponse;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionClaims;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionCodec;
import io.phasetwo.keycloak.nativeauth.core.session.InvalidAuthSessionException;
import io.phasetwo.keycloak.nativeauth.core.spi.ChallengeEnvelope;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
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
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AcrStore;
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
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Request lifecycle of {@code POST /native-auth/challenge} (spec/04 §2.1). Together with
 * {@link CodeIssuer}, {@link RequiredActionDriver}, {@link PasskeyRegistrationDriver},
 * {@link DPoPProofChecker} and {@link RedirectToWebBuilder} this is where all Keycloak-internal API
 * usage lives (spec/08 R2, spec/11, spec/13).
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
      // An invalid proof fails before anything else; a missing one is fine (spec/03 §8).
      String jkt = DPoPProofChecker.thumbprint(session);
      checkExtensionParameters(form);
      String authSessionParam = form.getFirst(Protocol.AUTH_SESSION);
      if (authSessionParam == null || authSessionParam.isBlank()) {
        return start(form, jkt);
      }
      return resume(authSessionParam, form, jkt);
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

  private Response start(MultivaluedMap<String, String> form, String jkt) {
    ClientModel client = requireClient(form.getFirst(Protocol.CLIENT_ID));
    checkInitialParameters(client, form);
    EventBuilder event = newEvent(client);
    AuthenticationSessionModel authSession = newAuthenticationSession(client, form, jkt);
    AuthenticationFlowModel flow = requireFlow(client);
    return run(authSession, flow, event);
  }

  private void checkInitialParameters(ClientModel client, MultivaluedMap<String, String> form) {
    if (!OAuth2Constants.CODE.equals(form.getFirst(Protocol.RESPONSE_TYPE))) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "response_type must be 'code'");
    }
    checkPkce(client, form.getFirst(Protocol.CODE_CHALLENGE), form.getFirst(Protocol.CODE_CHALLENGE_METHOD));
  }

  /** Root authentication session + tab with the §2.1 parameters as client notes (no cookies). */
  private AuthenticationSessionModel newAuthenticationSession(
      ClientModel client, MultivaluedMap<String, String> form, String jkt) {
    String codeChallenge = form.getFirst(Protocol.CODE_CHALLENGE);
    String codeChallengeMethod = form.getFirst(Protocol.CODE_CHALLENGE_METHOD);
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
    copyNote(form, Protocol.ACR_VALUES, authSession, OIDCLoginProtocol.ACR_PARAM);
    requestedLevelOfAuthentication(authSession, client, form.getFirst(Protocol.ACR_VALUES));
    if (codeChallenge != null) {
      authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, codeChallenge);
      authSession.setClientNote(
          OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM,
          codeChallengeMethod == null ? OAuth2Constants.PKCE_METHOD_PLAIN : codeChallengeMethod);
    }
    copyNote(form, Protocol.DEVICE_ID, authSession, NativeRequestContext.CLIENT_NOTE_DEVICE_ID);
    copyNote(form, Protocol.DEVICE_NAME, authSession, NativeRequestContext.CLIENT_NOTE_DEVICE_NAME);
    // spec/03 §2.3: initial-request extension parameters live for the whole login.
    form.forEach(
        (name, values) -> {
          if (name.startsWith(Protocol.EXTENSION_PARAM_PREFIX) && values != null && !values.isEmpty() && values.get(0) != null) {
            authSession.setClientNote(NativeRequestContext.CLIENT_NOTE_REQUEST_PARAM_PREFIX + name, values.get(0));
          }
        });
    NativeRequestContext.markNative(authSession, Protocol.VERSION);
    authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, LoginActionsService.AUTHENTICATE_PATH);
    if (jkt != null) {
      // Binds the in-flow auth_session (mint), the code (CodeIssuer) and the post-login value.
      authSession.setClientNote(OIDCLoginProtocol.DPOP_JKT, jkt);
    }
    session.getContext().setAuthenticationSession(authSession);
    return authSession;
  }

  /**
   * {@code acr_values} → {@code REQUESTED_LEVEL_OF_AUTHENTICATION}, as the authorization endpoint does
   * for a browser request: the client/realm ACR-to-LoA map, else the numeric value, else the minimum
   * (an unknown non-numeric value is not an error for a non-essential request). The LoA conditions in
   * the flow read the note (spec/03 §5).
   */
  private void requestedLevelOfAuthentication(AuthenticationSessionModel authSession, ClientModel client, String acrValues) {
    List<String> values = AcrUtils.getAcrValues(null, acrValues, client);
    if (values.isEmpty()) {
      return;
    }
    Map<String, Integer> acrLoaMap = AcrUtils.getAcrLoaMap(client);
    values.stream()
        .mapToInt(
            acr -> {
              Integer loa = acrLoaMap.get(acr);
              if (loa != null) return loa;
              try {
                return Integer.parseInt(acr);
              } catch (NumberFormatException e) {
                log.warnf("Requested acr value '%s' is neither numeric nor mapped in the ACR-to-LoA map; using the minimum level", acr);
                return Constants.MINIMUM_LOA;
              }
            })
        .min()
        .ifPresent(loa -> authSession.setClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION, String.valueOf(loa)));
  }

  /** Runs the native flow from its start for a fresh login or a step-up. */
  private Response run(AuthenticationSessionModel authSession, AuthenticationFlowModel flow, EventBuilder event) {
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
  // Step-up / re-authentication with the post-login auth_session (spec/03 §5, spec/13 D1)

  /**
   * Mirrors what {@code CookieAuthenticator} does for a browser with an identity cookie: the user is
   * known, the levels authenticated earlier in the user session are carried over, {@code max_age} /
   * {@code prompt=login} force a full re-authentication, and the flow then asks only for what the LoA
   * conditions still need. The code is issued for the existing user session.
   */
  private Response stepUp(AuthSessionClaims claims, ClientModel client, MultivaluedMap<String, String> form, String jkt) {
    String ref = AuthSessionCodec.hashPrefix(claims.getUserSessionId());
    if (form.getFirst(Protocol.CHALLENGE_TYPE) != null || form.getFirst(Protocol.RESPONSE_TYPE) == null) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST,
          Protocol.ERR_INVALID_REQUEST,
          "a post-login auth_session starts a step-up: send the initial-request parameters (response_type=code, code_challenge, acr_values/max_age) with it, not a challenge answer");
    }
    checkInitialParameters(client, form);
    UserSessionModel userSession = session.sessions().getUserSession(realm, claims.getUserSessionId());
    if (userSession == null || userSession.getUser() == null || !AuthenticationManager.isSessionValid(realm, userSession)) {
      log.debugf("step-up for user session %s refused: session ended", ref);
      throw invalidSession("the user session behind auth_session has ended; start a new login");
    }
    UserModel user = userSession.getUser();
    if (!user.isEnabled()) {
      throw invalidSession("the user is disabled; start a new login");
    }
    EventBuilder event = newEvent(client).user(user).detail("step_up", "true");
    AuthenticationSessionModel authSession = newAuthenticationSession(client, form, jkt);
    authSession.setAuthenticatedUser(user);
    authSession.setClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP, "true");
    authSession.setClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP_USER_SESSION, userSession.getId());
    String loaMap = userSession.getNote(Constants.LOA_MAP);
    if (loaMap != null) {
      authSession.setAuthNote(Constants.LOA_MAP, loaMap);
    }
    AuthenticationFlowModel flow = requireFlow(client);
    AcrStore acrStore = new AcrStore(session, authSession);
    LoginProtocol protocol = session.getProvider(LoginProtocol.class, OIDCLoginProtocol.LOGIN_PROTOCOL);
    if (protocol.requireReauthentication(userSession, authSession)) {
      // prompt=login or max_age exceeded: every level has to be authenticated again.
      acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
      authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
      log.debugf("step-up for user session %s: forced re-authentication", ref);
    } else {
      int previous = acrStore.getHighestAuthenticatedLevelFromPreviousAuthentication(flow.getId());
      acrStore.setLevelAuthenticatedToCurrentRequest(previous);
      log.debugf("step-up for user session %s: previously authenticated level %d, requested %d", ref, previous, acrStore.getRequestedLevelOfAuthentication(flow));
    }
    return run(authSession, flow, event);
  }

  /** True when an authenticator other than {@code native-username} succeeded in this session. */
  private boolean factorAuthenticated(AuthenticationSessionModel authSession) {
    for (Map.Entry<String, AuthenticationSessionModel.ExecutionStatus> e : authSession.getExecutionStatus().entrySet()) {
      if (e.getValue() != AuthenticationSessionModel.ExecutionStatus.SUCCESS) continue;
      AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(e.getKey());
      if (execution == null || execution.isAuthenticatorFlow()) continue;
      AuthenticatorFactory factory =
          (AuthenticatorFactory) session.getKeycloakSessionFactory().getProviderFactory(Authenticator.class, execution.getAuthenticator());
      if (factory instanceof NativeAuthenticatorFactory nf && nf.challengeType() != ChallengeType.USERNAME) {
        return true;
      }
    }
    return false;
  }

  // ---------------------------------------------------------------------------------------------
  // Continuation request (spec/03 §2.2)

  private Response resume(String token, MultivaluedMap<String, String> form, String jkt) {
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
    if (claims.getJkt() != null && !claims.getJkt().equals(jkt)) {
      // spec/03 §8: a session started with a DPoP proof must keep proving the same key.
      log.debugf("auth_session %s: DPoP key mismatch (proof %s)", ref, jkt == null ? "missing" : "different");
      throw invalidSession("auth_session is bound to a different DPoP key");
    }
    if (claims.isPostLogin()) {
      return stepUp(claims, client, form, jkt);
    }
    AuthenticationSessionModel authSession =
        sessions.getAuthenticationSessionByIdAndClient(
            realm, claims.getRootSessionId(), client, claims.getTabId());
    boolean inFlow =
        authSession != null
            && AuthenticationSessionModel.Action.AUTHENTICATE.name().equals(authSession.getAction());
    boolean inRequiredAction =
        authSession != null
            && AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name().equals(authSession.getAction())
            && NativeRequestContext.pendingRequiredAction(authSession) != null;
    if (authSession == null || !NativeRequestContext.isNative(authSession) || !(inFlow || inRequiredAction)) {
      log.debugf("auth_session %s: authentication session not found or not in progress", ref);
      throw invalidSession("auth_session expired or unknown");
    }
    // Same timeouts as the browser flow: login timeout while authenticating, user-action timeout
    // while a required action is pending (SessionCodeChecks).
    ClientSessionCode.ActionType actionType =
        inRequiredAction ? ClientSessionCode.ActionType.USER : ClientSessionCode.ActionType.LOGIN;
    if (!new ClientSessionCode<>(session, realm, authSession).isActionActive(actionType)) {
      log.debugf("auth_session %s: timeout exceeded", ref);
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
    event.detail(DETAIL_CHALLENGE_TYPE, challengeType);
    // Like AuthenticationProcessor.checkClientSession(): every valid request refreshes the timeout.
    authSession.getParentSession().setTimestamp(Time.currentTime());

    boolean skip = Protocol.ACTION_SKIP.equals(form.getFirst(Protocol.ACTION));
    if (skip && !(inRequiredAction && NativeRequestContext.isPendingRequiredActionSkippable(authSession))) {
      throw invalidRequest("action=skip is only valid on a descriptor with skippable: true", authSession);
    }
    if (inRequiredAction) {
      return continueRequiredAction(authSession, challengeId, event, skip);
    }
    AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(challengeId);
    if (execution == null) {
      throw invalidRequest("challenge_id is unknown", authSession);
    }
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
      AuthenticationExecutionModel model = execution == null ? null : realm.getAuthenticationExecutionById(execution);
      String providerId = model == null ? execution : model.getAuthenticator();
      if (NativeAuthConfig.nonNativeExecutionRedirectsToWeb(realm)) {
        // spec/03 §3.4: hand the login to the browser flow instead of failing it.
        String reason = "execution:" + providerId;
        log.warnf("Native flow '%s' reached non-native execution %s (%s); answering redirect_to_web", NativeAuthConfig.flowAlias(realm, authSession.getClient()), execution, providerId);
        RedirectToWebResponse redirect = RedirectToWebBuilder.tryBuild(session, realm, authSession, reason);
        sessions.removeAuthenticationSession(realm, authSession, false);
        if (redirect != null) {
          return Responses.json(Response.Status.FORBIDDEN, redirect);
        }
        throw new NativeAuthException(Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, reason + " cannot be completed in the native flow");
      }
      log.errorf(
          "Native flow '%s' produced a non-native response at execution %s (%s, HTTP %d); check the flow configuration or set the realm attribute %s=redirect_to_web",
          NativeAuthConfig.flowAlias(realm, authSession.getClient()),
          execution,
          providerId,
          processorResponse.getStatus(),
          Protocol.ATTR_NON_NATIVE_EXECUTION);
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

  /**
   * The flow is done: serve native required actions in-band (spec/11 D1), then issue the code.
   * Loops because a required action may complete immediately or be followed by another one.
   */
  private Response complete(AuthenticationSessionModel authSession, EventBuilder event) {
    CodeIssuer issuer = new CodeIssuer(session, realm, connection, request, event);
    RequiredActionDriver actions = new RequiredActionDriver(session, realm, request, event);
    UserSessionModel existingUserSession = null;
    if ("true".equals(authSession.getClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP))) {
      existingUserSession =
          session.sessions().getUserSession(realm, authSession.getClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP_USER_SESSION));
      if (existingUserSession == null || !AuthenticationManager.isSessionValid(realm, existingUserSession)) {
        sessions.removeAuthenticationSession(realm, authSession, false);
        throw invalidSession("the user session behind auth_session ended during the step-up; start a new login");
      }
      if (!factorAuthenticated(authSession)) {
        // Nothing had to be asked (level already satisfied): an SSO-style authentication, which keeps
        // AUTH_TIME untouched, exactly like CookieAuthenticator's cookie-only branch.
        authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");
      }
    }
    String previous = null;
    while (true) {
      CodeIssuer.Outcome outcome = issuer.complete(authSession, existingUserSession);
      String alias = outcome.pendingRequiredAction();
      if (alias == null) {
        event.success();
        return Responses.json(
            Response.Status.OK, new AuthorizationCodeResponse(outcome.code(), mintPostLogin(authSession, outcome.userSessionId())));
      }
      NativeRequiredActionFactory factory = RequiredActionDriver.nativeFactory(session, providerIdOf(alias));
      if (factory == null) {
        // One of Keycloak's own actions: serve it through its native variant when there is one (spec/03 §4.11).
        factory = RequiredActionDriver.substituteFor(session, realm, alias, authSession.getAuthenticatedUser());
      }
      if (factory == null || alias.equals(previous)) {
        // Non-native required action: hand the login to the browser (spec/03 §3.4) when possible.
        String reason = "required_action:" + alias;
        RedirectToWebResponse redirect = RedirectToWebBuilder.tryBuild(session, realm, authSession, reason);
        sessions.removeAuthenticationSession(realm, authSession, false);
        if (redirect != null) {
          event.detail("required_action", alias).detail("redirect_to_web", redirect.getReason()).error(Protocol.ERR_REDIRECT_TO_WEB);
          return Responses.json(Response.Status.FORBIDDEN, redirect);
        }
        event.detail("required_action", alias).error(Errors.NOT_ALLOWED);
        return Responses.error(
            Response.Status.FORBIDDEN,
            Protocol.ERR_ACCESS_DENIED,
            reason + " cannot be completed in the native flow");
      }
      previous = alias;
      switch (actions.challenge(authSession, factory, alias)) {
        case CHALLENGE -> {
          return challengeResponse(authSession, NativeRequestContext.markerResponse());
        }
        case SUCCESS -> {
          // Nothing to ask (e.g. already satisfied); evaluate the next action.
        }
        case FAILURE -> {
          return requiredActionFailed(authSession, event, alias, actions.lastFailureMessage());
        }
      }
    }
  }

  /** Continuation addressed to the pending native required action (challenge_id = provider id). */
  private Response continueRequiredAction(AuthenticationSessionModel authSession, String challengeId, EventBuilder event, boolean skip) {
    String pending = NativeRequestContext.pendingRequiredAction(authSession);
    NativeRequiredActionFactory factory = RequiredActionDriver.nativeFactory(session, pending);
    if (factory == null || !pending.equals(challengeId)) {
      throw invalidRequest("challenge_id is not pending", authSession);
    }
    RequiredActionDriver actions = new RequiredActionDriver(session, realm, request, event);
    String alias = NativeRequestContext.pendingRequiredActionAlias(authSession); // cleared by the driver on failure
    try {
      RequiredActionDriver.Status status = skip ? actions.processSkip(authSession, factory) : actions.processAction(authSession, factory);
      return switch (status) {
        case CHALLENGE -> challengeResponse(authSession, NativeRequestContext.markerResponse());
        case SUCCESS -> complete(authSession, event);
        case FAILURE -> requiredActionFailed(authSession, event, alias, actions.lastFailureMessage());
      };
    } catch (AuthenticationFlowException e) {
      return failed(authSession, event, e);
    } catch (WebApplicationException e) {
      return failed(authSession, event, e);
    }
  }

  private Response requiredActionFailed(AuthenticationSessionModel authSession, EventBuilder event, String alias, String message) {
    event.detail("required_action", alias).error(Errors.REJECTED_BY_USER);
    sessions.removeAuthenticationSession(realm, authSession, false);
    return Responses.error(
        Response.Status.FORBIDDEN, Protocol.ERR_ACCESS_DENIED, "required_action:" + alias + " " + (message == null ? "failed" : message));
  }

  /** Required actions are addressed by alias in the realm; the factory id is what we dispatch on. */
  private String providerIdOf(String alias) {
    var model = realm.getRequiredActionProviderByAlias(alias);
    return model == null ? alias : model.getProviderId();
  }

  /**
   * Post-login {@code auth_session} (spec/03 §5, spec/11 D4): points at the user session, lives as
   * long as the SSO session may, and is what a client will present for step-up in Phase 2.
   */
  private String mintPostLogin(AuthenticationSessionModel authSession, String userSessionId) {
    return PostLoginAuthSession.mint(
        session, realm, userSessionId, authSession.getClient().getClientId(), authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT));
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

  /** spec/03 §2.3: {@code x_*} parameters are opaque to the server but bounded. */
  private static void checkExtensionParameters(MultivaluedMap<String, String> form) {
    int count = 0;
    for (Map.Entry<String, List<String>> e : form.entrySet()) {
      String name = e.getKey();
      if (!name.startsWith(Protocol.EXTENSION_PARAM_PREFIX)) continue;
      count++;
      boolean tooLong =
          name.length() > Protocol.EXTENSION_PARAM_MAX_NAME_LENGTH
              || e.getValue().stream().anyMatch(v -> v != null && v.length() > Protocol.EXTENSION_PARAM_MAX_VALUE_LENGTH);
      if (count > Protocol.EXTENSION_PARAM_MAX_COUNT || tooLong) {
        throw new NativeAuthException(
            Response.Status.BAD_REQUEST,
            Protocol.ERR_INVALID_REQUEST,
            "at most " + Protocol.EXTENSION_PARAM_MAX_COUNT + " x_ parameters, names up to " + Protocol.EXTENSION_PARAM_MAX_NAME_LENGTH
                + " and values up to " + Protocol.EXTENSION_PARAM_MAX_VALUE_LENGTH + " characters");
      }
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
            .setIat(Time.currentTime())
            .setJkt(authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT)));
  }

  private long expiresIn(AuthenticationSessionModel authSession) {
    boolean requiredAction =
        AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name().equals(authSession.getAction());
    int lifespan =
        !requiredAction && realm.getAccessCodeLifespanLogin() > 0
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
    if ("true".equals(authSession.getClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP))) {
      ctx.setStepUp(true);
      ctx.setAcrRequested(authSession.getClientNote(OIDCLoginProtocol.ACR_PARAM));
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
