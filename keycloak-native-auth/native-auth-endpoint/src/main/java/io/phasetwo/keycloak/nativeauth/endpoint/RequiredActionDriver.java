package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionContextResult;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Runs a native required action in-band (spec/04 §4, spec/11 D1). Third class allowed to use
 * Keycloak-internal APIs (spec/08 R2): it reproduces the state handling of {@code
 * AuthenticationManager.executeAction} (challenge) and {@code LoginActionsService.processRequireAction}
 * (action) for an authentication session that has no browser: no redirects, no session-code query
 * parameters, no FreeMarker.
 *
 * <p>The session is moved to {@code Action.REQUIRED_ACTIONS} while an action is pending, exactly
 * like {@code AuthenticationManager.redirectToRequiredActions} does for the browser flow, and the
 * action's provider id is both the {@code challenge_id} the client echoes and the auth note the
 * endpoint uses to route the continuation.
 */
final class RequiredActionDriver {

  private static final Logger log = Logger.getLogger(RequiredActionDriver.class);

  enum Status {
    /** The action emitted a challenge into the envelope; respond with it. */
    CHALLENGE,
    /** The action completed; re-evaluate the next required action / issue the code. */
    SUCCESS,
    /** The action aborted the login. */
    FAILURE
  }

  private final KeycloakSession session;
  private final RealmModel realm;
  private final HttpRequest request;
  private final EventBuilder event;

  RequiredActionDriver(KeycloakSession session, RealmModel realm, HttpRequest request, EventBuilder event) {
    this.session = session;
    this.realm = realm;
    this.request = request;
    this.event = event;
  }

  /** @return the factory if {@code providerId} names an installed native required action, else null. */
  static NativeRequiredActionFactory nativeFactory(KeycloakSession session, String providerId) {
    RequiredActionFactory factory =
        (RequiredActionFactory)
            session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, providerId);
    return factory instanceof NativeRequiredActionFactory n ? n : null;
  }

  /** Equivalent of {@code AuthenticationManager.executeAction} for a native action. */
  Status challenge(AuthenticationSessionModel authSession, NativeRequiredActionFactory factory) {
    RequiredActionContextResult context = context(authSession, factory);
    RequiredActionProvider provider = AuthenticationManager.createRequiredAction(context);
    provider.requiredActionChallenge(context);
    return afterChallenge(authSession, factory, context, provider);
  }

  /** Equivalent of {@code LoginActionsService.processRequireAction} for a native action. */
  Status processAction(AuthenticationSessionModel authSession, NativeRequiredActionFactory factory) {
    event.event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId());
    RequiredActionContextResult context =
        new RequiredActionContextResult(authSession, realm, event, session, request, authSession.getAuthenticatedUser(), factory) {
          @Override
          public void ignore() {
            throw new RuntimeException("Cannot call ignore within processAction()");
          }
        };
    RequiredActionProvider provider = AuthenticationManager.createRequiredAction(context);
    provider.processAction(context);
    authSession.setAuthNote(AuthenticationProcessor.LAST_PROCESSED_EXECUTION, factory.getId());
    event.event(EventType.LOGIN);
    return afterChallenge(authSession, factory, context, provider);
  }

  private Status afterChallenge(
      AuthenticationSessionModel authSession,
      NativeRequiredActionFactory factory,
      RequiredActionContextResult context,
      RequiredActionProvider provider) {
    RequiredActionContext.Status status = context.getStatus();
    if (status == null) {
      throw new IllegalStateException("Required action " + factory.getId() + " set no status");
    }
    switch (status) {
      case CHALLENGE -> {
        Response challenge = context.getChallenge();
        if (!NativeRequestContext.isMarker(challenge)) {
          log.errorf("Native required action '%s' produced a non-native response (HTTP %d)", factory.getId(), challenge.getStatus());
          throw new IllegalStateException("Required action " + factory.getId() + " did not produce a native challenge");
        }
        // AuthenticationManager.redirectToRequiredActions equivalents (minus the redirect).
        authSession.setAction(AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name());
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, LoginActionsService.REQUIRED_ACTION);
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, factory.getId());
        return Status.CHALLENGE;
      }
      case SUCCESS -> {
        event.clone().event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).success();
        authSession.getAuthenticatedUser().removeRequiredAction(factory.getId());
        authSession.removeRequiredAction(factory.getId());
        authSession.removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
        AuthenticationManager.setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.SUCCESS, authSession);
        NativeRequestContext.clearPendingRequiredAction(authSession);
        return Status.SUCCESS;
      }
      case IGNORE -> {
        // AuthenticationManager.nextRequiredAction() has no "ignored actions" parameter, so an ignored
        // action would be returned again on the next evaluation; native actions must not ignore().
        log.warnf("Native required action '%s' called ignore(); treating it as a failure", factory.getId());
        NativeRequestContext.clearPendingRequiredAction(authSession);
        return Status.FAILURE;
      }
      default -> {
        NativeRequestContext.clearPendingRequiredAction(authSession);
        return Status.FAILURE;
      }
    }
  }

  private RequiredActionContextResult context(AuthenticationSessionModel authSession, RequiredActionFactory factory) {
    return new RequiredActionContextResult(authSession, realm, event, session, request, authSession.getAuthenticatedUser(), factory);
  }
}
