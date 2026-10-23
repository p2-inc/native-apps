package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.spi.ChallengeEnvelope;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredAction;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import jakarta.ws.rs.core.Response;
import java.util.List;
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
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
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
  private static final String DETAIL_SKIPPED = "skipped";

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
  /** The message the action passed to {@code failure(String)} in the last call, if any. */
  private String lastFailureMessage;

  String lastFailureMessage() {
    return lastFailureMessage;
  }

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

  /**
   * Equivalent of {@code AuthenticationManager.executeAction} for a native action.
   *
   * @param alias the user's pending required action this native action serves: its own id, or the
   *     Keycloak action it substitutes for (spec/03 §4.11)
   */
  Status challenge(AuthenticationSessionModel authSession, NativeRequiredActionFactory factory, String alias) {
    NativeRequestContext.setPendingRequiredActionAlias(authSession, alias);
    RequiredActionContextResult context = context(authSession, factory);
    RequiredActionProvider provider = AuthenticationManager.createRequiredAction(context);
    provider.requiredActionChallenge(context);
    return afterChallenge(authSession, factory, context, provider);
  }

  /**
   * The installed native action that substitutes for the Keycloak required action {@code alias}
   * (spec/03 §4.11): registered and enabled in the realm under its own id, and able to serve the
   * user; {@code null} when there is none.
   */
  static NativeRequiredActionFactory substituteFor(KeycloakSession session, RealmModel realm, String alias, UserModel user) {
    return session.getKeycloakSessionFactory().getProviderFactoriesStream(RequiredActionProvider.class)
        .filter(f -> f instanceof NativeRequiredActionFactory)
        .map(f -> (NativeRequiredActionFactory) f)
        .filter(f -> alias.equals(f.substitutesFor()))
        .filter(
            f -> {
              RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(f.getId());
              if (model == null || !model.isEnabled()) {
                log.debugf("Native required action '%s' could serve '%s' but is not registered and enabled in realm '%s'", f.getId(), alias, realm.getName());
                return false;
              }
              if (!f.canServe(session, realm, user)) {
                log.debugf("Native required action '%s' cannot serve '%s' for user %s", f.getId(), alias, user.getUsername());
                return false;
              }
              return true;
            })
        .findFirst()
        .orElse(null);
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

  /**
   * {@code action=skip} on a descriptor the action marked skippable (spec/03 §4.11): the action's
   * {@link NativeRequiredAction#processSkip} decides; on success the action is dropped from this
   * login (it was scheduled on the authentication session, never stored on the user).
   */
  Status processSkip(AuthenticationSessionModel authSession, NativeRequiredActionFactory factory) {
    event.event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).detail(DETAIL_SKIPPED, "true");
    RequiredActionContextResult context = context(authSession, factory);
    RequiredActionProvider provider = AuthenticationManager.createRequiredAction(context);
    if (!(provider instanceof NativeRequiredAction nativeAction)) {
      throw new IllegalStateException("Required action " + factory.getId() + " is not a native required action");
    }
    nativeAction.processSkip(context);
    event.event(EventType.LOGIN);
    if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
      event.clone().event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).detail(DETAIL_SKIPPED, "true").success();
      String alias = NativeRequestContext.pendingRequiredActionAlias(authSession);
      authSession.removeRequiredAction(alias);
      authSession.removeRequiredAction(factory.getId());
      authSession.removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
      AuthenticationManager.setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.CANCELLED, authSession);
      NativeRequestContext.clearPendingRequiredAction(authSession);
      return Status.SUCCESS;
    }
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
        markSkippable(authSession, factory, context, provider);
        return Status.CHALLENGE;
      }
      case SUCCESS -> {
        event.clone().event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).success();
        // The served action (the Keycloak alias when substituting, spec/03 §4.11) and the native id.
        String alias = NativeRequestContext.pendingRequiredActionAlias(authSession);
        for (String done : alias == null || alias.equals(factory.getId()) ? List.of(factory.getId()) : List.of(alias, factory.getId())) {
          authSession.getAuthenticatedUser().removeRequiredAction(done);
          authSession.removeRequiredAction(done);
        }
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
        lastFailureMessage = context.getErrorMessage();
        NativeRequestContext.clearPendingRequiredAction(authSession);
        return Status.FAILURE;
      }
    }
  }

  /**
   * Puts {@code skippable: true} on the emitted descriptor when the action allows a skip and the
   * served alias is only scheduled on this login: a skipped action stored on the user would be
   * returned again by {@code nextRequiredAction} (spec/03 §4.11).
   */
  private void markSkippable(
      AuthenticationSessionModel authSession,
      NativeRequiredActionFactory factory,
      RequiredActionContextResult context,
      RequiredActionProvider provider) {
    String alias = NativeRequestContext.pendingRequiredActionAlias(authSession);
    UserModel user = authSession.getAuthenticatedUser();
    boolean storedOnUser =
        user != null && user.getRequiredActionsStream().anyMatch(a -> a.equals(alias) || a.equals(factory.getId()));
    boolean skippable = provider instanceof NativeRequiredAction nativeAction && !storedOnUser && nativeAction.isSkippable(context);
    if (!skippable) {
      authSession.removeAuthNote(NativeRequestContext.AUTH_NOTE_REQUIRED_ACTION_SKIPPABLE);
      return;
    }
    authSession.setAuthNote(NativeRequestContext.AUTH_NOTE_REQUIRED_ACTION_SKIPPABLE, "true");
    ChallengeEnvelope envelope = NativeRequestContext.envelopeIfPresent(session);
    if (envelope != null) {
      envelope.challenges().forEach(d -> d.setSkippable(true));
    }
  }

  private RequiredActionContextResult context(AuthenticationSessionModel authSession, RequiredActionFactory factory) {
    return new RequiredActionContextResult(authSession, realm, event, session, request, authSession.getAuthenticatedUser(), factory);
  }
}
