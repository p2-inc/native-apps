package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

/**
 * A {@link RequiredActionProvider} that speaks the native profile (spec/04 §4, spec/11 D1): instead of
 * rendering a page, {@code requiredActionChallenge} puts one challenge descriptor into the request's
 * {@link ChallengeEnvelope} and hands the marker response to {@code context.challenge()}; {@code
 * processAction} validates the continuation parameters and ends with {@code context.success()} or a
 * new challenge carrying {@code error}.
 *
 * <p>The endpoint routes the client's answer by {@code challenge_id}, which for a required action is
 * the provider id (there is no execution id); see {@link NativeRequestContext#setPendingRequiredAction}.
 */
public interface NativeRequiredAction extends RequiredActionProvider {

  ChallengeType challengeType();

  /**
   * Whether the user may decline this action for the current login with {@code action=skip}
   * (spec/03 §4.11). Asked by the endpoint after every challenge this action emits; {@code true}
   * puts {@code skippable: true} on the descriptor. The endpoint only honours it for an action
   * scheduled on the authentication session, never for one stored on the user.
   */
  default boolean isSkippable(RequiredActionContext context) {
    return false;
  }

  /**
   * Handles {@code action=skip} on a descriptor this action marked skippable. Record the decline if
   * the action needs it, then call {@code context.success()}: the endpoint drops the action from this
   * login and continues. The default refuses the skip and ends the login.
   */
  default void processSkip(RequiredActionContext context) {
    context.failure();
  }
}
