package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
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
}
