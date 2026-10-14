package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;

/**
 * An {@link Authenticator} that speaks the native profile: instead of rendering a form it describes a
 * challenge (spec/03 §4) and validates the continuation parameters in {@link #action}.
 *
 * <p>{@link #describe} must be side-effect free with respect to the flow state (it may store
 * per-challenge material such as a WebAuthn challenge in auth notes) because it is also invoked for
 * sibling ALTERNATIVE executions that are not the "current" one, so that all eligible alternatives can
 * be listed in a single {@code challenges[]} set (spec/08 Q2).
 */
public interface NativeAuthenticator extends Authenticator {

  ChallengeType challengeType();

  /**
   * Build the descriptor for {@code execution}. The caller fills {@code id}, {@code required} and
   * {@code error}; the implementation sets {@code type}, {@code label} and {@code params}.
   */
  ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution);
}
