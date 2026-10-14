package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.RequiredActionFactory;

/**
 * Factory marker for {@link NativeRequiredAction}s: lets the endpoint recognise a pending required
 * action as native (and run it in-band instead of answering {@code access_denied}) and advertise its
 * challenge type in {@code challenge_types_supported}.
 */
public interface NativeRequiredActionFactory extends RequiredActionFactory {

  ChallengeType challengeType();
}
