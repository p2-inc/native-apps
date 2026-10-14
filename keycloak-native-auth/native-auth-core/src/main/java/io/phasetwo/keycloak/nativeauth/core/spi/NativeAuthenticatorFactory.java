package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.AuthenticatorFactory;

/** Factory marker: lets the endpoint advertise {@code challenge_types_supported} from installed factories. */
public interface NativeAuthenticatorFactory extends AuthenticatorFactory {

  ChallengeType challengeType();
}
