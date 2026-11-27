package io.phasetwo.keycloak.nativeauth.registration;

import io.phasetwo.keycloak.nativeauth.authenticators.AbstractNativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class NativeRegistrationAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-registration";

  private static final NativeRegistrationAuthenticator SINGLETON = new NativeRegistrationAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.REGISTRATION;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Registration";
  }

  @Override
  public String getHelpText() {
    return "Creates a user from the 'registration' challenge: the realm's user profile for registration plus a password checked against the password policy. Put it alone (REQUIRED) in the flow named by native-auth.registration-flow-alias (default native-registration).";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }
}
