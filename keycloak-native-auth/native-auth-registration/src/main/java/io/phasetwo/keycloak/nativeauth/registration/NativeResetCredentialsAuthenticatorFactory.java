package io.phasetwo.keycloak.nativeauth.registration;

import io.phasetwo.keycloak.nativeauth.authenticators.AbstractNativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class NativeResetCredentialsAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-reset-credentials";

  private static final NativeResetCredentialsAuthenticator SINGLETON = new NativeResetCredentialsAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.OTP;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Reset credentials (email code)";
  }

  @Override
  public String getHelpText() {
    return "Forgot password: asks for the username or email, emails a code, then runs Update Password natively and signs the user in. Put it alone (REQUIRED) in the flow named by native-auth.reset-credentials-flow-alias (default native-reset-credentials).";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }
}
