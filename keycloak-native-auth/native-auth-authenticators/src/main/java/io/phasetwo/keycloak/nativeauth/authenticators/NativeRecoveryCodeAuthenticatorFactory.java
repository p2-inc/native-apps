package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class NativeRecoveryCodeAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-recovery-code";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.RECOVERY_CODE;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new NativeRecoveryCodeAuthenticator();
  }

  @Override
  public String getDisplayType() {
    return "Native: recovery code";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'recovery_code' challenge of the native authentication profile against the user's recovery authentication codes.";
  }

  @Override
  public String getReferenceCategory() {
    return "recovery-authn-codes";
  }
}
