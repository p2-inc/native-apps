package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;

public class NativeTotpAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-totp";

  private static final NativeTotpAuthenticator SINGLETON = new NativeTotpAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.TOTP;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: TOTP";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'totp' challenge of the native authentication profile against the user's OTP credentials.";
  }

  @Override
  public String getReferenceCategory() {
    return OTPCredentialModel.TYPE;
  }
}
