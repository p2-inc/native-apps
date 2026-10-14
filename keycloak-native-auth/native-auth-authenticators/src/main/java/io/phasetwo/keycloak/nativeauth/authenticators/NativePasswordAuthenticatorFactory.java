package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.PasswordCredentialModel;

public class NativePasswordAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-password";

  private static final NativePasswordAuthenticator SINGLETON = new NativePasswordAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSWORD;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Password";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'password' challenge of the native authentication profile against the user's password credential.";
  }

  @Override
  public String getReferenceCategory() {
    return PasswordCredentialModel.TYPE;
  }
}
