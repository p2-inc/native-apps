package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.WebAuthnCredentialModel;

public class NativePasskeyAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-passkey";

  private static final NativePasskeyAuthenticator SINGLETON = new NativePasskeyAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSKEY;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Passkey";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'passkey' challenge of the native authentication profile (WebAuthn assertion) against the realm's Passwordless policy and the user's passkeys; supports discoverable (username-less) login.";
  }

  @Override
  public String getReferenceCategory() {
    return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
  }
}
