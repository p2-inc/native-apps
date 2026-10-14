package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

public class NativeUsernameAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-username";
  public static final String CONFIG_REVEAL_USER_NOT_FOUND = "reveal-user-not-found";

  private static final NativeUsernameAuthenticator SINGLETON = new NativeUsernameAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.USERNAME;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Username";
  }

  @Override
  public String getHelpText() {
    return "Identifies the user from the 'username' challenge of the native authentication profile.";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty reveal = new ProviderConfigProperty();
    reveal.setName(CONFIG_REVEAL_USER_NOT_FOUND);
    reveal.setLabel("Reveal unknown username");
    reveal.setHelpText(
        "When on, an unknown username gets error code 'invalid_user'. Default off: a generic 'invalid_credential' is returned (spec/03 §4.1).");
    reveal.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    reveal.setDefaultValue("false");
    return List.of(reveal);
  }
}
