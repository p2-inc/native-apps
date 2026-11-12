package io.phasetwo.keycloak.nativeauth.pin;

import io.phasetwo.keycloak.nativeauth.authenticators.AbstractNativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Registers {@code native-pin} ("Native: PIN"). Its execution config is keycloak-pin's own ({@code
 * max-attempts}, {@link PinConfig#AUTHENTICATOR_PROPERTIES}); its reference category is the PIN
 * credential type, so the account console keeps offering the PIN when only native flows use it.
 */
public class NativePinAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-pin";

  private static final NativePinAuthenticator SINGLETON = new NativePinAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PIN;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: PIN";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'pin' challenge of the native authentication profile against the user's"
        + " PIN (keycloak-pin). Place after a step that identifies the user, usually in a"
        + " conditional sub-flow with 'Condition - user configured'.";
  }

  @Override
  public String getReferenceCategory() {
    return PinConstants.CREDENTIAL_TYPE;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return PinConfig.AUTHENTICATOR_PROPERTIES;
  }
}
