package io.phasetwo.keycloak.nativeauth.push;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import io.phasetwo.keycloak.nativeauth.authenticators.AbstractNativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

public class NativePushAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-push";

  /** Seconds between two {@code action=poll} requests the descriptor suggests. */
  public static final String CONFIG_POLL_INTERVAL = "pollIntervalSeconds";

  public static final int DEFAULT_POLL_INTERVAL = 3;

  private static final List<ProviderConfigProperty> CONFIG =
      List.of(
          // Same keys as ba-itsys' authenticator so its AuthenticatorConfigHelper reads them unchanged.
          property(PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG, "Login challenge TTL (s)", "Lifetime of a push challenge", ProviderConfigProperty.STRING_TYPE, String.valueOf(PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.getSeconds())),
          property(PushMfaConstants.USER_VERIFICATION_CONFIG, "User verification", "none, number-match or pin (the number / PIN is sent to the native client in params.user_verification)", ProviderConfigProperty.STRING_TYPE, PushMfaConstants.USER_VERIFICATION_NONE),
          property(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "PIN length", "Length of the PIN when user verification is pin", ProviderConfigProperty.STRING_TYPE, String.valueOf(PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH)),
          property(CONFIG_POLL_INTERVAL, "Poll interval (s)", "Suggested seconds between action=poll requests", ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_POLL_INTERVAL)));

  private static ProviderConfigProperty property(String name, String label, String help, String type, String defaultValue) {
    ProviderConfigProperty p = new ProviderConfigProperty();
    p.setName(name);
    p.setLabel(label);
    p.setHelpText(help);
    p.setType(type);
    p.setDefaultValue(defaultValue);
    return p;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PUSH;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new NativePushAuthenticator(session);
  }

  @Override
  public String getDisplayType() {
    return "Native: push MFA (approve on device)";
  }

  @Override
  public String getHelpText() {
    return "Issues a ba-itsys push-MFA challenge and lets the native client poll it (spec/03 §4.7).";
  }

  @Override
  public String getReferenceCategory() {
    return PushMfaConstants.CREDENTIAL_TYPE;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG;
  }
}
