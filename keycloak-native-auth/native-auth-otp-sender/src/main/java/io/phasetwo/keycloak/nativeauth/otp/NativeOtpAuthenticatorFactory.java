package io.phasetwo.keycloak.nativeauth.otp;

import io.phasetwo.keycloak.nativeauth.authenticators.AbstractNativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

public class NativeOtpAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-otp";

  public static final String CONFIG_CHANNEL = "channel";
  public static final String CONFIG_DIGITS = "digits";
  public static final String CONFIG_TTL = "ttl";
  public static final String CONFIG_RESEND_COOLDOWN = "resend-cooldown";
  public static final String CONFIG_MAX_ATTEMPTS = "max-attempts";

  public static final String DEFAULT_CHANNEL = EmailOtpSenderFactory.ID;
  public static final int DEFAULT_DIGITS = 6;
  public static final int DEFAULT_TTL = 300;
  public static final int DEFAULT_RESEND_COOLDOWN = 30;
  public static final int DEFAULT_MAX_ATTEMPTS = 5;

  private static final List<ProviderConfigProperty> CONFIG =
      List.of(
          property(CONFIG_CHANNEL, "Channel", "Id of the native-otp-sender provider: email or sms-webhook", ProviderConfigProperty.STRING_TYPE, DEFAULT_CHANNEL),
          property(CONFIG_DIGITS, "Digits", "Length of the code", ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_DIGITS)),
          property(CONFIG_TTL, "Code lifetime (s)", "Seconds a sent code stays valid", ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_TTL)),
          property(CONFIG_RESEND_COOLDOWN, "Resend cooldown (s)", "Seconds between two sends", ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_RESEND_COOLDOWN)),
          property(CONFIG_MAX_ATTEMPTS, "Max attempts", "Wrong codes before the outstanding code is invalidated", ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_MAX_ATTEMPTS)));

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
    return ChallengeType.OTP;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new NativeOtpAuthenticator(session);
  }

  @Override
  public String getDisplayType() {
    return "Native: one-time code (email / SMS)";
  }

  @Override
  public String getHelpText() {
    return "Sends a one-time code through a native-otp-sender channel and validates the 'otp' challenge of the native authentication profile.";
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG;
  }
}
