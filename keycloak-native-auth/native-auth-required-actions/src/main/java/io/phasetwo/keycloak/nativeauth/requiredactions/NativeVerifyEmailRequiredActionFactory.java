package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import io.phasetwo.keycloak.nativeauth.otp.EmailOtpSenderFactory;
import io.phasetwo.keycloak.nativeauth.otp.NativeOtpSender;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class NativeVerifyEmailRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-verify-email";

  public static final String CONFIG_DIGITS = "digits";
  public static final String CONFIG_TTL = "ttl";
  public static final String CONFIG_RESEND_COOLDOWN = "resend-cooldown";
  public static final String CONFIG_MAX_ATTEMPTS = "max-attempts";
  public static final int DEFAULT_DIGITS = 6;
  public static final int DEFAULT_TTL = 300;
  public static final int DEFAULT_RESEND_COOLDOWN = 30;
  public static final int DEFAULT_MAX_ATTEMPTS = 5;

  private static final List<ProviderConfigProperty> CONFIG =
      List.of(
          property(CONFIG_DIGITS, "Digits", "Length of the code", String.valueOf(DEFAULT_DIGITS)),
          property(CONFIG_TTL, "Code lifetime (s)", "Seconds a sent code stays valid", String.valueOf(DEFAULT_TTL)),
          property(CONFIG_RESEND_COOLDOWN, "Resend cooldown (s)", "Seconds between two sends", String.valueOf(DEFAULT_RESEND_COOLDOWN)),
          property(CONFIG_MAX_ATTEMPTS, "Max attempts", "Wrong codes before the outstanding code is invalidated", String.valueOf(DEFAULT_MAX_ATTEMPTS)));

  static ProviderConfigProperty property(String name, String label, String help, String defaultValue) {
    ProviderConfigProperty p = new ProviderConfigProperty();
    p.setName(name);
    p.setLabel(label);
    p.setHelpText(help);
    p.setType(ProviderConfigProperty.STRING_TYPE);
    p.setDefaultValue(defaultValue);
    return p;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.VERIFY_EMAIL;
  }

  @Override
  public String substitutesFor() {
    return UserModel.RequiredAction.VERIFY_EMAIL.name();
  }

  @Override
  public boolean canServe(KeycloakSession session, RealmModel realm, UserModel user) {
    NativeOtpSender sender = session.getProvider(NativeOtpSender.class, EmailOtpSenderFactory.ID);
    return sender != null && sender.canSend(realm, user);
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativeVerifyEmailRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: verify email (code)";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return CONFIG;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
