package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class NativeTermsRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-terms";

  public static final String CONFIG_TEXT = "terms-text";
  public static final String CONFIG_URL = "terms-url";
  public static final String CONFIG_VERSION = "terms-version";

  private static final List<ProviderConfigProperty> CONFIG =
      List.of(
          NativeVerifyEmailRequiredActionFactory.property(CONFIG_TEXT, "Terms text", "Text shown by the app (plain text); realm attribute native-auth.terms-text is the fallback", null),
          NativeVerifyEmailRequiredActionFactory.property(CONFIG_URL, "Terms URL", "Page the app offers to open; realm attribute native-auth.terms-url is the fallback", null),
          NativeVerifyEmailRequiredActionFactory.property(CONFIG_VERSION, "Version", "Informational version label sent to the app", null));

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.TERMS;
  }

  @Override
  public String substitutesFor() {
    return UserModel.RequiredAction.TERMS_AND_CONDITIONS.name();
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativeTermsRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: terms and conditions";
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
