package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

public class NativeUpdatePasswordRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-update-password";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.UPDATE_PASSWORD;
  }

  @Override
  public String substitutesFor() {
    return UserModel.RequiredAction.UPDATE_PASSWORD.name();
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativeUpdatePasswordRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: update password";
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
