package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class NativePasskeyRegisterRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-passkey-register";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSKEY_REGISTRATION;
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativePasskeyRegisterRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: register passkey";
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
