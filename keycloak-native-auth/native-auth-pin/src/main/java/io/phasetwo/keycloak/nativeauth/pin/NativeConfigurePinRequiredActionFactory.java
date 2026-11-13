package io.phasetwo.keycloak.nativeauth.pin;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import io.phasetwo.keycloak.pin.PinConstants;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers {@code native-configure-pin} ("Native: configure PIN"), which substitutes for
 * keycloak-pin's {@code phasetwo-configure-pin} in native logins (spec/03 §4.11). Its settings
 * ({@code length}, {@code reject-weak}) are read from {@code phasetwo-configure-pin}'s realm
 * config, so there is one place to configure PINs.
 */
public class NativeConfigurePinRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-configure-pin";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PIN_SETUP;
  }

  @Override
  public String substitutesFor() {
    return PinConstants.REQUIRED_ACTION_ID;
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativeConfigurePinRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: configure PIN";
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
