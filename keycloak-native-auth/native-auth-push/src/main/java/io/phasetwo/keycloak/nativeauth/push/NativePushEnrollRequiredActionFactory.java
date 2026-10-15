package io.phasetwo.keycloak.nativeauth.push;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class NativePushEnrollRequiredActionFactory implements NativeRequiredActionFactory {

  public static final String PROVIDER_ID = "native-push-enroll";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PUSH_ENROLLMENT;
  }

  @Override
  public String substitutesFor() {
    return PushMfaConstants.REQUIRED_ACTION_ID;
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new NativePushEnrollRequiredAction(session);
  }

  @Override
  public String getDisplayText() {
    return "Native: enrol push MFA device";
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
