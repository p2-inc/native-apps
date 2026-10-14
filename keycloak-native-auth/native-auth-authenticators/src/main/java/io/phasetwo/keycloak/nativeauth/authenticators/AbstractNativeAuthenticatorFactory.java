package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Shared factory boilerplate for the native authenticators. */
public abstract class AbstractNativeAuthenticatorFactory implements NativeAuthenticatorFactory {

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    // Enrolment inside the native flow needs native required actions (spec/04 §4); Phase 1+.
    return false;
  }

  @Override
  public boolean isConfigurable() {
    return !getConfigProperties().isEmpty();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
