package io.phasetwo.keycloak.nativeauth.core.push;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/** SPI {@code native-auth-push-enrolment}: the optional push-MFA bridge (spec/14 D9). */
public class NativePushEnrolmentSpi implements Spi {

  public static final String NAME = "native-auth-push-enrolment";

  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return NativePushEnrolmentProvider.class;
  }

  @Override
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return NativePushEnrolmentProviderFactory.class;
  }
}
