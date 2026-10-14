package io.phasetwo.keycloak.nativeauth.otp;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/** SPI {@code native-otp-sender}: delivery channels for the {@code otp} challenge (spec/03 §4.6, spec/13 D4). */
public class NativeOtpSenderSpi implements Spi {

  public static final String NAME = "native-otp-sender";

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
    return NativeOtpSender.class;
  }

  @Override
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return NativeOtpSenderFactory.class;
  }
}
