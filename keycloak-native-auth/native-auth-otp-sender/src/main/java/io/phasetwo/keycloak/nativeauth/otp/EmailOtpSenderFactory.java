package io.phasetwo.keycloak.nativeauth.otp;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** {@code email}: sends the code with the realm's SMTP settings through Keycloak's {@code EmailSenderProvider}. */
public class EmailOtpSenderFactory implements NativeOtpSenderFactory {

  public static final String ID = "email";

  @Override
  public NativeOtpSender create(KeycloakSession session) {
    return new EmailOtpSender(session);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }
}
