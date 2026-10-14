package io.phasetwo.keycloak.nativeauth.otp;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * {@code sms-webhook}: POSTs {@code {"to": "<number>", "message": "<text>"}} to a webhook that hands
 * the text to an SMS gateway. Configured with Keycloak SPI options:
 *
 * <pre>
 * --spi-native-otp-sender--sms-webhook--url=https://sms.example.com/send
 * --spi-native-otp-sender--sms-webhook--token=…            (optional bearer token)
 * --spi-native-otp-sender--sms-webhook--phone-attribute=phoneNumber   (user attribute, default phoneNumber)
 * </pre>
 */
public class SmsWebhookOtpSenderFactory implements NativeOtpSenderFactory {

  public static final String ID = "sms-webhook";
  public static final String DEFAULT_PHONE_ATTRIBUTE = "phoneNumber";

  private String url;
  private String token;
  private String phoneAttribute = DEFAULT_PHONE_ATTRIBUTE;

  @Override
  public NativeOtpSender create(KeycloakSession session) {
    return new SmsWebhookOtpSender(url, token, phoneAttribute);
  }

  @Override
  public void init(Config.Scope config) {
    url = config.get("url");
    token = config.get("token");
    phoneAttribute = config.get("phone-attribute", DEFAULT_PHONE_ATTRIBUTE);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }
}
