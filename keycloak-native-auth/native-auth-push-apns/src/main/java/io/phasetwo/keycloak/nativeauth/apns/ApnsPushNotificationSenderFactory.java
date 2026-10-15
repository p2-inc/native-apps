package io.phasetwo.keycloak.nativeauth.apns;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.spi.PushNotificationSenderFactory;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers the {@code apns} push provider type. Keycloak SPI options (spec/04 §6):
 *
 * <pre>
 * --spi-push-notification-sender--apns--team-id=ABCDE12345
 * --spi-push-notification-sender--apns--key-id=XYZ9876543
 * --spi-push-notification-sender--apns--key=-----BEGIN PRIVATE KEY-----…     (or --key-file=/path/AuthKey.p8)
 * --spi-push-notification-sender--apns--topic=io.phasetwo.keycloak.nativedemo  (the app's bundle id)
 * --spi-push-notification-sender--apns--environment=sandbox|production          (default sandbox)
 * --spi-push-notification-sender--apns--url=https://…                           (overrides the environment URL; tests)
 * --spi-push-notification-sender--apns--expiration-seconds=240
 * </pre>
 *
 * Environment form: {@code KC_SPI_PUSH_NOTIFICATION_SENDER__APNS__TEAM_ID} etc.
 */
public class ApnsPushNotificationSenderFactory implements PushNotificationSenderFactory {

  private static final Logger log = Logger.getLogger(ApnsPushNotificationSenderFactory.class);

  public static final String ID = "apns";
  public static final String SANDBOX_URL = "https://api.sandbox.push.apple.com";
  public static final String PRODUCTION_URL = "https://api.push.apple.com";

  record Settings(String url, String topic, long expirationSeconds) {}

  private Settings settings;
  private ApnsProviderToken providerToken;
  private HttpClient http;

  @Override
  public PushNotificationSender create(KeycloakSession session) {
    return new ApnsPushNotificationSender(http, settings, providerToken);
  }

  @Override
  public void init(Config.Scope config) {
    String environment = config.get("environment", "sandbox");
    String url = config.get("url", "production".equalsIgnoreCase(environment) ? PRODUCTION_URL : SANDBOX_URL);
    while (url.endsWith("/")) url = url.substring(0, url.length() - 1);
    settings = new Settings(url, config.get("topic", ""), config.getLong("expiration-seconds", 240L));
    String key = config.get("key");
    String keyFile = config.get("key-file");
    if ((key == null || key.isBlank()) && keyFile != null && !keyFile.isBlank()) {
      try {
        key = Files.readString(Path.of(keyFile));
      } catch (IOException e) {
        log.errorf(e, "apns: cannot read key file %s", keyFile);
      }
    }
    String teamId = config.get("team-id");
    String keyId = config.get("key-id");
    if (key != null && !key.isBlank() && teamId != null && !teamId.isBlank() && keyId != null && !keyId.isBlank()) {
      providerToken = new ApnsProviderToken(key, keyId, teamId);
      log.infof("apns: configured for topic %s at %s", settings.topic(), settings.url());
    } else {
      providerToken = null;
      log.infof("apns: installed but not configured (team-id, key-id, key/key-file); notifications will be skipped");
    }
    http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).connectTimeout(Duration.ofSeconds(5)).build();
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
