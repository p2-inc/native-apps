package io.phasetwo.keycloak.nativeauth.apns;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code apns}: delivers the confirm token to an iOS device over HTTP/2 with token-based provider
 * authentication (spec/04 §6, spec/14 D10). {@code pushProviderId} is the APNs device token the app
 * registered at enrolment. Delivery failures are logged with Apple's {@code reason}; they never fail
 * the login, because the device can still fetch the pending challenge itself (spec/05 §5).
 */
public class ApnsPushNotificationSender implements PushNotificationSender {

  private static final Logger log = Logger.getLogger(ApnsPushNotificationSender.class);

  private final HttpClient http;
  private final ApnsPushNotificationSenderFactory.Settings settings;
  private final ApnsProviderToken providerToken;

  ApnsPushNotificationSender(HttpClient http, ApnsPushNotificationSenderFactory.Settings settings, ApnsProviderToken providerToken) {
    this.http = http;
    this.settings = settings;
    this.providerToken = providerToken;
  }

  @Override
  public void send(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      String confirmToken,
      String deviceCredentialId,
      String challengeId,
      String pushProviderId,
      String clientId) {
    if (pushProviderId == null || pushProviderId.isBlank()) {
      log.warnf("apns: credential %s has no device token; nothing sent for challenge %s", deviceCredentialId, challengeId);
      return;
    }
    if (providerToken == null) {
      log.warnf("apns: sender is not configured (team-id, key-id and key are required); nothing sent for challenge %s", challengeId);
      return;
    }
    String body = ApnsPayload.build(confirmToken, challengeId, deviceCredentialId, clientId, PushMfaConstants.PUSH_MESSAGE_TYPE, PushMfaConstants.PUSH_MESSAGE_VERSION);
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(settings.url() + "/3/device/" + pushProviderId))
            .timeout(Duration.ofSeconds(10))
            .header("authorization", "bearer " + providerToken.current())
            .header("apns-topic", settings.topic())
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-collapse-id", challengeId)
            .header("apns-expiration", String.valueOf(Instant.now().getEpochSecond() + settings.expirationSeconds()))
            .header("content-type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
    try {
      HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() == 200) {
        log.debugf("apns: delivered challenge %s to credential %s (apns-id %s)", challengeId, deviceCredentialId, response.headers().firstValue("apns-id").orElse("-"));
      } else {
        // Apple answers {"reason":"BadDeviceToken"|"Unregistered"|"ExpiredProviderToken"|...}.
        log.warnf("apns: HTTP %d for challenge %s, credential %s: %s", response.statusCode(), challengeId, deviceCredentialId, response.body());
      }
    } catch (IOException e) {
      log.warnf(e, "apns: delivery of challenge %s failed", challengeId);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @Override
  public void close() {}
}
