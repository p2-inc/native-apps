package io.phasetwo.keycloak.nativeauth.otp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

public class SmsWebhookOtpSender implements NativeOtpSender {

  private static final Logger log = Logger.getLogger(SmsWebhookOtpSender.class);
  private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

  private final String url;
  private final String token;
  private final String phoneAttribute;

  public SmsWebhookOtpSender(String url, String token, String phoneAttribute) {
    this.url = url;
    this.token = token;
    this.phoneAttribute = phoneAttribute;
  }

  @Override
  public String channel() {
    return "sms";
  }

  private String phone(UserModel user) {
    String value = user.getFirstAttribute(phoneAttribute);
    return value == null || value.isBlank() ? null : value.trim();
  }

  @Override
  public boolean canSend(RealmModel realm, UserModel user) {
    return url != null && !url.isBlank() && phone(user) != null;
  }

  @Override
  public String destinationMasked(UserModel user) {
    return NativeOtpSender.maskPhone(phone(user));
  }

  @Override
  public void send(RealmModel realm, UserModel user, String code, int ttlSeconds) throws NativeOtpException {
    String to = phone(user);
    if (to == null) throw new NativeOtpException("User has no phone number");
    String body;
    try {
      body = JsonSerialization.writeValueAsString(
          java.util.Map.of("to", to, "message", "Your verification code is " + code + ". It expires in " + Math.max(1, ttlSeconds / 60) + " min."));
    } catch (IOException e) {
      throw new NativeOtpException("Cannot build webhook body", e);
    }
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
    if (token != null && !token.isBlank()) {
      request.header("Authorization", "Bearer " + token);
    }
    try {
      HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() < 200 || response.statusCode() >= 300) {
        log.warnf("SMS webhook answered HTTP %d", response.statusCode());
        throw new NativeOtpException("SMS webhook answered HTTP " + response.statusCode());
      }
    } catch (IOException e) {
      throw new NativeOtpException("SMS webhook unreachable", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NativeOtpException("Interrupted", e);
    }
  }
}
