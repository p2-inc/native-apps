package io.phasetwo.keycloak.nativeauth.otp;

import java.util.Map;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class EmailOtpSender implements NativeOtpSender {

  private final KeycloakSession session;

  public EmailOtpSender(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public String channel() {
    return "email";
  }

  @Override
  public boolean canSend(RealmModel realm, UserModel user) {
    Map<String, String> smtp = realm.getSmtpConfig();
    String host = smtp == null ? null : smtp.get("host");
    return host != null && !host.isBlank() && user.getEmail() != null && !user.getEmail().isBlank();
  }

  @Override
  public String destinationMasked(UserModel user) {
    return NativeOtpSender.maskEmail(user.getEmail());
  }

  @Override
  public void send(RealmModel realm, UserModel user, String code, int ttlSeconds) throws NativeOtpException {
    String realmName = realm.getDisplayName() == null || realm.getDisplayName().isBlank() ? realm.getName() : realm.getDisplayName();
    String subject = realmName + ": your verification code";
    int minutes = Math.max(1, ttlSeconds / 60);
    String text = "Your verification code is " + code + ". It expires in " + minutes + " minute" + (minutes == 1 ? "" : "s") + ".";
    String html = "<p>Your verification code is <b>" + code + "</b>.</p><p>It expires in " + minutes + " minute" + (minutes == 1 ? "" : "s") + ".</p>";
    try {
      session.getProvider(EmailSenderProvider.class).send(realm.getSmtpConfig(), user, subject, text, html);
    } catch (EmailException e) {
      throw new NativeOtpException("Sending the email failed", e);
    }
  }
}
