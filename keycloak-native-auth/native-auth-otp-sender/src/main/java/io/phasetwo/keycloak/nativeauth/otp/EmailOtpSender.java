package io.phasetwo.keycloak.nativeauth.otp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code email}: delivers the code with the realm's SMTP settings through Keycloak's theme-based
 * {@link EmailTemplateProvider} (spec/08 Q10): template {@code native-otp.ftl} (html + text) and the
 * {@code nativeOtp*} message keys shipped under {@code theme-resources/} of this JAR, overridable
 * by the realm's email theme and localised through the user's / request's locale. Falls back to a
 * plain inline message when the template cannot be rendered.
 */
public class EmailOtpSender implements NativeOtpSender {

  private static final Logger log = Logger.getLogger(EmailOtpSender.class);
  static final String TEMPLATE = "native-otp.ftl";
  static final String SUBJECT_KEY = "nativeOtpSubject";

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
    int minutes = Math.max(1, ttlSeconds / 60);
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("code", code);
    attributes.put("ttlMinutes", minutes);
    try {
      session.getProvider(EmailTemplateProvider.class)
          .setRealm(realm)
          .setUser(user)
          .setAuthenticationSession(session.getContext().getAuthenticationSession())
          .send(SUBJECT_KEY, List.of(realmName), TEMPLATE, attributes);
    } catch (EmailException e) {
      if (e.getCause() instanceof java.io.IOException || String.valueOf(e.getMessage()).contains("template")) {
        // A custom email theme without the template: still deliver the code.
        log.warnf(e, "native-otp: template %s could not be rendered; sending a plain message", TEMPLATE);
        sendPlain(realm, user, code, minutes, realmName);
        return;
      }
      throw new NativeOtpException("Sending the email failed", e);
    }
  }

  private void sendPlain(RealmModel realm, UserModel user, String code, int minutes, String realmName) throws NativeOtpException {
    String subject = realmName + ": your verification code";
    String unit = " minute" + (minutes == 1 ? "" : "s") + ".";
    String text = "Your verification code is " + code + ". It expires in " + minutes + unit;
    String html = "<p>Your verification code is <b>" + code + "</b>.</p><p>It expires in " + minutes + unit + "</p>";
    try {
      session.getProvider(EmailSenderProvider.class).send(realm.getSmtpConfig(), user, subject, text, html);
    } catch (EmailException e) {
      throw new NativeOtpException("Sending the email failed", e);
    }
  }
}
