package io.phasetwo.keycloak.nativeauth.otp;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

/**
 * Delivers a one-time code out of band (spec/03 §4.6). Implementations: {@code email} (realm SMTP
 * settings) and {@code sms-webhook} (HTTP POST to a configured URL).
 */
public interface NativeOtpSender extends Provider {

  /** The {@code channel} shown in the descriptor, e.g. {@code email}, {@code sms}. */
  String channel();

  /** Whether a code can be delivered to this user (an address / number is known). */
  boolean canSend(RealmModel realm, UserModel user);

  /** The masked destination shown in the descriptor ({@code a***@example.com}); never the full value. */
  String destinationMasked(UserModel user);

  void send(RealmModel realm, UserModel user, String code, int ttlSeconds) throws NativeOtpException;

  @Override
  default void close() {}

  static String maskEmail(String email) {
    if (email == null) return null;
    int at = email.indexOf('@');
    if (at <= 0) return "***";
    return email.charAt(0) + "***" + email.substring(at);
  }

  static String maskPhone(String phone) {
    if (phone == null) return null;
    String digits = phone.replaceAll("[^0-9]", "");
    if (digits.length() < 2) return "***";
    return "***" + digits.substring(digits.length() - 2);
  }
}
