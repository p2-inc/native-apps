package io.phasetwo.keycloak.nativeauth.otp;

import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * One-time codes kept salted-and-hashed in an auth note, shared by {@code native-otp} (spec/03
 * §4.6) and {@code native-verify-email} (§4.13): generate, deliver through a {@link
 * NativeOtpSender}, store, verify, count attempts.
 */
public final class OtpCodes {

  private OtpCodes() {}

  /** Serialized into the auth note. */
  public static final class State {
    public String hash;
    public String salt;
    public long sentAt;
    public int attempts;

    public boolean outstanding(int ttl) {
      return hash != null && Time.currentTime() <= sentAt + ttl;
    }
  }

  public static State load(AuthenticationSessionModel authSession, String note) {
    String value = authSession.getAuthNote(note);
    if (value == null) return null;
    try {
      return NativeAuthJson.read(value, State.class);
    } catch (IOException e) {
      return null;
    }
  }

  public static void save(AuthenticationSessionModel authSession, String note, State state) {
    authSession.setAuthNote(note, NativeAuthJson.write(state));
  }

  /** Generates a code, delivers it and returns the stored state; throws when delivery failed. */
  public static State send(
      AuthenticationSessionModel authSession,
      String note,
      NativeOtpSender sender,
      RealmModel realm,
      UserModel user,
      int digits,
      int ttl)
      throws NativeOtpException {
    String code = SecretGenerator.getInstance().randomString(digits, SecretGenerator.DIGITS);
    State state = new State();
    state.salt = SecretGenerator.getInstance().randomString(16);
    state.hash = hash(state.salt, code);
    state.sentAt = Time.currentTime();
    state.attempts = 0;
    sender.send(realm, user, code, ttl);
    save(authSession, note, state);
    return state;
  }

  public static boolean matches(State state, String code) {
    return state != null && state.hash != null && hash(state.salt, code).equals(state.hash);
  }

  public static String hash(String salt, String code) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest((salt + ":" + code).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public static int intOrDefault(String value, int fallback) {
    try {
      return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
