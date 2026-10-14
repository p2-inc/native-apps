package io.phasetwo.keycloak.nativeauth.otp;

import io.phasetwo.keycloak.nativeauth.authenticators.NativeAuthenticatorBase;
import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-otp} (spec/03 §4.6, spec/13 D4). The outstanding code is kept hashed in an auth note
 * keyed by execution id; it is sent unasked only when this challenge is the single option of the
 * set ({@link #prepare}), otherwise on {@code action=resend}. Wrong codes count as brute-force
 * failures; after {@code max-attempts} the code is invalidated.
 */
public class NativeOtpAuthenticator extends NativeAuthenticatorBase {

  static final String NOTE_PREFIX = "native-auth.otp.";

  /** Serialized into the auth note. */
  public static final class State {
    public String hash;
    public String salt;
    public long sentAt;
    public int attempts;

    boolean outstanding(int ttl) {
      return hash != null && Time.currentTime() <= sentAt + ttl;
    }
  }

  private final KeycloakSession session;

  public NativeOtpAuthenticator(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.OTP;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    // The authenticator config is not available here; the realm-wide default channel decides.
    NativeOtpSender sender = session.getProvider(NativeOtpSender.class, NativeOtpAuthenticatorFactory.DEFAULT_CHANNEL);
    return sender != null && sender.canSend(realm, user);
  }

  // ---------------------------------------------------------------------------------------------

  @Override
  public ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    Settings s = settings(context.getRealm().getAuthenticatorConfigById(execution.getAuthenticatorConfig()));
    NativeOtpSender sender = sender(s);
    State state = state(context.getAuthenticationSession(), execution.getId());
    boolean sent = state != null && state.outstanding(s.ttl);
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.OTP)
            .setLabel(sender == null ? "One-time code" : "One-time code by " + sender.channel())
            .param("channel", sender == null ? s.channel : sender.channel())
            .param("digits", s.digits)
            .param("ttl", s.ttl)
            .param("sent", sent);
    UserModel user = context.getUser();
    if (sender != null && user != null) {
      d.param("destination_masked", sender.destinationMasked(user));
    }
    if (state != null) {
      d.param("resend_allowed_at", state.sentAt + s.cooldown);
    }
    return d;
  }

  @Override
  public void prepare(AuthenticationFlowContext context, AuthenticationExecutionModel execution, ChallengeDescriptor descriptor, boolean required) {
    if (!required || context.getUser() == null) {
      return;
    }
    Settings s = settings(context.getRealm().getAuthenticatorConfigById(execution.getAuthenticatorConfig()));
    State state = state(context.getAuthenticationSession(), execution.getId());
    if (state != null) {
      return; // sent before in this session (maybe expired or exhausted): the client resends explicitly
    }
    State fresh = send(context, execution.getId(), s);
    if (fresh != null) {
      descriptor.param("sent", true).param("resend_allowed_at", fresh.sentAt + s.cooldown);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String executionId = context.getExecution().getId();
    Settings s = settings(context.getAuthenticatorConfig());
    AuthenticationSessionModel authSession = context.getAuthenticationSession();

    if (Protocol.ACTION_RESEND.equals(param(context, Protocol.ACTION))) {
      State state = state(authSession, executionId);
      long now = Time.currentTime();
      if (state != null && now < state.sentAt + s.cooldown) {
        rechallenge(context, Protocol.DESC_ERR_RESEND_TOO_SOON, "Wait before requesting another code");
        return;
      }
      if (send(context, executionId, s) == null) {
        rechallenge(context, Protocol.DESC_ERR_EXPIRED_CODE, "The code could not be sent; try again later");
        return;
      }
      challenge(context, buildChallengeSet(context, null), false, null);
      return;
    }

    String otp = param(context, Protocol.OTP);
    if (otp == null || otp.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Code is required");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    State state = state(authSession, executionId);
    if (state == null || !state.outstanding(s.ttl)) {
      rechallenge(context, Protocol.DESC_ERR_EXPIRED_CODE, "No valid code outstanding; request a new one");
      return;
    }
    if (!hash(state.salt, otp).equals(state.hash)) {
      state.attempts++;
      context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
      if (state.attempts >= s.maxAttempts) {
        state.hash = null; // exhausted: resend needed (cooldown still measured from sentAt)
        save(authSession, executionId, state);
        failAndRechallenge(context, Protocol.DESC_ERR_EXPIRED_CODE, "Too many wrong codes; request a new one");
      } else {
        save(authSession, executionId, state);
        failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid code");
      }
      return;
    }
    authSession.removeAuthNote(NOTE_PREFIX + executionId);
    context.getEvent().detail(Details.CREDENTIAL_TYPE, "otp");
    context.success();
  }

  // ---------------------------------------------------------------------------------------------

  /** Generates, stores (hashed) and delivers a code; {@code null} when delivery failed. */
  private State send(AuthenticationFlowContext context, String executionId, Settings s) {
    NativeOtpSender sender = sender(s);
    UserModel user = context.getUser();
    if (sender == null || user == null) {
      log.warnf("native-otp: no sender '%s' installed", s.channel);
      return null;
    }
    String code = SecretGenerator.getInstance().randomString(s.digits, SecretGenerator.DIGITS);
    State state = new State();
    state.salt = SecretGenerator.getInstance().randomString(16);
    state.hash = hash(state.salt, code);
    state.sentAt = Time.currentTime();
    state.attempts = 0;
    try {
      sender.send(context.getRealm(), user, code, s.ttl);
    } catch (NativeOtpException e) {
      log.warnf(e, "native-otp: sending the code to user %s failed", user.getUsername());
      context.getEvent().detail("otp_channel", sender.channel()).error(Errors.EMAIL_SEND_FAILED);
      return null;
    }
    save(context.getAuthenticationSession(), executionId, state);
    context.getEvent().detail("otp_channel", sender.channel());
    log.debugf("native-otp: sent a code to user %s via %s", user.getUsername(), sender.channel());
    return state;
  }

  private NativeOtpSender sender(Settings s) {
    return session.getProvider(NativeOtpSender.class, s.channel);
  }

  static State state(AuthenticationSessionModel authSession, String executionId) {
    String note = authSession.getAuthNote(NOTE_PREFIX + executionId);
    if (note == null) return null;
    try {
      return NativeAuthJson.read(note, State.class);
    } catch (IOException e) {
      return null;
    }
  }

  private static void save(AuthenticationSessionModel authSession, String executionId, State state) {
    authSession.setAuthNote(NOTE_PREFIX + executionId, NativeAuthJson.write(state));
  }

  static String hash(String salt, String code) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest((salt + ":" + code).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Effective configuration of one execution. */
  record Settings(String channel, int digits, int ttl, int cooldown, int maxAttempts) {}

  static Settings settings(AuthenticatorConfigModel config) {
    Map<String, String> c = config == null || config.getConfig() == null ? Map.of() : config.getConfig();
    return new Settings(
        orDefault(c.get(NativeOtpAuthenticatorFactory.CONFIG_CHANNEL), NativeOtpAuthenticatorFactory.DEFAULT_CHANNEL),
        intOrDefault(c.get(NativeOtpAuthenticatorFactory.CONFIG_DIGITS), NativeOtpAuthenticatorFactory.DEFAULT_DIGITS),
        intOrDefault(c.get(NativeOtpAuthenticatorFactory.CONFIG_TTL), NativeOtpAuthenticatorFactory.DEFAULT_TTL),
        intOrDefault(c.get(NativeOtpAuthenticatorFactory.CONFIG_RESEND_COOLDOWN), NativeOtpAuthenticatorFactory.DEFAULT_RESEND_COOLDOWN),
        intOrDefault(c.get(NativeOtpAuthenticatorFactory.CONFIG_MAX_ATTEMPTS), NativeOtpAuthenticatorFactory.DEFAULT_MAX_ATTEMPTS));
  }

  private static String orDefault(String value, String fallback) {
    return value == null || value.isBlank() ? fallback : value.trim();
  }

  private static int intOrDefault(String value, int fallback) {
    try {
      return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
