package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.otp.EmailOtpSenderFactory;
import io.phasetwo.keycloak.nativeauth.otp.NativeOtpException;
import io.phasetwo.keycloak.nativeauth.otp.NativeOtpSender;
import io.phasetwo.keycloak.nativeauth.otp.OtpCodes;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-verify-email} (spec/03 §4.13): substitutes for Keycloak's {@code VERIFY_EMAIL}. A
 * code goes to the user's e-mail address through the {@code native-otp-sender} {@code email}
 * provider when the challenge is first issued; the client answers with {@code code} or asks for
 * another one with {@code action=resend}. The code lives salted-and-hashed in an auth note with the
 * same rules as {@code native-otp} (ttl, resend cooldown, attempt limit).
 */
public class NativeVerifyEmailRequiredAction extends NativeRequiredActionBase {

  static final String AUTH_NOTE_STATE = "native-auth.verify-email";

  public NativeVerifyEmailRequiredAction(KeycloakSession session) {
    super(session);
  }

  @Override
  protected String providerId() {
    return NativeVerifyEmailRequiredActionFactory.PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.VERIFY_EMAIL;
  }

  private NativeOtpSender sender() {
    return session.getProvider(NativeOtpSender.class, EmailOtpSenderFactory.ID);
  }

  /** Effective configuration (required-action config, else defaults). */
  record Settings(int digits, int ttl, int cooldown, int maxAttempts) {
    static Settings of(RequiredActionConfigModel config) {
      return new Settings(
          value(config, NativeVerifyEmailRequiredActionFactory.CONFIG_DIGITS, NativeVerifyEmailRequiredActionFactory.DEFAULT_DIGITS),
          value(config, NativeVerifyEmailRequiredActionFactory.CONFIG_TTL, NativeVerifyEmailRequiredActionFactory.DEFAULT_TTL),
          value(config, NativeVerifyEmailRequiredActionFactory.CONFIG_RESEND_COOLDOWN, NativeVerifyEmailRequiredActionFactory.DEFAULT_RESEND_COOLDOWN),
          value(config, NativeVerifyEmailRequiredActionFactory.CONFIG_MAX_ATTEMPTS, NativeVerifyEmailRequiredActionFactory.DEFAULT_MAX_ATTEMPTS));
    }

    private static int value(RequiredActionConfigModel config, String key, int fallback) {
      return OtpCodes.intOrDefault(config == null ? null : config.getConfigValue(key), fallback);
    }
  }

  @Override
  protected void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    Settings s = Settings.of(context.getConfig());
    UserModel user = context.getUser();
    NativeOtpSender sender = sender();
    OtpCodes.State state = OtpCodes.load(authSession, AUTH_NOTE_STATE);
    if (state == null && sender != null) {
      // A required action is always the single entry of the set: send at once (spec/03 §4.13).
      state = send(context, sender, s);
    }
    boolean sent = state != null && state.outstanding(s.ttl);
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.VERIFY_EMAIL)
            .setLabel("Verify your email address")
            .setError(error)
            .param("email_masked", sender == null ? NativeOtpSender.maskEmail(user.getEmail()) : sender.destinationMasked(user))
            .param("digits", s.digits)
            .param("ttl", s.ttl)
            .param("sent", sent);
    if (state != null) {
      d.param("resend_allowed_at", state.sentAt + s.cooldown);
    }
    emit(context, d);
  }

  private OtpCodes.State send(RequiredActionContext context, NativeOtpSender sender, Settings s) {
    UserModel user = context.getUser();
    try {
      OtpCodes.State state =
          OtpCodes.send(context.getAuthenticationSession(), AUTH_NOTE_STATE, sender, context.getRealm(), user, s.digits, s.ttl);
      context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail()).success();
      return state;
    } catch (NativeOtpException e) {
      log.warnf(e, "native-verify-email: sending the code to user %s failed", user.getUsername());
      context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL_ERROR).detail(Details.EMAIL, user.getEmail()).error(Errors.EMAIL_SEND_FAILED);
      return null;
    }
  }

  @Override
  public void processAction(RequiredActionContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    Settings s = Settings.of(context.getConfig());
    UserModel user = context.getUser();
    OtpCodes.State state = OtpCodes.load(authSession, AUTH_NOTE_STATE);

    if (Protocol.ACTION_RESEND.equals(param(context, Protocol.ACTION))) {
      long now = Time.currentTime();
      if (state != null && now < state.sentAt + s.cooldown) {
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_RESEND_TOO_SOON, "Wait before requesting another code"));
        return;
      }
      NativeOtpSender sender = sender();
      if (sender == null || send(context, sender, s) == null) {
        authSession.removeAuthNote(AUTH_NOTE_STATE);
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_EXPIRED_CODE, "The code could not be sent; try again later"));
        return;
      }
      challenge(context, null);
      return;
    }

    String code = param(context, Protocol.CODE);
    if (isBlank(code)) {
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "Code is required"));
      return;
    }
    if (state == null || !state.outstanding(s.ttl)) {
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_EXPIRED_CODE, "No valid code outstanding; request a new one"));
      return;
    }
    if (!OtpCodes.matches(state, code)) {
      state.attempts++;
      context.getEvent().clone().event(EventType.VERIFY_EMAIL_ERROR).detail(Details.EMAIL, user.getEmail()).error(Errors.INVALID_CODE);
      if (state.attempts >= s.maxAttempts) {
        state.hash = null; // exhausted: an explicit resend after the cooldown is needed
        OtpCodes.save(authSession, AUTH_NOTE_STATE, state);
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_EXPIRED_CODE, "Too many wrong codes; request a new one"));
      } else {
        OtpCodes.save(authSession, AUTH_NOTE_STATE, state);
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid code"));
      }
      return;
    }
    authSession.removeAuthNote(AUTH_NOTE_STATE);
    user.setEmailVerified(true);
    context.getEvent().clone().event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail()).success();
    context.success();
  }
}
