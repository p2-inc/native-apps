package io.phasetwo.keycloak.nativeauth.registration;

import io.phasetwo.keycloak.nativeauth.authenticators.NativeAuthenticatorBase;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.otp.EmailOtpSenderFactory;
import io.phasetwo.keycloak.nativeauth.otp.NativeOtpException;
import io.phasetwo.keycloak.nativeauth.otp.NativeOtpSender;
import io.phasetwo.keycloak.nativeauth.otp.OtpCodes;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-reset-credentials} (spec/22 phase 3): "Forgot password" as a native flow, with the
 * challenge types every SDK already renders. First a {@code username} challenge (username or email);
 * then an {@code otp} challenge for the code emailed to the account; then Keycloak's Update Password
 * required action, served natively as {@code update_password}; then the user is signed in, as after
 * Keycloak's own reset.
 *
 * <p>Nothing tells whether the account exists: an unknown, disabled or email-less account gets the
 * same {@code otp} challenge and the same timing, and no code ever matches. The destination is shown
 * only when the user typed an email address, masked from what they typed.
 */
public class NativeResetCredentialsAuthenticator extends NativeAuthenticatorBase {

  static final String NOTE_USER = "native-reset.user";
  static final String NOTE_TYPED = "native-reset.typed";
  static final String NOTE_CODE = "native-reset.code";
  static final String PHANTOM = "-";

  static final int DIGITS = 6;
  static final int TTL = 600;
  static final int COOLDOWN = 30;
  static final int MAX_ATTEMPTS = 5;

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.OTP;
  }

  @Override
  public ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    if (authSession.getAuthNote(NOTE_USER) == null) {
      return new ChallengeDescriptor(ChallengeType.USERNAME)
          .setLabel("Username or email")
          .param("allow_email", true);
    }
    OtpCodes.State state = OtpCodes.load(authSession, NOTE_CODE);
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.OTP)
            .setLabel("Code from your email")
            .param("channel", "email")
            .param("digits", DIGITS)
            .param("ttl", TTL)
            .param("sent", state != null && state.hash != null);
    String typed = authSession.getAuthNote(NOTE_TYPED);
    if (typed != null && typed.contains("@")) d.param("destination_masked", mask(typed));
    if (state != null) d.param("resend_allowed_at", state.sentAt + COOLDOWN);
    return d;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    if (authSession.getAuthNote(NOTE_USER) == null) {
      identify(context);
      return;
    }
    if (Protocol.ACTION_RESEND.equals(param(context, Protocol.ACTION))) {
      OtpCodes.State state = OtpCodes.load(authSession, NOTE_CODE);
      if (state != null && Time.currentTime() < state.sentAt + COOLDOWN) {
        rechallenge(context, Protocol.DESC_ERR_RESEND_TOO_SOON, "Wait before requesting another code");
        return;
      }
      send(context);
      challenge(context, buildChallengeSet(context, null), false, null);
      return;
    }
    verify(context);
  }

  private void identify(AuthenticationFlowContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String typed = param(context, Protocol.USERNAME);
    if (typed == null || typed.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Enter your username or email");
      return;
    }
    UserModel user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), typed);
    boolean usable = user != null && user.isEnabled() && user.getEmail() != null && !user.getEmail().isBlank();
    authSession.setAuthNote(NOTE_TYPED, typed);
    authSession.setAuthNote(NOTE_USER, usable ? user.getId() : PHANTOM);
    context.getEvent().detail(Details.USERNAME, typed);
    send(context);
    challenge(context, buildChallengeSet(context, null), false, null);
  }

  /** Sends a code to a real account; for a phantom only the timing and the state change. */
  private void send(AuthenticationFlowContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String userId = authSession.getAuthNote(NOTE_USER);
    UserModel user = PHANTOM.equals(userId) ? null : context.getSession().users().getUserById(context.getRealm(), userId);
    NativeOtpSender sender = context.getSession().getProvider(NativeOtpSender.class, EmailOtpSenderFactory.ID);
    if (user != null && sender != null) {
      try {
        OtpCodes.send(authSession, NOTE_CODE, sender, context.getRealm(), user, DIGITS, TTL);
        context.getEvent().user(user).detail("otp_channel", "email");
        return;
      } catch (NativeOtpException e) {
        log.warnf(e, "native-reset-credentials: sending the code to user %s failed", user.getUsername());
        context.getEvent().user(user).error(Errors.EMAIL_SEND_FAILED);
      }
    }
    // Unknown account (or a failed send): a state no code matches.
    OtpCodes.State state = new OtpCodes.State();
    state.salt = "phantom";
    state.hash = "phantom";
    state.sentAt = Time.currentTime();
    OtpCodes.save(authSession, NOTE_CODE, state);
  }

  private void verify(AuthenticationFlowContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String code = param(context, Protocol.OTP);
    if (code == null || code.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Code is required");
      return;
    }
    OtpCodes.State state = OtpCodes.load(authSession, NOTE_CODE);
    if (state == null || state.hash == null || !state.outstanding(TTL)) {
      rechallenge(context, Protocol.DESC_ERR_EXPIRED_CODE, "No valid code outstanding; request a new one");
      return;
    }
    String userId = authSession.getAuthNote(NOTE_USER);
    UserModel user = PHANTOM.equals(userId) ? null : context.getSession().users().getUserById(context.getRealm(), userId);
    if (user == null || !OtpCodes.matches(state, code)) {
      state.attempts++;
      if (user != null) context.getEvent().user(user);
      context.getEvent().error(Errors.INVALID_CODE);
      if (state.attempts >= MAX_ATTEMPTS) {
        state.hash = null;
        OtpCodes.save(authSession, NOTE_CODE, state);
        rechallenge(context, Protocol.DESC_ERR_EXPIRED_CODE, "Too many wrong codes; request a new one");
      } else {
        OtpCodes.save(authSession, NOTE_CODE, state);
        rechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid code");
      }
      return;
    }
    if (!user.isEnabled()) {
      context.getEvent().user(user).error(Errors.USER_DISABLED);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return;
    }
    authSession.removeAuthNote(NOTE_CODE);
    // The code reached the mailbox: like Keycloak's reset email link, that verifies the address.
    user.setEmailVerified(true);
    context.setUser(user);
    authSession.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    context.getEvent().user(user).detail(Details.CREDENTIAL_TYPE, "password").detail(Details.REASON, "native reset credentials");
    context.success();
  }

  /** {@code a***@example.com}. */
  static String mask(String email) {
    int at = email.indexOf('@');
    if (at <= 0) return "***";
    return email.charAt(0) + "***" + email.substring(at);
  }
}
