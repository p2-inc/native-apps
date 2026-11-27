package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

/**
 * {@code native-update-password} (spec/03 §4.12): the JSON variant of Keycloak's {@code
 * UPDATE_PASSWORD}, for which it substitutes (spec/03 §4.11). The password is stored through the
 * user's credential manager exactly as {@code UpdatePassword} does, so the realm's password policy
 * (and its history / expiry rules) applies; a policy violation is reported as {@code
 * invalid_password} with the policy's message rendered from the login theme in the request's locale.
 */
public class NativeUpdatePasswordRequiredAction extends NativeRequiredActionBase {

  /** Policy entries that describe hashing or lifetimes, not what a new password must look like. */
  private static final Set<String> HIDDEN_POLICIES =
      Set.of(
          PasswordPolicy.HASH_ALGORITHM_ID,
          PasswordPolicy.HASH_ITERATIONS_ID,
          PasswordPolicy.FORCE_EXPIRED_ID,
          PasswordPolicy.PASSWORD_AGE,
          PasswordPolicy.RECOVERY_CODES_WARNING_THRESHOLD_ID,
          PasswordPolicy.MAX_AUTH_AGE_ID,
          "passwordBlacklist");

  public NativeUpdatePasswordRequiredAction(KeycloakSession session) {
    super(session);
  }

  @Override
  protected String providerId() {
    return NativeUpdatePasswordRequiredActionFactory.PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.UPDATE_PASSWORD;
  }

  /** The application may start a password change with {@code kc_action=UPDATE_PASSWORD} (spec/21). */
  @Override
  public InitiatedActionSupport initiatedActionSupport() {
    return InitiatedActionSupport.SUPPORTED;
  }

  @Override
  protected void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.UPDATE_PASSWORD)
            .setLabel("Choose a new password")
            .setError(error)
            .param("username", context.getUser().getUsername())
            .param("policy", policyHints(context.getRealm()))
            // Offered like the browser page's "Sign out from other devices" checkbox, checked by default (spec/21).
            .param(Protocol.LOGOUT_OTHER_SESSIONS, Boolean.TRUE);
    emit(context, d);
  }

  /** The realm's password policy by Keycloak id, minus hashing/lifetime entries (spec/03 §4.12). */
  public static Map<String, Object> policyHints(RealmModel realm) {
    Map<String, Object> hints = new LinkedHashMap<>();
    PasswordPolicy policy = realm.getPasswordPolicy();
    if (policy == null) return hints;
    for (String id : policy.getPolicies()) {
      if (HIDDEN_POLICIES.contains(id)) continue;
      Object config = policy.getPolicyConfig(id);
      hints.put(id, config == null ? Boolean.TRUE : config);
    }
    return hints;
  }

  @Override
  public void processAction(RequiredActionContext context) {
    UserModel user = context.getUser();
    EventBuilder event =
        context.getEvent().clone().event(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.PASSWORD);
    String password = form(context).getFirst(Protocol.PASSWORD);
    String confirm = form(context).getFirst(Protocol.PASSWORD_CONFIRM);
    if (isBlank(password)) {
      event.error(Errors.PASSWORD_MISSING);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "A new password is required"));
      return;
    }
    if (!password.equals(confirm)) {
      event.error(Errors.PASSWORD_CONFIRM_ERROR);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_PASSWORD_MISMATCH, "Passwords do not match"));
      return;
    }
    try {
      // 26.8.1 has no updateCredentialAndGet (that is nightly); the boolean variant suffices.
      user.credentialManager().updateCredential(UserCredentialModel.password(password, false));
      event.success();
      if (Boolean.parseBoolean(form(context).getFirst(Protocol.LOGOUT_OTHER_SESSIONS))) {
        logoutOtherSessions(context);
      }
      context.success();
    } catch (ModelException e) {
      // The realm's password policy rejected the value: message key + parameters (PasswordPolicyManagerProvider).
      String message = localise(context, e.getMessage(), e.getParameters());
      event.detail(Details.REASON, e.getMessage()).error(Errors.PASSWORD_REJECTED);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_PASSWORD, message));
    }
  }

  /**
   * {@code AuthenticatorUtil.logoutOtherSessions} for a native login (spec/21). Keycloak's helper keeps
   * only the user session whose id equals the root authentication session's, which holds for a fresh
   * login but not for a step-up: that continues an existing user session from a new root
   * authentication session, so the helper would also end the session the app is signed in with.
   */
  private void logoutOtherSessions(RequiredActionContext context) {
    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    Set<String> keep = new HashSet<>();
    keep.add(authSession.getParentSession().getId());
    String stepUpSession = authSession.getClientNote(NativeRequestContext.CLIENT_NOTE_STEP_UP_USER_SESSION);
    if (stepUpSession != null) keep.add(stepUpSession);
    EventBuilder event = context.getEvent().clone().detail(Details.LOGOUT_TRIGGERED_BY_REQUIRED_ACTION, context.getAction());
    Consumer<UserSessionModel> logout =
        s -> {
          AuthenticationManager.backchannelLogout(
              session, realm, s, session.getContext().getUri(), context.getConnection(), context.getHttpRequest().getHttpHeaders(), true);
          event.clone().event(EventType.LOGOUT).session(s).user(user).success();
        };
    session.sessions().getUserSessionsStream(realm, user)
        .filter(s -> !keep.contains(s.getId()))
        .toList() // backchannelLogout removes sessions; avoid modifying the stream's source
        .forEach(logout);
    if (!Profile.isFeatureEnabled(Profile.Feature.LOGOUT_ALL_SESSIONS_V1)) {
      session.sessions().getOfflineUserSessionsStream(realm, user)
          .filter(s -> !keep.contains(s.getId()))
          .toList()
          .forEach(logout);
    }
  }

  /** Renders a login-theme message key in the request's locale, as the FreeMarker pages do. */
  private String localise(RequiredActionContext context, String key, Object[] parameters) {
    if (key == null) return "Password rejected by the realm's password policy";
    try {
      Locale locale = session.getContext().resolveLocale(context.getUser());
      Properties messages = session.theme().getTheme(Theme.Type.LOGIN).getEnhancedMessages(context.getRealm(), locale);
      String pattern = messages.getProperty(key, key);
      return new MessageFormat(pattern.replace("'", "''"), locale).format(parameters == null ? new Object[0] : parameters);
    } catch (IOException | RuntimeException e) {
      log.debugf(e, "Cannot render password policy message %s", key);
      return key;
    }
  }
}
