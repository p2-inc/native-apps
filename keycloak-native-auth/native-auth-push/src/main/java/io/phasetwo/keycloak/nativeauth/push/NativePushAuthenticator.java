package io.phasetwo.keycloak.nativeauth.push;

import de.arbeitsagentur.keycloak.push.auth.ChallengeIssuer;
import de.arbeitsagentur.keycloak.push.auth.ChallengeNoteHelper;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import io.phasetwo.keycloak.nativeauth.authenticators.NativeAuthenticatorBase;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-push} (spec/03 §4.7, spec/14 D9): scenario B of spec/02 §3 — a push challenge
 * inside a native login. The challenge is issued through ba-itsys' {@code ChallengeIssuer} (same
 * store, same confirm token, same push provider), so the approving device uses the §7 API
 * unchanged; the native client polls with {@code action=poll}. Like {@code native-otp}, the
 * challenge is only created when this is the single option or the client asks with {@code
 * action=resend}.
 */
public class NativePushAuthenticator extends NativeAuthenticatorBase {

  static final String AUTH_NOTE_SENT_AT = "native-auth.push.sent-at";
  static final int RESEND_COOLDOWN_SECONDS = 10;

  private final KeycloakSession session;

  public NativePushAuthenticator(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PUSH;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return !PushCredentialService.getActiveCredentials(user).isEmpty();
  }

  @Override
  public ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    ChallengeDescriptor d = new ChallengeDescriptor(ChallengeType.PUSH).setLabel("Approve on your phone");
    UserModel user = context.getUser();
    if (user == null) return d.param("sent", false);
    List<Map<String, String>> devices = new ArrayList<>();
    for (CredentialModel c : PushCredentialService.getActiveCredentials(user)) {
      Map<String, String> entry = new LinkedHashMap<>();
      entry.put("label", c.getUserLabel() == null ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME : c.getUserLabel());
      devices.add(entry);
    }
    d.param("devices", devices);
    Settings s = settings(context.getRealm().getAuthenticatorConfigById(execution.getAuthenticatorConfig()));
    d.param("poll_interval", s.pollInterval);
    Optional<PushChallenge> pending = pendingChallenge(context.getAuthenticationSession());
    if (pending.isPresent()) {
      PushChallenge ch = pending.get();
      d.param("sent", true)
          .param("cid", ch.getId())
          .param("expires_at", ch.getExpiresAt().getEpochSecond())
          .param("status", ch.getStatus().name().toLowerCase());
      if (ch.getUserVerificationMode() == PushChallenge.UserVerificationMode.NUMBER_MATCH && ch.getUserVerificationValue() != null) {
        Map<String, String> uv = new LinkedHashMap<>();
        uv.put("type", "number_match");
        uv.put("number", ch.getUserVerificationValue());
        d.param("user_verification", uv);
      } else if (ch.getUserVerificationMode() == PushChallenge.UserVerificationMode.PIN && ch.getUserVerificationValue() != null) {
        Map<String, String> uv = new LinkedHashMap<>();
        uv.put("type", "pin");
        uv.put("pin", ch.getUserVerificationValue());
        d.param("user_verification", uv);
      }
    } else {
      d.param("sent", false);
    }
    String sentAt = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_SENT_AT);
    if (sentAt != null) {
      d.param("resend_allowed_at", Long.parseLong(sentAt) + RESEND_COOLDOWN_SECONDS);
    }
    return d;
  }

  @Override
  public void prepare(AuthenticationFlowContext context, AuthenticationExecutionModel execution, ChallengeDescriptor descriptor, boolean required) {
    if (!required || context.getUser() == null || pendingChallenge(context.getAuthenticationSession()).isPresent()) {
      return;
    }
    if (context.getAuthenticationSession().getAuthNote(AUTH_NOTE_SENT_AT) != null) {
      return; // a challenge was issued earlier in this session and ended: the client resends explicitly
    }
    PushChallenge issued = issue(context);
    if (issued != null) {
      descriptor.getParams().putAll(describe(context, execution).getParams());
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String action = param(context, Protocol.ACTION);
    if (!checkUserEnabled(context, user)) {
      return;
    }
    if (Protocol.ACTION_RESEND.equals(action)) {
      String sentAt = authSession.getAuthNote(AUTH_NOTE_SENT_AT);
      if (sentAt != null && Time.currentTime() < Long.parseLong(sentAt) + RESEND_COOLDOWN_SECONDS) {
        rechallenge(context, Protocol.DESC_ERR_RESEND_TOO_SOON, "Wait before requesting another push");
        return;
      }
      pendingChallenge(authSession).ifPresent(ch -> new PushChallengeStore(session).remove(ch.getId()));
      ChallengeNoteHelper.clear(authSession);
      if (issue(context) == null) {
        rechallenge(context, Protocol.DESC_ERR_EXPIRED, "No push device could be notified");
        return;
      }
      challenge(context, buildChallengeSet(context, null), false, null);
      return;
    }
    if (!Protocol.ACTION_POLL.equals(action)) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "action=poll or action=resend is required");
      return;
    }
    String challengeId = ChallengeNoteHelper.readChallengeId(authSession);
    PushChallengeStore store = new PushChallengeStore(session);
    Optional<PushChallenge> current = challengeId == null ? Optional.empty() : store.get(challengeId);
    if (current.isEmpty()) {
      ChallengeNoteHelper.clear(authSession);
      rechallenge(context, Protocol.DESC_ERR_EXPIRED, "No push challenge is pending; request a new one");
      return;
    }
    PushChallenge ch = current.get();
    if (!user.getId().equals(ch.getUserId()) || ch.getType() != PushChallenge.Type.AUTHENTICATION) {
      ChallengeNoteHelper.clear(authSession);
      rechallenge(context, Protocol.DESC_ERR_EXPIRED, "No push challenge is pending; request a new one");
      return;
    }
    switch (ch.getStatus()) {
      case PENDING -> challenge(context, buildChallengeSet(context, null), false, null);
      case APPROVED -> {
        store.remove(ch.getId());
        ChallengeNoteHelper.clear(authSession);
        context.getEvent().detail(Details.CREDENTIAL_TYPE, PushMfaConstants.CREDENTIAL_TYPE);
        context.success(PushMfaConstants.CREDENTIAL_TYPE);
      }
      case DENIED, USER_LOCKED_OUT -> {
        store.remove(ch.getId());
        ChallengeNoteHelper.clear(authSession);
        context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
        failAndRechallenge(context, Protocol.DESC_ERR_DENIED, "The sign-in was denied on the device");
      }
      case EXPIRED -> {
        store.remove(ch.getId());
        ChallengeNoteHelper.clear(authSession);
        rechallenge(context, Protocol.DESC_ERR_EXPIRED, "The push challenge expired; request a new one");
      }
    }
  }

  // ---------------------------------------------------------------------------------------------

  /** Issues a challenge through ba-itsys (store, confirm token, push provider); {@code null} without a device. */
  private PushChallenge issue(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
    if (credentials.isEmpty()) {
      log.debugf("native-push: user %s has no push credential", user.getUsername());
      return null;
    }
    CredentialModel credential = credentials.get(0);
    PushCredentialData data = PushCredentialService.readCredentialData(credential);
    if (data == null || data.getDeviceCredentialId() == null) {
      return null;
    }
    Settings s = settings(context.getAuthenticatorConfig());
    String clientId = context.getAuthenticationSession().getClient() == null ? null : context.getAuthenticationSession().getClient().getClientId();
    String rootSessionId = context.getAuthenticationSession().getParentSession() == null ? null : context.getAuthenticationSession().getParentSession().getId();
    ChallengeIssuer.IssuedChallenge issued =
        ChallengeIssuer.issue(context, new PushChallengeStore(session), data, credential, Duration.ofSeconds(s.ttl), clientId, rootSessionId);
    context.getAuthenticationSession().setAuthNote(AUTH_NOTE_SENT_AT, String.valueOf(Time.currentTime()));
    context.getEvent().detail("push_provider", data.getPushProviderType());
    log.debugf("native-push: issued challenge %s for user %s via %s", issued.challenge().getId(), user.getUsername(), data.getPushProviderType());
    return issued.challenge();
  }

  private Optional<PushChallenge> pendingChallenge(AuthenticationSessionModel authSession) {
    String id = ChallengeNoteHelper.readChallengeId(authSession);
    if (id == null) return Optional.empty();
    return new PushChallengeStore(session).get(id).filter(c -> c.getType() == PushChallenge.Type.AUTHENTICATION && c.getStatus() == PushChallengeStatus.PENDING);
  }

  record Settings(int ttl, int pollInterval) {}

  static Settings settings(AuthenticatorConfigModel config) {
    Map<String, String> c = config == null || config.getConfig() == null ? Map.of() : config.getConfig();
    return new Settings(
        intOrDefault(c.get(PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG), (int) PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.getSeconds()),
        intOrDefault(c.get(NativePushAuthenticatorFactory.CONFIG_POLL_INTERVAL), NativePushAuthenticatorFactory.DEFAULT_POLL_INTERVAL));
  }

  private static int intOrDefault(String value, int fallback) {
    try {
      return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
