package io.phasetwo.keycloak.nativeauth.push;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.requiredactions.NativeRequiredActionBase;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-push-enroll} (spec/03 §4.15, spec/14 D9): the JSON variant of ba-itsys' {@code
 * push-mfa-register}, for which it substitutes (spec/03 §4.11). The descriptor carries a fresh
 * enrolment token; the client answers with the device-signed enrolment JWT it would otherwise POST
 * to {@code /push-mfa/enroll/complete}, or with {@code action=check} after enrolling there.
 */
public class NativePushEnrollRequiredAction extends NativeRequiredActionBase {

  static final String AUTH_NOTE_CHALLENGE = "native-auth.push-enroll.challenge";

  public NativePushEnrollRequiredAction(KeycloakSession session) {
    super(session);
  }

  @Override
  protected String providerId() {
    return NativePushEnrollRequiredActionFactory.PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PUSH_ENROLLMENT;
  }

  @Override
  protected void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    URI baseUri = context.getUriInfo().getBaseUri();
    Optional<PushChallenge> existing = PushEnrolment.pending(session, authSession.getAuthNote(AUTH_NOTE_CHALLENGE));
    PushEnrolment.Started started;
    if (existing.isPresent()) {
      started =
          new PushEnrolment.Started(
              existing.get(),
              de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder.build(session, context.getRealm(), context.getUser(), existing.get(), baseUri),
              Math.max(1, Duration.between(Instant.now(), existing.get().getExpiresAt()).getSeconds()));
    } else {
      started = PushEnrolment.start(session, context.getRealm(), context.getUser(), baseUri);
      authSession.setAuthNote(AUTH_NOTE_CHALLENGE, started.challenge().getId());
    }
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.PUSH_ENROLLMENT)
            .setLabel("Enrol this device for push sign-in")
            .setError(error)
            .param("enrollment_token", started.enrollmentToken())
            .param("expires_in", started.expiresIn())
            .param("device_api_base", PushEnrolment.deviceApiBase(context.getRealm(), baseUri))
            .param("user_id", context.getUser().getId());
    emit(context, d);
  }

  @Override
  public void processAction(RequiredActionContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    UserModel user = context.getUser();
    if (Protocol.ACTION_CHECK.equals(param(context, Protocol.ACTION))) {
      // Enrolled through the device API (spec/03 §7) in the meantime?
      if (PushCredentialService.getActiveCredentials(user).isEmpty()) {
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "No push credential yet; complete the enrolment first"));
        return;
      }
      finish(context, authSession);
      return;
    }
    String token = param(context, Protocol.TOKEN);
    if (isBlank(token)) {
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "token (the device-signed enrolment JWT) or action=check is required"));
      return;
    }
    Optional<PushChallenge> pending = PushEnrolment.pending(session, authSession.getAuthNote(AUTH_NOTE_CHALLENGE));
    if (pending.isEmpty()) {
      authSession.removeAuthNote(AUTH_NOTE_CHALLENGE);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_EXPIRED_CODE, "The enrolment challenge expired; a new enrolment token is attached"));
      return;
    }
    String jkt = authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT);
    String clientId = authSession.getClient() == null ? null : authSession.getClient().getClientId();
    try {
      PushEnrolment.complete(session, context.getRealm(), user, pending.get(), token, jkt, clientId);
    } catch (PushEnrolment.EnrolmentException e) {
      context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION_ERROR).detail(Details.CUSTOM_REQUIRED_ACTION, providerId()).detail(Details.REASON, e.getMessage()).error(Errors.INVALID_REGISTRATION);
      if (e.isExpired()) {
        authSession.removeAuthNote(AUTH_NOTE_CHALLENGE);
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_EXPIRED_CODE, e.getMessage()));
      } else {
        challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_CREDENTIAL, e.getMessage()));
      }
      return;
    }
    finish(context, authSession);
  }

  private void finish(RequiredActionContext context, AuthenticationSessionModel authSession) {
    authSession.removeAuthNote(AUTH_NOTE_CHALLENGE);
    context.getEvent().clone().event(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PushMfaConstants.CREDENTIAL_TYPE).success();
    context.success();
  }
}
