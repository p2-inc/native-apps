package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredAction;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.util.Base64Url;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code native-passkey-register} (spec/03 §4.4, spec/04 §4, spec/11 D1): registers a {@code
 * webauthn-passwordless} credential mid-flow. {@code requiredActionChallenge} emits one {@code
 * passkey_registration} descriptor through the request's {@link
 * io.phasetwo.keycloak.nativeauth.core.spi.ChallengeEnvelope}; {@code processAction} verifies the
 * attestation with {@link PasskeyRegistrationVerifier} and stores the credential.
 *
 * <p>The challenge is stored in an auth note and, like Keycloak's {@code WebAuthnRegister}, in a
 * single-use object so a ceremony can be completed only once even across cluster nodes.
 *
 * <p>Outside a native authentication session (browser login) the action is ignored for that login
 * and stays on the user; operators who need browser enrolment use Keycloak's {@code
 * webauthn-register-passwordless} instead.
 */
public class NativePasskeyRegisterRequiredAction implements NativeRequiredAction {

  private static final Logger log = Logger.getLogger(NativePasskeyRegisterRequiredAction.class);

  static final String AUTH_NOTE_CHALLENGE = "native-auth.passkey-registration.challenge";
  static final String SINGLE_USE_PREFIX = "native-auth.passkey-registration:";

  private final KeycloakSession session;

  public NativePasskeyRegisterRequiredAction(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSKEY_REGISTRATION;
  }

  @Override
  public void evaluateTriggers(RequiredActionContext context) {}

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    if (!NativeRequestContext.isNative(context.getAuthenticationSession())) {
      log.warnf(
          "Required action '%s' is only served by the native challenge endpoint; ignoring it for a non-native login of user %s",
          NativePasskeyRegisterRequiredActionFactory.PROVIDER_ID, context.getUser().getUsername());
      context.ignore();
      return;
    }
    challenge(context, null);
  }

  private void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String challenge = PasskeyRegistrationOptions.newChallenge();
    authSession.setAuthNote(AUTH_NOTE_CHALLENGE, challenge);
    session.singleUseObjects().put(SINGLE_USE_PREFIX + challenge, context.getRealm().getAccessCodeLifespanUserAction(), Map.of());

    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.PASSKEY_REGISTRATION)
            .setLabel("Create a passkey")
            .setRequired(true)
            .setError(error)
            .setParams(
                PasskeyRegistrationOptions.build(
                    context.getRealm(), context.getUser(), context.getUriInfo().getBaseUri(), challenge));
    NativeRequestContext.setPendingRequiredAction(authSession, NativePasskeyRegisterRequiredActionFactory.PROVIDER_ID, d);
    NativeRequestContext.envelope(session).replaceAll(java.util.List.of(d));
    context.challenge(NativeRequestContext.markerResponse());
  }

  @Override
  public void processAction(RequiredActionContext context) {
    UserModel user = context.getUser();
    // Separate UPDATE_CREDENTIAL event; the shared builder stays the LOGIN event of the request.
    EventBuilder credentialEvent =
        context.getEvent().clone().event(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
    if (params == null) params = new MultivaluedHashMap<>();
    String credentialIdParam = params.getFirst(Protocol.CREDENTIAL_ID);
    String clientDataParam = params.getFirst(Protocol.CLIENT_DATA_JSON);
    String attestationParam = params.getFirst(Protocol.ATTESTATION_OBJECT);
    if (isBlank(credentialIdParam) || isBlank(clientDataParam) || isBlank(attestationParam)) {
      challenge(context, new ChallengeDescriptor.ChallengeError(
          Protocol.DESC_ERR_MISSING_CREDENTIAL, "credential_id, client_data_json and attestation_object are required"));
      return;
    }
    byte[] clientDataJson;
    byte[] attestationObject;
    try {
      clientDataJson = Base64Url.decode(clientDataParam);
      attestationObject = Base64Url.decode(attestationParam);
    } catch (RuntimeException e) {
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "Registration fields must be base64url"));
      return;
    }
    Set<String> transports = parseTransports(params.getFirst(Protocol.TRANSPORTS));
    String label = params.getFirst(Protocol.LABEL);

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String challenge = authSession.getAuthNote(AUTH_NOTE_CHALLENGE);
    authSession.removeAuthNote(AUTH_NOTE_CHALLENGE);
    if (challenge == null || session.singleUseObjects().remove(SINGLE_USE_PREFIX + challenge) == null) {
      credentialEvent.error(Errors.INVALID_REGISTRATION);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_ATTESTATION, "Registration challenge expired or already used"));
      return;
    }

    try {
      PasskeyRegistrationVerifier.Registered registered =
          PasskeyRegistrationVerifier.verifyAndStore(
              session, context.getRealm(), user, context.getUriInfo().getBaseUri(), challenge,
              attestationObject, clientDataJson, transports, label);
      credentialEvent
          .detail(WebAuthnConstants.PUBKEY_CRED_ID_ATTR, registered.credentialIdBase64Url())
          .detail(WebAuthnConstants.PUBKEY_CRED_LABEL_ATTR, label == null ? "" : label)
          .detail(WebAuthnConstants.PUBKEY_CRED_AAGUID_ATTR, registered.aaguid());
      if (registered.credential() != null) {
        credentialEvent.detail(Details.CREDENTIAL_ID, registered.credential().getId());
      }
      credentialEvent.success();
      NativeRequestContext.clearPendingRequiredAction(authSession);
      context.success();
    } catch (PasskeyRegistrationException e) {
      credentialEvent.detail(WebAuthnConstants.REG_ERR_DETAIL_LABEL, e.getMessage()).error(Errors.INVALID_REGISTRATION);
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_ATTESTATION, e.getMessage()));
    }
  }

  static Set<String> parseTransports(String value) {
    if (value == null || value.isBlank()) return Set.of();
    return Arrays.stream(value.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private static boolean isBlank(String s) {
    return s == null || s.isEmpty();
  }

  @Override
  public void close() {}
}
