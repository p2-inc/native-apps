package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Glue between the endpoint and the authenticators: notes that mark an authentication session as
 * native, the per-request {@link ChallengeEnvelope}, and the marker {@link Response} authenticators
 * hand to {@code context.challenge()} so the processor stops the flow and returns to the endpoint.
 */
public final class NativeRequestContext {

  private NativeRequestContext() {}

  /** Client note set by the endpoint when it creates the authentication session. */
  public static final String CLIENT_NOTE_NATIVE = "native-auth";

  /** Auth note with the profile version the client negotiated. */
  public static final String AUTH_NOTE_PROTOCOL_VERSION = "native-auth.protocol_version";

  /**
   * Auth note: JSON object {@code {challengeId: challengeType}} of the challenges last issued. Ids are
   * execution ids while the flow runs and the required action's provider id once the flow has
   * finished and a native required action is being served (spec/11 D1).
   */
  public static final String AUTH_NOTE_PENDING = "native-auth.pending";

  /** Auth note: provider id of the native required action whose challenge is currently pending. */
  public static final String AUTH_NOTE_REQUIRED_ACTION = "native-auth.required-action";

  /** Client note copied from the request's optional {@code device_id} / {@code device_name}. */
  public static final String CLIENT_NOTE_DEVICE_ID = "native-auth.device_id";

  public static final String CLIENT_NOTE_DEVICE_NAME = "native-auth.device_name";

  /** Client note: this authentication session is a step-up inside an existing user session (spec/03 §5). */
  public static final String CLIENT_NOTE_STEP_UP = "native-auth.step-up";

  /** Client note: id of the user session a step-up continues. */
  public static final String CLIENT_NOTE_STEP_UP_USER_SESSION = "native-auth.step-up.user-session";

  /** {@link KeycloakSession} attribute holding the envelope for the current request. */
  public static final String SESSION_ATTR_ENVELOPE = "native-auth.envelope";

  /** Entity of the marker response. Never reaches a client; the endpoint replaces it. */
  public static final String MARKER = "native-auth-challenge";

  public static boolean isNative(AuthenticationSessionModel authSession) {
    return authSession != null && "true".equals(authSession.getClientNote(CLIENT_NOTE_NATIVE));
  }

  public static boolean isNative(AuthenticationFlowContext context) {
    return isNative(context.getAuthenticationSession());
  }

  public static void markNative(AuthenticationSessionModel authSession, String protocolVersion) {
    authSession.setClientNote(CLIENT_NOTE_NATIVE, "true");
    authSession.setAuthNote(AUTH_NOTE_PROTOCOL_VERSION, protocolVersion);
  }

  public static ChallengeEnvelope envelope(KeycloakSession session) {
    ChallengeEnvelope envelope = session.getAttribute(SESSION_ATTR_ENVELOPE, ChallengeEnvelope.class);
    if (envelope == null) {
      envelope = new ChallengeEnvelope();
      session.setAttribute(SESSION_ATTR_ENVELOPE, envelope);
    }
    return envelope;
  }

  public static ChallengeEnvelope envelopeIfPresent(KeycloakSession session) {
    return session.getAttribute(SESSION_ATTR_ENVELOPE, ChallengeEnvelope.class);
  }

  public static Response markerResponse() {
    return Response.status(Response.Status.FORBIDDEN).type(MediaType.TEXT_PLAIN_TYPE).entity(MARKER).build();
  }

  public static boolean isMarker(Response response) {
    return response != null && MARKER.equals(response.getEntity());
  }

  /** Records which executions the client may answer next (validated by the endpoint). */
  public static void setPending(AuthenticationSessionModel authSession, List<ChallengeDescriptor> descriptors) {
    Map<String, String> pending = new LinkedHashMap<>();
    for (ChallengeDescriptor d : descriptors) {
      pending.put(d.getId(), d.getType().wire());
    }
    authSession.setAuthNote(AUTH_NOTE_PENDING, NativeAuthJson.write(pending));
  }

  /**
   * Records that the next continuation must go to the native required action {@code providerId}
   * (its {@code challenge_id} is the provider id). Clears any flow-level pending ids.
   */
  public static void setPendingRequiredAction(
      AuthenticationSessionModel authSession, String providerId, ChallengeDescriptor descriptor) {
    descriptor.setId(providerId);
    setPending(authSession, List.of(descriptor));
    authSession.setAuthNote(AUTH_NOTE_REQUIRED_ACTION, providerId);
  }

  /** @return the provider id of the pending native required action, or {@code null} while the flow runs. */
  public static String pendingRequiredAction(AuthenticationSessionModel authSession) {
    return authSession.getAuthNote(AUTH_NOTE_REQUIRED_ACTION);
  }

  public static void clearPendingRequiredAction(AuthenticationSessionModel authSession) {
    authSession.removeAuthNote(AUTH_NOTE_REQUIRED_ACTION);
    authSession.removeAuthNote(AUTH_NOTE_PENDING);
  }

  /** @return {@code {challengeId: challengeTypeWire}} of the last issued challenge set (possibly empty). */
  @SuppressWarnings("unchecked")
  public static Map<String, String> pending(AuthenticationSessionModel authSession) {
    String note = authSession.getAuthNote(AUTH_NOTE_PENDING);
    if (note == null || note.isBlank()) return Collections.emptyMap();
    try {
      return NativeAuthJson.read(note, Map.class);
    } catch (IOException e) {
      return Collections.emptyMap();
    }
  }

  public static ChallengeType pendingType(AuthenticationSessionModel authSession, String executionId) {
    return ChallengeType.fromWire(pending(authSession).get(executionId));
  }
}
