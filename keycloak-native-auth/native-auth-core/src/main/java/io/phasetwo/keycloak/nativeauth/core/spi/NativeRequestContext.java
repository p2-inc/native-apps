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

  /** Auth note: JSON object {@code {executionId: challengeType}} of the challenges last issued. */
  public static final String AUTH_NOTE_PENDING = "native-auth.pending";

  /** Client note copied from the request's optional {@code device_id} / {@code device_name}. */
  public static final String CLIENT_NOTE_DEVICE_ID = "native-auth.device_id";

  public static final String CLIENT_NOTE_DEVICE_NAME = "native-auth.device_name";

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

  /** @return {@code {executionId: challengeTypeWire}} of the last issued challenge set (possibly empty). */
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
