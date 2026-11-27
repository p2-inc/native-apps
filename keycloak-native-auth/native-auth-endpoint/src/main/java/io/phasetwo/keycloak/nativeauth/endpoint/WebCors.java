package io.phasetwo.keycloak.nativeauth.endpoint;

import jakarta.ws.rs.core.Response;
import java.util.Set;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.WebOriginsUtils;

/**
 * CORS for browser clients of the native endpoint (the web SDK, spec/22). The endpoint uses no
 * cookies, so no credentials are allowed: a browser calls it with {@code credentials: "omit"}.
 *
 * <p>A request's {@code Origin} is allowed when it is one of the Web Origins of the client the
 * request belongs to (Keycloak's own rule for the token endpoint, including {@code +} and {@code
 * *}). When the client is not known, for example an {@code auth_session} that no longer decodes,
 * the origin is allowed when any enabled native-auth client of the realm lists it, so the browser
 * can still read the error. Preflights are answered for any origin, as Keycloak's token endpoint
 * does; the actual response decides.
 *
 * <p>Keycloak's {@code Cors} SPI changed signatures between 26.4 and 26.8, so the headers are
 * written here with the stable {@link WebOriginsUtils}.
 */
final class WebCors {

  static final String ALLOWED_METHODS = "GET, POST, OPTIONS";
  static final String ALLOWED_HEADERS = "Accept, Authorization, Content-Type, DPoP";
  static final String EXPOSED_HEADERS = "DPoP-Nonce, WWW-Authenticate, Retry-After";
  static final long MAX_AGE_SECONDS = 3600;

  private WebCors() {}

  /** The request's {@code Origin} header, or {@code null} for a non-browser request. */
  static String origin(KeycloakSession session) {
    String origin = session.getContext().getRequestHeaders().getHeaderString("Origin");
    return origin == null || origin.isBlank() || "null".equals(origin) ? null : origin;
  }

  /** Answers an {@code OPTIONS} preflight. */
  static Response preflight(KeycloakSession session) {
    Response.ResponseBuilder builder = Response.noContent();
    String origin = origin(session);
    if (origin != null) {
      builder
          .header("Access-Control-Allow-Origin", origin)
          .header("Access-Control-Allow-Methods", ALLOWED_METHODS)
          .header("Access-Control-Allow-Headers", ALLOWED_HEADERS)
          .header("Access-Control-Max-Age", MAX_AGE_SECONDS)
          .header("Vary", "Origin");
    }
    return builder.build();
  }

  /** {@code response} with CORS headers when the request's origin is allowed for {@code client}. */
  static Response apply(KeycloakSession session, ClientModel client, Response response) {
    String origin = origin(session);
    if (origin == null || response.getHeaders().containsKey("Access-Control-Allow-Origin")) {
      return response;
    }
    boolean allowed = client != null ? allows(session, client, origin) : realmAllows(session, origin);
    if (!allowed) return response;
    return Response.fromResponse(response)
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Expose-Headers", EXPOSED_HEADERS)
        .header("Vary", "Origin")
        .build();
  }

  /** {@code response} with {@code Access-Control-Allow-Origin: *}, for public documents. */
  static Response anyOrigin(Response response) {
    return Response.fromResponse(response).header("Access-Control-Allow-Origin", "*").build();
  }

  static boolean allows(KeycloakSession session, ClientModel client, String origin) {
    Set<String> origins = WebOriginsUtils.resolveValidWebOrigins(session, client);
    return origins.contains("*") || origins.contains(origin);
  }

  private static boolean realmAllows(KeycloakSession session, String origin) {
    RealmModel realm = session.getContext().getRealm();
    return realm.getClientsStream()
        .filter(ClientModel::isEnabled)
        .filter(NativeAuthConfig::isNativeEnabled)
        .anyMatch(c -> allows(session, c, origin));
  }
}
