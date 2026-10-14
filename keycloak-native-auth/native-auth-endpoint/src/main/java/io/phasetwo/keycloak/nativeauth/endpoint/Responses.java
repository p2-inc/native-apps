package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import io.phasetwo.keycloak.nativeauth.core.model.ErrorResponse;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** JSON responses with the cache headers OAuth requires for credential-bearing bodies. */
final class Responses {

  private Responses() {}

  static Response json(Response.Status status, Object body) {
    return Response.status(status)
        .type(MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .entity(NativeAuthJson.write(body))
        .build();
  }

  static Response error(Response.Status status, String error, String description) {
    return json(status, new ErrorResponse(error, description));
  }

  static Response error(Response.Status status, String error, String description, String authSession) {
    return json(status, new ErrorResponse(error, description).setAuthSession(authSession));
  }
}
