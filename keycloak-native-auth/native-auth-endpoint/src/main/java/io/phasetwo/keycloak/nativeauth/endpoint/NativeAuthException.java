package io.phasetwo.keycloak.nativeauth.endpoint;

import jakarta.ws.rs.core.Response;

/** Internal: aborts request handling with a spec/03 §3.5 error. */
class NativeAuthException extends RuntimeException {

  private final Response.Status status;
  private final String error;
  private final String authSession;

  NativeAuthException(Response.Status status, String error, String description) {
    this(status, error, description, null);
  }

  NativeAuthException(Response.Status status, String error, String description, String authSession) {
    super(description);
    this.status = status;
    this.error = error;
    this.authSession = authSession;
  }

  Response toResponse() {
    return Responses.error(status, error, getMessage(), authSession);
  }

  /** An exception whose response is the given (already filled) error body. */
  static NativeAuthException withBody(Response.Status status, io.phasetwo.keycloak.nativeauth.core.model.ErrorResponse body) {
    return new NativeAuthException(status, body.getError(), body.getErrorDescription(), body.getAuthSession()) {
      @Override
      Response toResponse() {
        return Responses.json(status, body);
      }
    };
  }
}
