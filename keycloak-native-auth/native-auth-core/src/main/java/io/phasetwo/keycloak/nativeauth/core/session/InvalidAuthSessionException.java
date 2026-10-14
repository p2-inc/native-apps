package io.phasetwo.keycloak.nativeauth.core.session;

/** Thrown when an {@code auth_session} value cannot be decrypted or has the wrong shape. */
public class InvalidAuthSessionException extends Exception {
  public InvalidAuthSessionException(String message) {
    super(message);
  }

  public InvalidAuthSessionException(String message, Throwable cause) {
    super(message, cause);
  }
}
