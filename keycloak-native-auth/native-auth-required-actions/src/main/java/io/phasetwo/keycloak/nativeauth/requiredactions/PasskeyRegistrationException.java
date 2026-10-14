package io.phasetwo.keycloak.nativeauth.requiredactions;

/** Attestation did not verify or violates the policy; {@link #getMessage()} is safe to show a client. */
public class PasskeyRegistrationException extends Exception {

  public PasskeyRegistrationException(String message, Throwable cause) {
    super(message, cause);
  }
}
