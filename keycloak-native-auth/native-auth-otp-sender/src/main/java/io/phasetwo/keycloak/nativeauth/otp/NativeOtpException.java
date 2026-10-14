package io.phasetwo.keycloak.nativeauth.otp;

/** Delivery failed; the authenticator re-challenges without a code. */
public class NativeOtpException extends Exception {
  public NativeOtpException(String message, Throwable cause) {
    super(message, cause);
  }

  public NativeOtpException(String message) {
    super(message);
  }
}
