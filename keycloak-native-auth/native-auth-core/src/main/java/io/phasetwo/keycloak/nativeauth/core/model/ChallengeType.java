package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Challenge types of spec/03 §4. The wire value is the snake_case {@link #wire()} string. */
public enum ChallengeType {
  USERNAME("username"),
  PASSWORD("password"),
  PASSKEY("passkey"),
  PASSKEY_REGISTRATION("passkey_registration"),
  TOTP("totp"),
  OTP("otp"),
  PUSH("push"),
  RECOVERY_CODE("recovery_code"),
  SELECT("select"),
  REDIRECT_TO_WEB("redirect_to_web");

  private final String wire;

  ChallengeType(String wire) {
    this.wire = wire;
  }

  @JsonValue
  public String wire() {
    return wire;
  }

  @JsonCreator
  public static ChallengeType fromWire(String value) {
    if (value == null) return null;
    for (ChallengeType t : values()) {
      if (t.wire.equals(value)) return t;
    }
    return null;
  }
}
