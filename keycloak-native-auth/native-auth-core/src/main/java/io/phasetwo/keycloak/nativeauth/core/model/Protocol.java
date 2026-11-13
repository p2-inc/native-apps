package io.phasetwo.keycloak.nativeauth.core.model;

/**
 * Wire-level constants of the Keycloak Native Authentication Profile (spec/03). Parameter names are
 * form fields on {@code POST /native-auth/challenge}; error codes are the {@code error} values of
 * spec/03 §3.
 */
public final class Protocol {

  private Protocol() {}

  public static final String VERSION = "1";
  public static final String FIPA_DRAFT = "draft-ietf-oauth-first-party-apps-04";

  /** Provider id of the realm resource; yields {@code /realms/{realm}/native-auth}. */
  public static final String RESOURCE_ID = "native-auth";

  // ---- request parameters (spec/03 §2) ----
  public static final String CLIENT_ID = "client_id";
  public static final String RESPONSE_TYPE = "response_type";
  public static final String SCOPE = "scope";
  public static final String CODE_CHALLENGE = "code_challenge";
  public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
  public static final String ACR_VALUES = "acr_values";
  public static final String MAX_AGE = "max_age";
  public static final String LOGIN_HINT = "login_hint";
  public static final String PROMPT = "prompt";
  public static final String NONCE = "nonce";
  public static final String UI_LOCALES = "ui_locales";
  public static final String AUTH_SESSION = "auth_session";
  public static final String DEVICE_NAME = "device_name";
  public static final String DEVICE_ID = "device_id";
  public static final String CHALLENGE_TYPE = "challenge_type";
  public static final String CHALLENGE_ID = "challenge_id";
  public static final String ACTION = "action";

  public static final String ACTION_CANCEL = "cancel";
  public static final String ACTION_RESEND = "resend";
  public static final String ACTION_SELECT = "select";
  /** {@code push}: read the challenge status (spec/03 §4.7). */
  public static final String ACTION_POLL = "poll";
  /** {@code push_enrollment}: the device enrolled through the device API, check for the credential (spec/03 §4.15). */
  public static final String ACTION_CHECK = "check";
  /** Declines a descriptor that carries {@code skippable: true} (spec/03 §4.11). */
  public static final String ACTION_SKIP = "skip";

  // ---- extension parameters (spec/03 §2.3) ----
  public static final String EXTENSION_PARAM_PREFIX = "x_";
  public static final int EXTENSION_PARAM_MAX_COUNT = 16;
  public static final int EXTENSION_PARAM_MAX_NAME_LENGTH = 64;
  public static final int EXTENSION_PARAM_MAX_VALUE_LENGTH = 2048;

  // ---- challenge-type specific continuation fields (spec/03 §4) ----
  public static final String USERNAME = "username";
  public static final String PASSWORD = "password";
  public static final String TOTP = "totp";
  public static final String CREDENTIAL_ID = "credential_id";
  // passkey (spec/03 §4.3) and passkey_registration (§4.4, §6)
  public static final String CLIENT_DATA_JSON = "client_data_json";
  public static final String AUTHENTICATOR_DATA = "authenticator_data";
  public static final String SIGNATURE = "signature";
  public static final String USER_HANDLE = "user_handle";
  public static final String ATTESTATION_OBJECT = "attestation_object";
  public static final String TRANSPORTS = "transports";
  public static final String LABEL = "label";
  public static final String REGISTRATION_ID = "registration_id";
  // otp (spec/03 §4.6)
  public static final String OTP = "otp";
  // recovery_code (spec/03 §4.8)
  public static final String RECOVERY_CODE = "recovery_code";
  // update_password (spec/03 §4.12): PASSWORD plus
  public static final String PASSWORD_CONFIRM = "password_confirm";
  // verify_email (spec/03 §4.13)
  public static final String CODE = "code";
  // terms (spec/03 §4.14)
  public static final String ACCEPTED = "accepted";
  // push_enrollment (spec/03 §4.15): the device-signed enrolment JWT
  public static final String TOKEN = "token";
  // pin (spec/03 §4.17) and pin_setup (§4.18)
  public static final String PIN = "pin";
  public static final String PIN_CONFIRM = "pin_confirm";
  // redirect_to_web (spec/03 §3.4) and step-up (§5, §6)
  public static final String REQUEST_URI = "request_uri";
  public static final String REDIRECT_URI = "redirect_uri";
  public static final String STATE = "state";
  public static final String REASON = "reason";
  public static final String EXPIRES_IN = "expires_in";

  // ---- error codes (spec/03 §3) ----
  public static final String ERR_INSUFFICIENT_AUTHORIZATION = "insufficient_authorization";
  public static final String ERR_REDIRECT_TO_WEB = "redirect_to_web";
  public static final String ERR_INVALID_REQUEST = "invalid_request";
  public static final String ERR_INVALID_SESSION = "invalid_session";
  public static final String ERR_INVALID_DPOP_PROOF = "invalid_dpop_proof";
  public static final String ERR_INVALID_CLIENT = "invalid_client";
  public static final String ERR_ACCESS_DENIED = "access_denied";
  public static final String ERR_SLOW_DOWN = "slow_down";
  public static final String ERR_CLIENT_ATTESTATION_REQUIRED = "client_attestation_required";
  public static final String ERR_SERVER_ERROR = "server_error";
  /** RFC 6750 error for the bearer-authenticated endpoints (spec/03 §6). */
  public static final String ERR_INVALID_TOKEN = "invalid_token";

  // ---- descriptor error codes (spec/03 §3.3 / §4) ----
  public static final String DESC_ERR_INVALID_CREDENTIAL = "invalid_credential";
  public static final String DESC_ERR_INVALID_USER = "invalid_user";
  public static final String DESC_ERR_MISSING_CREDENTIAL = "missing_credential";
  /** {@code passkey_registration}: the attestation did not verify (spec/03 §4.4). */
  public static final String DESC_ERR_INVALID_ATTESTATION = "invalid_attestation";
  /** {@code otp}: the code expired or was consumed by too many attempts; resend (spec/03 §4.6). */
  public static final String DESC_ERR_EXPIRED_CODE = "expired_code";
  /** {@code otp}: {@code action=resend} before {@code resend_allowed_at} (spec/03 §4.6). */
  public static final String DESC_ERR_RESEND_TOO_SOON = "resend_too_soon";
  /** {@code update_password}: {@code password_confirm} differs (spec/03 §4.12). */
  public static final String DESC_ERR_PASSWORD_MISMATCH = "password_mismatch";
  /** {@code update_password}: the realm's password policy rejected the value (spec/03 §4.12). */
  public static final String DESC_ERR_INVALID_PASSWORD = "invalid_password";
  /** {@code push}: the device user refused the sign-in (spec/03 §4.7). */
  public static final String DESC_ERR_DENIED = "denied";
  /** {@code push}: the challenge expired unanswered (spec/03 §4.7). */
  public static final String DESC_ERR_EXPIRED = "expired";
  /** {@code pin}: the PIN reached its attempt limit and must be reset (spec/03 §4.17). */
  public static final String DESC_ERR_CREDENTIAL_LOCKED = "credential_locked";
  /** {@code pin_setup}: {@code pin_confirm} differs (spec/03 §4.18). */
  public static final String DESC_ERR_PIN_MISMATCH = "pin_mismatch";
  /** {@code pin_setup}: not exactly {@code length} digits (spec/03 §4.18). */
  public static final String DESC_ERR_INVALID_FORMAT = "invalid_format";
  /** {@code pin_setup}: rejected as easy to guess (spec/03 §4.18). */
  public static final String DESC_ERR_WEAK_PIN = "weak_pin";

  // ---- Keycloak client / realm attributes ----
  public static final String CLIENT_ATTR_ENABLED = "native-auth.enabled";
  public static final String ATTR_FLOW_ALIAS = "native-auth.flow-alias";
  public static final String ATTR_CODE_REDIRECT_URI_MODE = "native-auth.code-redirect-uri-mode";
  public static final String ATTR_CODE_REDIRECT_URI = "native-auth.code-redirect-uri";
  /** Realm attribute: max age (s) of the authentication behind a token used for passkey registration (spec/07 §5). */
  public static final String ATTR_PASSKEY_REGISTRATION_MAX_AGE = "native-auth.passkey-registration-max-age";
  public static final int DEFAULT_PASSKEY_REGISTRATION_MAX_AGE = 300;
  public static final String DEFAULT_FLOW_ALIAS = "native";
  /** Client attribute: {@code redirect_uri} used for {@code redirect_to_web} (spec/03 §3.4); defaults to the first registered one. */
  public static final String CLIENT_ATTR_WEB_FALLBACK_REDIRECT_URI = "native-auth.web-fallback-redirect-uri";
  /** Provider id of the native passkey-registration required action (spec/03 §4.4); referenced by {@code native-passkey}'s enrol-on-first-login. */
  public static final String PASSKEY_REGISTER_ACTION = "native-passkey-register";
  /** Realm attribute: {@code true} restricts {@code /passkey/register/*} to tokens issued to native-enabled clients (spec/11 D5). */
  public static final String ATTR_PASSKEY_REGISTRATION_NATIVE_CLIENTS_ONLY = "native-auth.passkey-registration-native-clients-only";
  /** Realm attributes: fallback configuration of {@code native-terms} (spec/03 §4.14) when the required action has no config. */
  /**
   * Realm attribute: what the endpoint does when the flow reaches an execution that cannot produce a
   * native challenge (spec/03 §3.4): {@code error} (default, {@code 500 server_error}) or {@code
   * redirect_to_web}.
   */
  public static final String ATTR_NON_NATIVE_EXECUTION = "native-auth.non-native-execution";

  public static final String ATTR_TERMS_TEXT = "native-auth.terms-text";
  public static final String ATTR_TERMS_URL = "native-auth.terms-url";
  public static final String ATTR_TERMS_VERSION = "native-auth.terms-version";

  /** Sentinel redirect URI stored with the code when {@code code-redirect-uri-mode=sentinel}. */
  public static final String SENTINEL_REDIRECT_URI = "urn:keycloak:native-auth";
}
