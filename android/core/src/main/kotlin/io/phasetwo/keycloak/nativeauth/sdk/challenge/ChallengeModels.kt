package io.phasetwo.keycloak.nativeauth.sdk.challenge

import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.arrayValue
import io.phasetwo.keycloak.nativeauth.sdk.json.boolValue
import io.phasetwo.keycloak.nativeauth.sdk.json.doubleValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.intValue
import io.phasetwo.keycloak.nativeauth.sdk.json.jsonObjectOf
import io.phasetwo.keycloak.nativeauth.sdk.json.objectValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringArray
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAssertion
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import java.net.URI
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Challenge types of spec/03 §4. Types this SDK version cannot answer decode as [Unknown] and are kept
 * in the set so the app can show "update the app or use the web" (spec/03 §4.11). Two types are equal
 * when their [wire] values are.
 */
public sealed class ChallengeType(public val wire: String) {
  public object Username : ChallengeType("username")
  public object Password : ChallengeType("password")
  public object Passkey : ChallengeType("passkey")
  public object PasskeyRegistration : ChallengeType("passkey_registration")
  public object Totp : ChallengeType("totp")
  public object Otp : ChallengeType("otp")
  public object Push : ChallengeType("push")
  public object RecoveryCode : ChallengeType("recovery_code")
  public object Select : ChallengeType("select")

  // Native required actions (spec/03 §4.12–§4.15).
  public object UpdatePassword : ChallengeType("update_password")
  public object VerifyEmail : ChallengeType("verify_email")
  public object Terms : ChallengeType("terms")
  public object PushEnrollment : ChallengeType("push_enrollment")

  // PIN extension (spec/03 §4.17, §4.18): the PIN factor and its set-PIN required action. Servers
  // advertise them only when the extension is installed.
  public object Pin : ChallengeType("pin")
  public object PinSetup : ChallengeType("pin_setup")
  public class Unknown(wire: String) : ChallengeType(wire)

  /**
   * Whether this SDK version has a [ChallengeAnswer] for the type. `select` is specified (spec/03
   * §4.9) but no server-side authenticator emits it yet.
   */
  public val isSupported: Boolean get() = this !is Unknown && this != Select

  /**
   * A required action served in-band (spec/03 §4.11): always the single entry of the set, its `id`
   * is the native required action's provider id.
   */
  public val isRequiredAction: Boolean
    get() = this == PasskeyRegistration || this == UpdatePassword || this == VerifyEmail || this == Terms || this == PushEnrollment || this == PinSetup

  final override fun equals(other: Any?): Boolean = other is ChallengeType && other.wire == wire

  final override fun hashCode(): Int = wire.hashCode()

  final override fun toString(): String = wire

  public companion object {
    private val known: Map<String, ChallengeType> by lazy {
      listOf(Username, Password, Passkey, PasskeyRegistration, Totp, Otp, Push, RecoveryCode, Select, UpdatePassword, VerifyEmail, Terms, PushEnrollment, Pin, PinSetup)
        .associateBy { it.wire }
    }

    public fun fromWire(wire: String): ChallengeType = known[wire] ?: Unknown(wire)
  }
}

/** `error` of a descriptor: the previous attempt at this challenge failed (spec/03 §3.3). */
public data class ChallengeError(public val code: String, public val message: String?) {
  public object Code {
    public const val INVALID_CREDENTIAL: String = "invalid_credential"
    public const val INVALID_USER: String = "invalid_user"
    public const val MISSING_CREDENTIAL: String = "missing_credential"
    public const val INVALID_ATTESTATION: String = "invalid_attestation"

    /** `otp`: the code expired or was consumed by too many attempts; `OtpResend` is needed (spec/03 §4.6). */
    public const val EXPIRED_CODE: String = "expired_code"

    /** `otp`: `OtpResend` before `resend_allowed_at`; not a failure. */
    public const val RESEND_TOO_SOON: String = "resend_too_soon"

    /** `update_password`: `password_confirm` differed (spec/03 §4.12). */
    public const val PASSWORD_MISMATCH: String = "password_mismatch"

    /** `update_password`: the realm's password policy rejected the value; `message` says why. */
    public const val INVALID_PASSWORD: String = "invalid_password"

    /** `push`: the device user refused the sign-in (spec/03 §4.7); `PushResend` may ask again. */
    public const val DENIED: String = "denied"

    /** `push`: the pending approval expired unanswered; `PushResend` may ask again. */
    public const val EXPIRED: String = "expired"

    /**
     * `pin`: the PIN reached its attempt limit and must be reset (on the web or by an administrator);
     * every further attempt fails, `retry.remaining` is 0 (spec/03 §4.17).
     */
    public const val CREDENTIAL_LOCKED: String = "credential_locked"

    /** `pin_setup`: `pin_confirm` differed (spec/03 §4.18). */
    public const val PIN_MISMATCH: String = "pin_mismatch"

    /** `pin_setup`: not exactly `length` digits. */
    public const val INVALID_FORMAT: String = "invalid_format"

    /** `pin_setup`: rejected as easy to guess (all the same digit, a simple run). */
    public const val WEAK_PIN: String = "weak_pin"
  }
}

public data class RetryInfo(public val remaining: Int?)

/** A challenge descriptor (spec/03 §3.3) with typed views of [params]. */
public class Challenge(
  /** `challenge_id`: the execution id, or the required action's provider id (spec/11 D1). */
  public val id: String,
  public val type: ChallengeType,
  public val label: String? = null,
  public val required: Boolean = true,
  public val error: ChallengeError? = null,
  public val retry: RetryInfo? = null,
  /**
   * `skippable` (spec/03 §3.3, §4.11): the user may decline this required action for this login with
   * [ChallengeAnswer.Skip].
   */
  public val isSkippable: Boolean = false,
  /** The raw `params` object (never null; an empty object when absent). */
  public val params: JsonElement = JsonObject(emptyMap()),
  /** The whole descriptor as received. */
  public val raw: JsonElement = jsonObjectOf("type" to JsonPrimitive(type.wire), "id" to JsonPrimitive(id), "params" to params),
) {
  public val usernameParams: UsernameParams? get() = if (type == ChallengeType.Username) UsernameParams(params) else null
  public val passwordParams: PasswordParams? get() = if (type == ChallengeType.Password) PasswordParams(params) else null
  public val totpParams: TotpParams? get() = if (type == ChallengeType.Totp) TotpParams(params) else null
  public val passkeyParams: PasskeyAssertionParams? get() = if (type == ChallengeType.Passkey) PasskeyAssertionParams.parse(params) else null
  public val passkeyRegistrationParams: PasskeyRegistrationParams?
    get() = if (type == ChallengeType.PasskeyRegistration) PasskeyRegistrationParams.parse(params) else null
  public val otpParams: OtpParams? get() = if (type == ChallengeType.Otp) OtpParams(params) else null
  public val recoveryCodeParams: RecoveryCodeParams? get() = if (type == ChallengeType.RecoveryCode) RecoveryCodeParams(params) else null
  public val updatePasswordParams: UpdatePasswordParams? get() = if (type == ChallengeType.UpdatePassword) UpdatePasswordParams(params) else null
  public val verifyEmailParams: VerifyEmailParams? get() = if (type == ChallengeType.VerifyEmail) VerifyEmailParams(params) else null
  public val termsParams: TermsParams? get() = if (type == ChallengeType.Terms) TermsParams(params) else null
  public val pushParams: PushParams? get() = if (type == ChallengeType.Push) PushParams(params) else null
  public val pushEnrollmentParams: PushEnrollmentParams? get() = if (type == ChallengeType.PushEnrollment) PushEnrollmentParams(params) else null
  public val pinParams: PinParams? get() = if (type == ChallengeType.Pin) PinParams(params) else null
  public val pinSetupParams: PinSetupParams? get() = if (type == ChallengeType.PinSetup) PinSetupParams(params) else null

  /**
   * `pin` with `credential_locked` (spec/03 §4.17): the PIN cannot be used until it is reset; another
   * attempt always fails, so offer cancel (or another alternative) instead.
   */
  public val isLocked: Boolean get() = error?.code == ChallengeError.Code.CREDENTIAL_LOCKED

  override fun equals(other: Any?): Boolean =
    other is Challenge && other.id == id && other.type == type && other.label == label && other.required == required &&
      other.error == error && other.retry == retry && other.isSkippable == isSkippable && other.params == params

  override fun hashCode(): Int = 31 * id.hashCode() + type.hashCode()

  override fun toString(): String = "Challenge($type, id=$id)"

  public companion object {
    /** `null` when `type` or `id` is missing. */
    public fun parse(json: JsonElement): Challenge? {
      val type = json["type"].stringValue ?: return null
      val id = json["id"].stringValue ?: return null
      val error = json["error"]
      return Challenge(
        id = id,
        type = ChallengeType.fromWire(type),
        label = json["label"].stringValue,
        required = json["required"].boolValue ?: true,
        error = error["code"].stringValue?.let { ChallengeError(it, error["message"].stringValue) },
        retry = json["retry"]?.let { RetryInfo(it["remaining"].intValue) },
        isSkippable = json["skippable"].boolValue ?: false,
        params = json["params"] ?: JsonObject(emptyMap()),
        raw = json,
      )
    }
  }
}

/** Seconds since the epoch, as the protocol sends instants. */
internal fun JsonElement?.epochInstant(): Instant? = doubleValue?.let { Instant.ofEpochMilli((it * 1000).toLong()) }

internal fun waitUntil(instant: Instant?, now: Instant): Duration =
  if (instant == null || !instant.isAfter(now)) Duration.ZERO else (instant.toEpochMilli() - now.toEpochMilli()).milliseconds

/** spec/03 §4.7: approve the sign-in on an enrolled device. */
public class PushParams(json: JsonElement) {
  public enum class Status(public val wire: String) { PENDING("pending"), APPROVED("approved"), DENIED("denied"), EXPIRED("expired") }

  /**
   * `true` once a push challenge exists (sent on describe when `push` is the single option, else
   * after `PushResend`); `false` after `denied` / `expired`.
   */
  public val sent: Boolean = json["sent"].boolValue ?: false

  /** The ba-itsys challenge id the device sees in `/login/pending`. */
  public val cid: String? = json["cid"].stringValue
  public val expiresAt: Instant? = json["expires_at"].epochInstant()

  /** Seconds between `PushPoll` answers. */
  public val pollInterval: Int = maxOf(1, json["poll_interval"].intValue ?: 3)
  public val status: Status? = json["status"].stringValue?.let { s -> Status.entries.firstOrNull { it.wire == s } }

  /** Number match: the number THIS client shows; the device offers three and the user picks it. */
  public val userVerificationNumber: String? =
    json["user_verification"].takeIf { it["type"].stringValue == "number_match" }?.get("number").stringValue

  /** Labels of the user's enrolled devices. */
  public val devices: List<String> = json["devices"].arrayValue.orEmpty().mapNotNull { it["label"].stringValue }
  public val resendAllowedAt: Instant? = json["resend_allowed_at"].epochInstant()

  public fun resendWait(now: Instant = Instant.now()): Duration = waitUntil(resendAllowedAt, now)

  /** `true` while a poll is worthwhile. */
  public val isPending: Boolean get() = sent && (status == null || status == Status.PENDING)
}

/** spec/03 §4.15: enrol this device for push MFA mid-flow (served by `native-push-enroll`). */
public class PushEnrollmentParams(json: JsonElement) {
  /** Realm-signed JWT (`typ: push-enroll-challenge`) with `sub`, `username`, `enrollmentId`, `nonce`, `exp`. */
  public val enrollmentToken: String? = json["enrollment_token"].stringValue
  public val expiresIn: Int? = json["expires_in"].intValue

  /** ba-itsys device API root (`…/realms/{realm}/push-mfa`). */
  public val deviceApiBase: URI? = json["device_api_base"].stringValue?.let { runCatching { URI(it) }.getOrNull() }
  public val userId: String? = json["user_id"].stringValue

  /** Unverified claims of the enrolment token, for display and for building the device JWT. */
  public val enrollmentClaims: JsonElement? get() = enrollmentToken?.let(Jwt::decodePayload)
}

/** spec/03 §4.17: the PIN factor. */
public class PinParams(json: JsonElement) {
  /** The length of the user's stored PIN: show that many slots and a numeric keypad. */
  public val length: Int = json["length"].intValue ?: 4
}

/** spec/03 §4.18: set a PIN (required action). */
public class PinSetupParams(json: JsonElement) {
  /** The PIN length the realm asks for. */
  public val length: Int = json["length"].intValue ?: 4

  /**
   * Whether [pin] has the shape the server accepts (exactly [length] ASCII digits); the server always
   * validates (and also rejects weak PINs).
   */
  public fun isWellFormed(pin: String): Boolean = pin.length == length && pin.all { it in '0'..'9' }
}

/** spec/03 §4.8: how many single-use recovery codes are left before this attempt. */
public class RecoveryCodeParams(json: JsonElement) {
  public val remaining: Int? = json["remaining"].intValue

  /** The realm's `recoveryCodesWarningThreshold`: suggest generating new codes at or below it. */
  public val warningThreshold: Int? = json["warning_threshold"].intValue

  public val shouldWarn: Boolean get() = remaining != null && warningThreshold != null && remaining <= warningThreshold
}

/** spec/03 §4.12: the realm's password policy, for pre-validation and hints. */
public class UpdatePasswordParams(json: JsonElement) {
  public val username: String? = json["username"].stringValue

  /** Keycloak policy id → configured value (`length: 8`, `digits: 1`, `notUsername: true`, …). */
  public val policy: Map<String, JsonElement> = json["policy"].objectValue.orEmpty()

  public val minimumLength: Int? get() = policy["length"].intValue
  public val maximumLength: Int? get() = policy["maxLength"].intValue

  /** Human-readable hints in a stable order (English; apps localize with [policy] if they need to). */
  public val hints: List<String>
    get() = buildList {
      fun plural(n: Int, word: String) = "At least $n $word${if (n == 1) "" else "s"}"
      policy["length"].intValue?.let { add("At least $it characters") }
      policy["maxLength"].intValue?.let { add("At most $it characters") }
      policy["digits"].intValue?.let { add(plural(it, "digit")) }
      policy["upperCase"].intValue?.let { add(plural(it, "upper-case letter")) }
      policy["lowerCase"].intValue?.let { add(plural(it, "lower-case letter")) }
      policy["specialChars"].intValue?.let { add(plural(it, "special character")) }
      if (policy["notUsername"] != null) add("Not your username")
      if (policy["notEmail"] != null) add("Not your email address")
      if (policy["notContainsUsername"] != null) add("Must not contain your username")
      policy["passwordHistory"].intValue?.let { add("Not one of your last $it passwords") }
      policy["regexPattern"].stringValue?.let { add("Must match $it") }
    }
}

/** spec/03 §4.13: like [OtpParams], for the email verification code of a required action. */
public class VerifyEmailParams(json: JsonElement) {
  public val emailMasked: String? = json["email_masked"].stringValue
  public val digits: Int = json["digits"].intValue ?: 6
  public val ttl: Int? = json["ttl"].intValue
  public val sent: Boolean = json["sent"].boolValue ?: false
  public val resendAllowedAt: Instant? = json["resend_allowed_at"].epochInstant()

  public fun resendWait(now: Instant = Instant.now()): Duration = waitUntil(resendAllowedAt, now)
}

/** spec/03 §4.14: terms text and/or URL to show before the user accepts. */
public class TermsParams(json: JsonElement) {
  public val text: String? = json["text"].stringValue
  public val url: URI? = json["url"].stringValue?.let { runCatching { URI(it) }.getOrNull() }
  public val version: String? = json["version"].stringValue
}

/** spec/03 §4.6: a code delivered out of band (email / SMS). */
public class OtpParams(json: JsonElement) {
  /** `email` | `sms` */
  public val channel: String = json["channel"].stringValue ?: "email"

  /** `a***@example.com`; never the full address. */
  public val destinationMasked: String? = json["destination_masked"].stringValue
  public val digits: Int = json["digits"].intValue ?: 6

  /** Code lifetime in seconds from sending. */
  public val ttl: Int? = json["ttl"].intValue

  /**
   * `true` when a code is outstanding. `false` when the server waits for `OtpResend` (the challenge is
   * one of several alternatives, or the previous code expired / was exhausted).
   */
  public val sent: Boolean = json["sent"].boolValue ?: false

  /** Earliest time another `OtpResend` is accepted. */
  public val resendAllowedAt: Instant? = json["resend_allowed_at"].epochInstant()

  /** Time until a resend is accepted (zero when allowed now). */
  public fun resendWait(now: Instant = Instant.now()): Duration = waitUntil(resendAllowedAt, now)
}

public class UsernameParams(json: JsonElement) {
  public val allowEmail: Boolean = json["allow_email"].boolValue ?: false
  public val hint: String? = json["hint"].stringValue
}

public class PasswordParams(json: JsonElement) {
  public val usernameKnown: Boolean = json["username_known"].boolValue ?: true
}

/** spec/03 §4.5. */
public class TotpParams(json: JsonElement) {
  public data class Credential(public val id: String, public val label: String)

  public val digits: Int = json["digits"].intValue ?: 6
  public val period: Int = json["period"].intValue ?: 30
  public val algorithm: String? = json["algorithm"].stringValue
  public val credentialLabels: List<String> = json["credential_labels"].stringArray.orEmpty()
  public val credentials: List<Credential> =
    json["credentials"].arrayValue.orEmpty().mapNotNull { entry -> entry["id"].stringValue?.let { Credential(it, entry["label"].stringValue ?: "") } }
}

/** spec/03 §4.3: a snake_case mirror of `PublicKeyCredentialRequestOptions`. */
public data class PasskeyAssertionParams(
  public val challenge: String,
  public val rpId: String,
  public val timeoutMilliseconds: Int? = null,
  /** `required` | `preferred` | `discouraged` */
  public val userVerification: String = "preferred",
  public val allowCredentials: List<AllowedCredential> = emptyList(),
  /** `true` when `allow_credentials` is empty: username-less login, `user_handle` names the user. */
  public val discoverable: Boolean = allowCredentials.isEmpty(),
) {
  public data class AllowedCredential(public val id: String, public val type: String, public val transports: List<String>) {
    public val idBytes: ByteArray? get() = Base64Url.decode(id)
  }

  public val challengeBytes: ByteArray? get() = Base64Url.decode(challenge)

  public companion object {
    public fun parse(json: JsonElement): PasskeyAssertionParams? {
      val challenge = json["challenge"].stringValue ?: return null
      val rpId = json["rp_id"].stringValue ?: return null
      val allowed = json["allow_credentials"].arrayValue.orEmpty().mapNotNull { entry ->
        entry["id"].stringValue?.let { AllowedCredential(it, entry["type"].stringValue ?: "public-key", entry["transports"].stringArray.orEmpty()) }
      }
      return PasskeyAssertionParams(
        challenge = challenge,
        rpId = rpId,
        timeoutMilliseconds = json["timeout"].intValue,
        userVerification = json["user_verification"].stringValue ?: "preferred",
        allowCredentials = allowed,
        discoverable = json["discoverable"].boolValue ?: allowed.isEmpty(),
      )
    }
  }
}

/** spec/03 §4.4 / §6: a snake_case mirror of `PublicKeyCredentialCreationOptions`. */
public data class PasskeyRegistrationParams(
  public val challenge: String,
  public val rp: RelyingParty,
  public val user: User,
  /** COSE algorithm identifiers (-7 = ES256, -257 = RS256). */
  public val pubKeyCredParams: List<Int>,
  public val residentKey: String?,
  public val requireResidentKey: Boolean,
  public val userVerification: String,
  public val authenticatorAttachment: String?,
  public val attestation: String,
  /** base64url credential ids that must not be re-registered. */
  public val excludeCredentials: List<String>,
  public val timeoutMilliseconds: Int?,
  /** The params as received, for platform APIs that take the WebAuthn JSON (Credential Manager). */
  public val raw: JsonElement,
) {
  public data class RelyingParty(public val id: String, public val name: String?)

  public data class User(
    /** base64url; the user handle the server expects back in discoverable assertions. */
    public val id: String,
    public val name: String,
    public val displayName: String?,
  ) {
    public val idBytes: ByteArray? get() = Base64Url.decode(id)
  }

  public val challengeBytes: ByteArray? get() = Base64Url.decode(challenge)

  public companion object {
    public fun parse(json: JsonElement): PasskeyRegistrationParams? {
      val challenge = json["challenge"].stringValue ?: return null
      val rpId = json["rp"]["id"].stringValue ?: return null
      val userId = json["user"]["id"].stringValue ?: return null
      val userName = json["user"]["name"].stringValue ?: return null
      val selection = json["authenticator_selection"]
      return PasskeyRegistrationParams(
        challenge = challenge,
        rp = RelyingParty(rpId, json["rp"]["name"].stringValue),
        user = User(userId, userName, json["user"]["display_name"].stringValue),
        pubKeyCredParams = json["pub_key_cred_params"].arrayValue.orEmpty().mapNotNull { it["alg"].intValue },
        residentKey = selection["resident_key"].stringValue,
        requireResidentKey = selection["require_resident_key"].boolValue ?: false,
        userVerification = selection["user_verification"].stringValue ?: "preferred",
        authenticatorAttachment = selection["authenticator_attachment"].stringValue,
        attestation = json["attestation"].stringValue ?: "none",
        excludeCredentials = json["exclude_credentials"].arrayValue.orEmpty().mapNotNull { it["id"].stringValue },
        timeoutMilliseconds = json["timeout"].intValue,
        raw = json,
      )
    }
  }
}

/** Informational `context` of a challenge response (spec/03 §3.2). */
public class FlowContext(json: JsonElement?) {
  public val username: String? = json["username"].stringValue
  public val displayName: String? = json["display_name"].stringValue
  public val clientName: String? = json["client_name"].stringValue
  public val acrRequested: String? = json["acr_requested"].stringValue
  public val stepUp: Boolean = json["step_up"].boolValue ?: false
  public val raw: JsonElement = json ?: JsonObject(emptyMap())

  override fun equals(other: Any?): Boolean = other is FlowContext && other.raw == raw

  override fun hashCode(): Int = raw.hashCode()

  public companion object {
    public val EMPTY: FlowContext = FlowContext(null)
  }
}

/** What the state machine hands back after `start()` / `respond(...)` (spec/05 §2.1). */
public sealed class FlowStep {
  /** More input is needed: the challenge set in flow order (spec/11 D3) plus context. */
  public data class Challenges(override val challenges: List<Challenge>, public val context: FlowContext) : FlowStep()

  /** The code was issued and exchanged; [Credentials.authSession] holds the post-login value. */
  public data class Authorized(override val credentials: Credentials) : FlowStep()

  /**
   * The server cannot finish natively (spec/03 §3.4): hand the request to `WebFallback`, which opens
   * the browser and exchanges the resulting code with this flow's PKCE verifier.
   */
  public data class RedirectToWeb(public val request: RedirectToWebRequest) : FlowStep()

  public open val challenges: List<Challenge>? get() = null
  public open val credentials: Credentials? get() = null
  public val redirectToWeb: RedirectToWebRequest? get() = (this as? RedirectToWeb)?.request

  /** The challenges this SDK version can answer, in server order. */
  public val supportedChallenges: List<Challenge> get() = challenges.orEmpty().filter { it.type.isSupported }
}

/** A `redirect_to_web` answer (spec/03 §3.4). */
public class RedirectToWebRequest private constructor(
  /** PAR `request_uri` (single use, expires after [expiresIn]). */
  public val requestUri: String,
  public val expiresIn: Int?,
  /** Where the browser flow will send the code; its scheme is the callback scheme to listen on. */
  public val redirectUri: String,
  /** Must match the `state` on the callback. */
  public val state: String?,
  /** Informational, e.g. `required_action:UPDATE_PASSWORD`. */
  public val reason: String?,
  public val errorDescription: String?,
  public val raw: JsonElement,
) {
  public val callbackScheme: String? get() = runCatching { URI(redirectUri).scheme }.getOrNull()

  override fun equals(other: Any?): Boolean = other is RedirectToWebRequest && other.raw == raw

  override fun hashCode(): Int = raw.hashCode()

  public companion object {
    public fun parse(json: JsonElement): RedirectToWebRequest? {
      val requestUri = json["request_uri"].stringValue ?: return null
      val redirectUri = json["redirect_uri"].stringValue ?: return null
      return RedirectToWebRequest(
        requestUri = requestUri,
        expiresIn = json["expires_in"].intValue,
        redirectUri = redirectUri,
        state = json["state"].stringValue,
        reason = json["reason"].stringValue,
        errorDescription = json["error_description"].stringValue,
        raw = json,
      )
    }
  }
}

/** One form field of a request, in send order. */
public data class FormField(public val name: String, public val value: String)

/** The client's answer to one challenge (spec/03 §4 continuation parameters). */
public sealed class ChallengeAnswer {
  public data class Username(public val username: String) : ChallengeAnswer()
  public data class Password(public val password: String) : ChallengeAnswer()
  public data class Totp(public val code: String, public val credentialId: String? = null) : ChallengeAnswer()
  public data class Passkey(public val assertion: PasskeyAssertion) : ChallengeAnswer()
  public data class PasskeyRegistration(public val attestation: PasskeyAttestation, public val label: String? = null) : ChallengeAnswer()

  /** The code the user received (spec/03 §4.6). */
  public data class Otp(public val code: String) : ChallengeAnswer()

  /** `action=resend`: (re)send a code; also the first send when [OtpParams.sent] is `false`. */
  public object OtpResend : ChallengeAnswer()

  /** `update_password` (spec/03 §4.12): the new password, sent as `password` + `password_confirm`. */
  public data class UpdatePassword(public val password: String, public val confirm: String) : ChallengeAnswer()

  /** `verify_email` (spec/03 §4.13): the code received by email. */
  public data class VerifyEmail(public val code: String) : ChallengeAnswer()

  /** `verify_email`: `action=resend`. */
  public object VerifyEmailResend : ChallengeAnswer()

  /** `terms` (spec/03 §4.14): `accepted=true` continues, `accepted=false` ends the login. */
  public data class Terms(public val accepted: Boolean) : ChallengeAnswer()

  /** `recovery_code` (spec/03 §4.8): one single-use code; separators and case do not matter. */
  public data class RecoveryCode(public val code: String) : ChallengeAnswer()

  /**
   * `push` (spec/03 §4.7): `action=resend`, create (and send) the push challenge; also the first send
   * when [PushParams.sent] is `false`.
   */
  public object PushResend : ChallengeAnswer()

  /** `push`: `action=poll`, ask whether the device answered; the server advances on `approved`. */
  public object PushPoll : ChallengeAnswer()

  /** `push_enrollment` (spec/03 §4.15): the device-signed enrolment JWT. */
  public data class PushEnrollment(public val token: String) : ChallengeAnswer()

  /** `push_enrollment`: `action=check`, the device enrolled through `/push-mfa/enroll/complete`. */
  public object PushEnrollmentCheck : ChallengeAnswer()

  /** `pin` (spec/03 §4.17): the user's PIN, sent as `pin`. */
  public data class Pin(public val pin: String) : ChallengeAnswer() {
    override fun toString(): String = "Pin(***)"
  }

  /** `pin_setup` (spec/03 §4.18): the new PIN, sent as `pin` + `pin_confirm`. */
  public data class PinSetup(public val pin: String, public val confirm: String) : ChallengeAnswer() {
    override fun toString(): String = "PinSetup(***)"
  }

  /**
   * `action=skip` (spec/03 §4.11): decline a required action whose challenge [Challenge.isSkippable]
   * ("Not now"); pass the challenge's type. The flow continues like after any answer.
   */
  public data class Skip(public val type: ChallengeType) : ChallengeAnswer()

  /**
   * Any other answer, e.g. for an extension challenge type (spec/03 §4.16) or an action this SDK has
   * no case for. Sent through the normal pipeline (DPoP proof, `use_dpop_nonce` retry, `auth_session`
   * rotation, code exchange). [fields] must not repeat `auth_session`, `challenge_type` or
   * `challenge_id`. Values are masked in logs and the flow log only when the name is in
   * `Redactor.sensitiveKeys` or starts with `x_`.
   */
  public data class Custom(public val type: ChallengeType, public val fields: List<FormField>) : ChallengeAnswer()
  // EXTENSION POINT: Select(challengeId) (spec/03 §4.9) follows a server-side authenticator.

  public val challengeType: ChallengeType
    get() = when (this) {
      is Username -> ChallengeType.Username
      is Password -> ChallengeType.Password
      is Totp -> ChallengeType.Totp
      is Passkey -> ChallengeType.Passkey
      is PasskeyRegistration -> ChallengeType.PasskeyRegistration
      is Otp, OtpResend -> ChallengeType.Otp
      is UpdatePassword -> ChallengeType.UpdatePassword
      is VerifyEmail, VerifyEmailResend -> ChallengeType.VerifyEmail
      is Terms -> ChallengeType.Terms
      is RecoveryCode -> ChallengeType.RecoveryCode
      PushResend, PushPoll -> ChallengeType.Push
      is PushEnrollment, PushEnrollmentCheck -> ChallengeType.PushEnrollment
      is Pin -> ChallengeType.Pin
      is PinSetup -> ChallengeType.PinSetup
      is Skip -> type
      is Custom -> type
    }

  /** Type-specific form fields (without `auth_session`, `challenge_type`, `challenge_id`). */
  public val formFields: List<Pair<String, String>>
    get() = when (this) {
      is Username -> listOf("username" to username)
      is Password -> listOf("password" to password)
      is Totp -> listOf("totp" to code) + if (credentialId.isNullOrEmpty()) emptyList() else listOf("credential_id" to credentialId)
      is Passkey -> assertion.formFields
      is PasskeyRegistration -> attestation.formFields + if (label.isNullOrEmpty()) emptyList() else listOf("label" to label)
      is Otp -> listOf("otp" to code)
      OtpResend -> listOf("action" to "resend")
      is UpdatePassword -> listOf("password" to password, "password_confirm" to confirm)
      is VerifyEmail -> listOf("code" to code)
      VerifyEmailResend -> listOf("action" to "resend")
      is Terms -> listOf("accepted" to accepted.toString())
      is RecoveryCode -> listOf("recovery_code" to code)
      PushResend -> listOf("action" to "resend")
      PushPoll -> listOf("action" to "poll")
      is PushEnrollment -> listOf("token" to token)
      PushEnrollmentCheck -> listOf("action" to "check")
      is Pin -> listOf("pin" to pin)
      is PinSetup -> listOf("pin" to pin, "pin_confirm" to confirm)
      is Skip -> listOf("action" to "skip")
      is Custom -> fields.map { it.name to it.value }
    }
}
