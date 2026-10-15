import Foundation

/// Challenge types of spec/03 §4. Types this SDK version cannot answer decode as `.unknown` and are
/// kept in the set so the app can show "update the app or use the web" (spec/03 §4.11).
public enum ChallengeType: Sendable, Hashable, CustomStringConvertible {
  case username
  case password
  case passkey
  case passkeyRegistration
  case totp
  case otp
  case push
  case recoveryCode
  case select
  /// Native required actions (spec/03 §4.12–§4.15).
  case updatePassword
  case verifyEmail
  case terms
  case pushEnrollment
  case unknown(String)

  public init(wire: String) {
    switch wire {
    case "username": self = .username
    case "password": self = .password
    case "passkey": self = .passkey
    case "passkey_registration": self = .passkeyRegistration
    case "totp": self = .totp
    case "otp": self = .otp
    case "push": self = .push
    case "recovery_code": self = .recoveryCode
    case "select": self = .select
    case "update_password": self = .updatePassword
    case "verify_email": self = .verifyEmail
    case "terms": self = .terms
    case "push_enrollment": self = .pushEnrollment
    default: self = .unknown(wire)
    }
  }

  public var wire: String {
    switch self {
    case .username: "username"
    case .password: "password"
    case .passkey: "passkey"
    case .passkeyRegistration: "passkey_registration"
    case .totp: "totp"
    case .otp: "otp"
    case .push: "push"
    case .recoveryCode: "recovery_code"
    case .select: "select"
    case .updatePassword: "update_password"
    case .verifyEmail: "verify_email"
    case .terms: "terms"
    case .pushEnrollment: "push_enrollment"
    case .unknown(let value): value
    }
  }

  /// Whether this SDK version has a `ChallengeAnswer` for the type. `select` is specified (spec/03
  /// §4.9) but no server-side authenticator emits it yet.
  public var isSupported: Bool {
    switch self {
    case .username, .password, .passkey, .passkeyRegistration, .totp, .otp, .push, .recoveryCode, .updatePassword, .verifyEmail, .terms, .pushEnrollment: true
    default: false
    }
  }

  /// A required action served in-band (spec/03 §4.11): always the single entry of the set, its
  /// `id` is the native required action's provider id.
  public var isRequiredAction: Bool {
    switch self {
    case .passkeyRegistration, .updatePassword, .verifyEmail, .terms, .pushEnrollment: true
    default: false
    }
  }

  public var description: String { wire }
}

/// `error` of a descriptor: the previous attempt at this challenge failed (spec/03 §3.3).
public struct ChallengeError: Sendable, Equatable {
  public enum Code {
    public static let invalidCredential = "invalid_credential"
    public static let invalidUser = "invalid_user"
    public static let missingCredential = "missing_credential"
    public static let invalidAttestation = "invalid_attestation"
    /// `otp`: the code expired or was consumed by too many attempts; `otpResend` is needed (spec/03 §4.6).
    public static let expiredCode = "expired_code"
    /// `otp`: `otpResend` before `resend_allowed_at`; not a failure.
    public static let resendTooSoon = "resend_too_soon"
    /// `update_password`: `password_confirm` differed (spec/03 §4.12).
    public static let passwordMismatch = "password_mismatch"
    /// `update_password`: the realm's password policy rejected the value; `message` says why.
    public static let invalidPassword = "invalid_password"
    /// `push`: the device user refused the sign-in (spec/03 §4.7); `pushResend` may ask again.
    public static let denied = "denied"
    /// `push`: the pending approval expired unanswered; `pushResend` may ask again.
    public static let expired = "expired"
  }

  public let code: String
  public let message: String?

  public init(code: String, message: String?) {
    self.code = code
    self.message = message
  }
}

public struct RetryInfo: Sendable, Equatable {
  public let remaining: Int?
  public init(remaining: Int?) { self.remaining = remaining }
}

/// A challenge descriptor (spec/03 §3.3) with typed views of `params`.
public struct Challenge: Sendable, Identifiable, Equatable {
  /// `challenge_id`: the execution id, or the required action's provider id (spec/11 D1).
  public let id: String
  public let type: ChallengeType
  public let label: String?
  public let required: Bool
  public let error: ChallengeError?
  public let retry: RetryInfo?
  /// The raw `params` object (never nil; empty object when absent).
  public let params: JSONValue
  /// The whole descriptor as received.
  public let raw: JSONValue

  public init(id: String, type: ChallengeType, label: String? = nil, required: Bool = true, error: ChallengeError? = nil, retry: RetryInfo? = nil, params: JSONValue = .object([:])) {
    self.id = id
    self.type = type
    self.label = label
    self.required = required
    self.error = error
    self.retry = retry
    self.params = params
    self.raw = .object(["type": .string(type.wire), "id": .string(id), "params": params])
  }

  /// `nil` when `type` or `id` is missing.
  public init?(json: JSONValue) {
    guard let type = json["type"]?.stringValue, let id = json["id"]?.stringValue else { return nil }
    self.id = id
    self.type = ChallengeType(wire: type)
    self.label = json["label"]?.stringValue
    self.required = json["required"]?.boolValue ?? true
    if let error = json["error"], let code = error["code"]?.stringValue {
      self.error = ChallengeError(code: code, message: error["message"]?.stringValue)
    } else {
      self.error = nil
    }
    self.retry = json["retry"].map { RetryInfo(remaining: $0["remaining"]?.intValue) }
    self.params = json["params"] ?? .object([:])
    self.raw = json
  }

  public var usernameParams: UsernameParams? { type == .username ? UsernameParams(json: params) : nil }
  public var passwordParams: PasswordParams? { type == .password ? PasswordParams(json: params) : nil }
  public var totpParams: TOTPParams? { type == .totp ? TOTPParams(json: params) : nil }
  public var passkeyParams: PasskeyAssertionParams? { type == .passkey ? PasskeyAssertionParams(json: params) : nil }
  public var passkeyRegistrationParams: PasskeyRegistrationParams? {
    type == .passkeyRegistration ? PasskeyRegistrationParams(json: params) : nil
  }
  public var otpParams: OTPParams? { type == .otp ? OTPParams(json: params) : nil }
  public var recoveryCodeParams: RecoveryCodeParams? { type == .recoveryCode ? RecoveryCodeParams(json: params) : nil }
  public var updatePasswordParams: UpdatePasswordParams? { type == .updatePassword ? UpdatePasswordParams(json: params) : nil }
  public var verifyEmailParams: VerifyEmailParams? { type == .verifyEmail ? VerifyEmailParams(json: params) : nil }
  public var termsParams: TermsParams? { type == .terms ? TermsParams(json: params) : nil }
  public var pushParams: PushParams? { type == .push ? PushParams(json: params) : nil }
  public var pushEnrollmentParams: PushEnrollmentParams? { type == .pushEnrollment ? PushEnrollmentParams(json: params) : nil }
}

/// spec/03 §4.7 — approve the sign-in on an enrolled device.
public struct PushParams: Sendable, Equatable {
  public enum Status: String, Sendable { case pending, approved, denied, expired }

  /// `true` once a push challenge exists (sent on describe when `push` is the single option, else
  /// after `pushResend`); `false` after `denied` / `expired`.
  public let sent: Bool
  /// The ba-itsys challenge id the device sees in `/login/pending`.
  public let cid: String?
  public let expiresAt: Date?
  /// Seconds between `pushPoll` answers.
  public let pollInterval: Int
  public let status: Status?
  /// Number match: the number THIS client shows; the device offers three and the user picks it.
  public let userVerificationNumber: String?
  /// Labels of the user's enrolled devices.
  public let devices: [String]
  public let resendAllowedAt: Date?

  public init(json: JSONValue) {
    sent = json["sent"]?.boolValue ?? false
    cid = json["cid"]?.stringValue
    expiresAt = json["expires_at"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
    pollInterval = max(1, json["poll_interval"]?.intValue ?? 3)
    status = json["status"]?.stringValue.flatMap(Status.init(rawValue:))
    let uv = json["user_verification"]
    userVerificationNumber = uv?["type"]?.stringValue == "number_match" ? uv?["number"]?.stringValue : nil
    devices = (json["devices"]?.arrayValue ?? []).compactMap { $0["label"]?.stringValue }
    resendAllowedAt = json["resend_allowed_at"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
  }

  public func resendWait(at date: Date = Date()) -> TimeInterval {
    guard let resendAllowedAt else { return 0 }
    return max(0, resendAllowedAt.timeIntervalSince(date))
  }

  /// `true` while a poll is worthwhile.
  public var isPending: Bool { sent && (status == nil || status == .pending) }
}

/// spec/03 §4.15 — enrol this device for push MFA mid-flow (served by `native-push-enroll`).
public struct PushEnrollmentParams: Sendable, Equatable {
  /// Realm-signed JWT (`typ: push-enroll-challenge`) with `sub`, `username`, `enrollmentId`, `nonce`, `exp`.
  public let enrollmentToken: String?
  public let expiresIn: Int?
  /// ba-itsys device API root (`…/realms/{realm}/push-mfa`).
  public let deviceApiBase: URL?
  public let userId: String?

  public init(json: JSONValue) {
    enrollmentToken = json["enrollment_token"]?.stringValue
    expiresIn = json["expires_in"]?.intValue
    deviceApiBase = json["device_api_base"]?.stringValue.flatMap(URL.init(string:))
    userId = json["user_id"]?.stringValue
  }

  /// Unverified claims of the enrolment token, for display and for building the device JWT.
  public var enrollmentClaims: JSONValue? { enrollmentToken.flatMap(JWT.decodePayload) }
}

/// spec/03 §4.8 — how many single-use recovery codes are left before this attempt.
public struct RecoveryCodeParams: Sendable, Equatable {
  public let remaining: Int?
  /// The realm's `recoveryCodesWarningThreshold`: suggest generating new codes at or below it.
  public let warningThreshold: Int?

  public init(json: JSONValue) {
    remaining = json["remaining"]?.intValue
    warningThreshold = json["warning_threshold"]?.intValue
  }

  public var shouldWarn: Bool {
    guard let remaining, let warningThreshold else { return false }
    return remaining <= warningThreshold
  }
}

/// spec/03 §4.12 — the realm's password policy, for pre-validation and hints.
public struct UpdatePasswordParams: Sendable, Equatable {
  public let username: String?
  /// Keycloak policy id → configured value (`length: 8`, `digits: 1`, `notUsername: true`, …).
  public let policy: [String: JSONValue]

  public init(json: JSONValue) {
    username = json["username"]?.stringValue
    policy = json["policy"]?.objectValue ?? [:]
  }

  public var minimumLength: Int? { policy["length"]?.intValue }
  public var maximumLength: Int? { policy["maxLength"]?.intValue }

  /// Human-readable hints in a stable order (English; apps localise with `policy` if they need to).
  public var hints: [String] {
    var out: [String] = []
    if let n = policy["length"]?.intValue { out.append("At least \(n) characters") }
    if let n = policy["maxLength"]?.intValue { out.append("At most \(n) characters") }
    if let n = policy["digits"]?.intValue { out.append("At least \(n) digit\(n == 1 ? "" : "s")") }
    if let n = policy["upperCase"]?.intValue { out.append("At least \(n) upper-case letter\(n == 1 ? "" : "s")") }
    if let n = policy["lowerCase"]?.intValue { out.append("At least \(n) lower-case letter\(n == 1 ? "" : "s")") }
    if let n = policy["specialChars"]?.intValue { out.append("At least \(n) special character\(n == 1 ? "" : "s")") }
    if policy["notUsername"] != nil { out.append("Not your username") }
    if policy["notEmail"] != nil { out.append("Not your email address") }
    if policy["notContainsUsername"] != nil { out.append("Must not contain your username") }
    if let n = policy["passwordHistory"]?.intValue { out.append("Not one of your last \(n) passwords") }
    if let pattern = policy["regexPattern"]?.stringValue { out.append("Must match \(pattern)") }
    return out
  }
}

/// spec/03 §4.13 — like `OTPParams`, for the e-mail verification code of a required action.
public struct VerifyEmailParams: Sendable, Equatable {
  public let emailMasked: String?
  public let digits: Int
  public let ttl: Int?
  public let sent: Bool
  public let resendAllowedAt: Date?

  public init(json: JSONValue) {
    emailMasked = json["email_masked"]?.stringValue
    digits = json["digits"]?.intValue ?? 6
    ttl = json["ttl"]?.intValue
    sent = json["sent"]?.boolValue ?? false
    resendAllowedAt = json["resend_allowed_at"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
  }

  public func resendWait(at date: Date = Date()) -> TimeInterval {
    guard let resendAllowedAt else { return 0 }
    return max(0, resendAllowedAt.timeIntervalSince(date))
  }
}

/// spec/03 §4.14 — terms text and/or URL to show before the user accepts.
public struct TermsParams: Sendable, Equatable {
  public let text: String?
  public let url: URL?
  public let version: String?

  public init(json: JSONValue) {
    text = json["text"]?.stringValue
    url = json["url"]?.stringValue.flatMap(URL.init(string:))
    version = json["version"]?.stringValue
  }
}

/// spec/03 §4.6 — a code delivered out of band (email / SMS).
public struct OTPParams: Sendable, Equatable {
  /// `email` | `sms`
  public let channel: String
  /// `a***@example.com`; never the full address.
  public let destinationMasked: String?
  public let digits: Int
  /// Code lifetime in seconds from sending.
  public let ttl: Int?
  /// `true` when a code is outstanding. `false` when the server waits for `otpResend` (the challenge
  /// is one of several alternatives, or the previous code expired / was exhausted).
  public let sent: Bool
  /// Earliest time another `otpResend` is accepted.
  public let resendAllowedAt: Date?

  public init(json: JSONValue) {
    channel = json["channel"]?.stringValue ?? "email"
    destinationMasked = json["destination_masked"]?.stringValue
    digits = json["digits"]?.intValue ?? 6
    ttl = json["ttl"]?.intValue
    sent = json["sent"]?.boolValue ?? false
    resendAllowedAt = json["resend_allowed_at"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
  }

  /// Seconds until a resend is accepted (0 when allowed now).
  public func resendWait(at date: Date = Date()) -> TimeInterval {
    guard let resendAllowedAt else { return 0 }
    return max(0, resendAllowedAt.timeIntervalSince(date))
  }
}

public struct UsernameParams: Sendable, Equatable {
  public let allowEmail: Bool
  public let hint: String?

  public init(json: JSONValue) {
    allowEmail = json["allow_email"]?.boolValue ?? false
    hint = json["hint"]?.stringValue
  }
}

public struct PasswordParams: Sendable, Equatable {
  public let usernameKnown: Bool

  public init(json: JSONValue) {
    usernameKnown = json["username_known"]?.boolValue ?? true
  }
}

/// spec/03 §4.5.
public struct TOTPParams: Sendable, Equatable {
  public struct Credential: Sendable, Equatable {
    public let id: String
    public let label: String
  }

  public let digits: Int
  public let period: Int
  public let algorithm: String?
  public let credentialLabels: [String]
  public let credentials: [Credential]

  public init(json: JSONValue) {
    digits = json["digits"]?.intValue ?? 6
    period = json["period"]?.intValue ?? 30
    algorithm = json["algorithm"]?.stringValue
    credentialLabels = json["credential_labels"]?.stringArray ?? []
    credentials = (json["credentials"]?.arrayValue ?? []).compactMap { entry in
      guard let id = entry["id"]?.stringValue else { return nil }
      return Credential(id: id, label: entry["label"]?.stringValue ?? "")
    }
  }
}

/// spec/03 §4.3 — a snake_case mirror of `PublicKeyCredentialRequestOptions`.
public struct PasskeyAssertionParams: Sendable, Equatable {
  public struct AllowedCredential: Sendable, Equatable {
    public let id: String
    public let type: String
    public let transports: [String]
    public var idData: Data? { Base64URL.decode(id) }
  }

  public let challenge: String
  public let rpId: String
  public let timeoutMilliseconds: Int?
  /// `required` | `preferred` | `discouraged`
  public let userVerification: String
  public let allowCredentials: [AllowedCredential]
  /// `true` when `allow_credentials` is empty: username-less login, `user_handle` names the user.
  public let discoverable: Bool

  public var challengeData: Data? { Base64URL.decode(challenge) }

  public init(challenge: String, rpId: String, timeoutMilliseconds: Int? = nil, userVerification: String = "preferred", allowCredentials: [AllowedCredential] = [], discoverable: Bool? = nil) {
    self.challenge = challenge
    self.rpId = rpId
    self.timeoutMilliseconds = timeoutMilliseconds
    self.userVerification = userVerification
    self.allowCredentials = allowCredentials
    self.discoverable = discoverable ?? allowCredentials.isEmpty
  }

  public init?(json: JSONValue) {
    guard let challenge = json["challenge"]?.stringValue, let rpId = json["rp_id"]?.stringValue else { return nil }
    let allowed = (json["allow_credentials"]?.arrayValue ?? []).compactMap { entry -> AllowedCredential? in
      guard let id = entry["id"]?.stringValue else { return nil }
      return AllowedCredential(id: id, type: entry["type"]?.stringValue ?? "public-key", transports: entry["transports"]?.stringArray ?? [])
    }
    self.init(
      challenge: challenge,
      rpId: rpId,
      timeoutMilliseconds: json["timeout"]?.intValue,
      userVerification: json["user_verification"]?.stringValue ?? "preferred",
      allowCredentials: allowed,
      discoverable: json["discoverable"]?.boolValue)
  }
}

/// spec/03 §4.4 / §6 — a snake_case mirror of `PublicKeyCredentialCreationOptions`.
public struct PasskeyRegistrationParams: Sendable, Equatable {
  public struct RelyingParty: Sendable, Equatable {
    public let id: String
    public let name: String?
  }

  public struct User: Sendable, Equatable {
    /// base64url; the user handle the server expects back in discoverable assertions.
    public let id: String
    public let name: String
    public let displayName: String?
    public var idData: Data? { Base64URL.decode(id) }
  }

  public let challenge: String
  public let rp: RelyingParty
  public let user: User
  /// COSE algorithm identifiers (-7 = ES256, -257 = RS256).
  public let pubKeyCredParams: [Int]
  public let residentKey: String?
  public let requireResidentKey: Bool
  public let userVerification: String
  public let authenticatorAttachment: String?
  public let attestation: String
  /// base64url credential ids that must not be re-registered.
  public let excludeCredentials: [String]
  public let timeoutMilliseconds: Int?

  public var challengeData: Data? { Base64URL.decode(challenge) }

  public init?(json: JSONValue) {
    guard let challenge = json["challenge"]?.stringValue,
      let rpId = json["rp"]?["id"]?.stringValue,
      let userId = json["user"]?["id"]?.stringValue,
      let userName = json["user"]?["name"]?.stringValue
    else { return nil }
    self.challenge = challenge
    self.rp = RelyingParty(id: rpId, name: json["rp"]?["name"]?.stringValue)
    self.user = User(id: userId, name: userName, displayName: json["user"]?["display_name"]?.stringValue)
    self.pubKeyCredParams = (json["pub_key_cred_params"]?.arrayValue ?? []).compactMap { $0["alg"]?.intValue }
    let selection = json["authenticator_selection"]
    self.residentKey = selection?["resident_key"]?.stringValue
    self.requireResidentKey = selection?["require_resident_key"]?.boolValue ?? false
    self.userVerification = selection?["user_verification"]?.stringValue ?? "preferred"
    self.authenticatorAttachment = selection?["authenticator_attachment"]?.stringValue
    self.attestation = json["attestation"]?.stringValue ?? "none"
    self.excludeCredentials = (json["exclude_credentials"]?.arrayValue ?? []).compactMap { $0["id"]?.stringValue }
    self.timeoutMilliseconds = json["timeout"]?.intValue
  }
}

/// Informational `context` of a challenge response (spec/03 §3.2).
public struct FlowContext: Sendable, Equatable {
  public let username: String?
  public let displayName: String?
  public let clientName: String?
  public let acrRequested: String?
  public let stepUp: Bool
  public let raw: JSONValue

  public init(json: JSONValue?) {
    username = json?["username"]?.stringValue
    displayName = json?["display_name"]?.stringValue
    clientName = json?["client_name"]?.stringValue
    acrRequested = json?["acr_requested"]?.stringValue
    stepUp = json?["step_up"]?.boolValue ?? false
    raw = json ?? .object([:])
  }

  public static let empty = FlowContext(json: nil)
}

/// What the state machine hands back after `start()` / `respond(_:to:)` (spec/05 §2.1).
public enum FlowStep: Sendable {
  /// More input is needed: the challenge set in flow order (spec/11 D3) plus context.
  case challenges([Challenge], FlowContext)
  /// The code was issued and exchanged; `Credentials.authSession` holds the post-login value.
  case authorized(Credentials)
  /// The server cannot finish natively (spec/03 §3.4): hand the request to `WebFallback`, which
  /// opens the system browser and exchanges the resulting code with this flow's PKCE verifier.
  case redirectToWeb(RedirectToWebRequest)
}

/// A `redirect_to_web` answer (spec/03 §3.4).
public struct RedirectToWebRequest: Sendable, Equatable {
  /// PAR `request_uri` (single use, expires after `expiresIn`).
  public let requestUri: String
  public let expiresIn: Int?
  /// Where the browser flow will send the code; its scheme is the callback scheme to listen on.
  public let redirectUri: String
  /// Must match the `state` on the callback.
  public let state: String?
  /// Informational, e.g. `required_action:UPDATE_PASSWORD`.
  public let reason: String?
  public let errorDescription: String?
  public let raw: JSONValue

  public init?(json: JSONValue) {
    guard let requestUri = json["request_uri"]?.stringValue, let redirectUri = json["redirect_uri"]?.stringValue else { return nil }
    self.requestUri = requestUri
    self.expiresIn = json["expires_in"]?.intValue
    self.redirectUri = redirectUri
    self.state = json["state"]?.stringValue
    self.reason = json["reason"]?.stringValue
    self.errorDescription = json["error_description"]?.stringValue
    self.raw = json
  }

  public var callbackScheme: String? { URL(string: redirectUri)?.scheme }
}

extension FlowStep {
  public var challenges: [Challenge]? {
    if case .challenges(let list, _) = self { return list }
    return nil
  }

  public var credentials: Credentials? {
    if case .authorized(let credentials) = self { return credentials }
    return nil
  }

  public var redirectToWeb: RedirectToWebRequest? {
    if case .redirectToWeb(let request) = self { return request }
    return nil
  }

  /// The challenges this SDK version can answer, in server order.
  public var supportedChallenges: [Challenge] {
    challenges?.filter { $0.type.isSupported } ?? []
  }
}

/// The client's answer to one challenge (spec/03 §4 continuation parameters).
public enum ChallengeAnswer: Sendable, Equatable {
  case username(String)
  case password(String)
  case totp(String, credentialId: String? = nil)
  case passkey(PasskeyAssertion)
  case passkeyRegistration(PasskeyAttestation, label: String? = nil)
  /// The code the user received (spec/03 §4.6).
  case otp(String)
  /// `action=resend`: (re)send a code; also the first send when `OTPParams.sent` is `false`.
  case otpResend
  /// `update_password` (spec/03 §4.12): the new password, sent as `password` + `password_confirm`.
  case updatePassword(String, confirm: String)
  /// `verify_email` (spec/03 §4.13): the code received by e-mail.
  case verifyEmail(code: String)
  /// `verify_email`: `action=resend`.
  case verifyEmailResend
  /// `terms` (spec/03 §4.14): `accepted=true` continues, `accepted=false` ends the login.
  case terms(accepted: Bool)
  /// `recovery_code` (spec/03 §4.8): one single-use code; separators and case do not matter.
  case recoveryCode(String)
  /// `push` (spec/03 §4.7): `action=resend` — create (and send) the push challenge; also the first
  /// send when `PushParams.sent` is `false`.
  case pushResend
  /// `push`: `action=poll` — ask whether the device answered; the server advances on `approved`.
  case pushPoll
  /// `push_enrollment` (spec/03 §4.15): the device-signed enrolment JWT (`KeycloakNativePush`
  /// builds it from `PushEnrollmentParams`).
  case pushEnrollment(token: String)
  /// `push_enrollment`: `action=check` — the device enrolled through `/push-mfa/enroll/complete`.
  case pushEnrollmentCheck
  // EXTENSION POINT: select(challengeId:) (spec/03 §4.9) follows a server-side authenticator.

  public var challengeType: ChallengeType {
    switch self {
    case .username: .username
    case .password: .password
    case .totp: .totp
    case .passkey: .passkey
    case .passkeyRegistration: .passkeyRegistration
    case .otp, .otpResend: .otp
    case .updatePassword: .updatePassword
    case .verifyEmail, .verifyEmailResend: .verifyEmail
    case .terms: .terms
    case .recoveryCode: .recoveryCode
    case .pushResend, .pushPoll: .push
    case .pushEnrollment, .pushEnrollmentCheck: .pushEnrollment
    }
  }

  /// Type-specific form fields (without `auth_session`, `challenge_type`, `challenge_id`).
  public var formFields: [(name: String, value: String)] {
    switch self {
    case .username(let value):
      return [("username", value)]
    case .password(let value):
      return [("password", value)]
    case .totp(let code, let credentialId):
      var fields = [(name: "totp", value: code)]
      if let credentialId, !credentialId.isEmpty { fields.append(("credential_id", credentialId)) }
      return fields
    case .passkey(let assertion):
      return assertion.formFields
    case .passkeyRegistration(let attestation, let label):
      var fields = attestation.formFields
      if let label, !label.isEmpty { fields.append(("label", label)) }
      return fields
    case .otp(let code):
      return [("otp", code)]
    case .otpResend:
      return [("action", "resend")]
    case .updatePassword(let password, let confirm):
      return [("password", password), ("password_confirm", confirm)]
    case .verifyEmail(let code):
      return [("code", code)]
    case .verifyEmailResend:
      return [("action", "resend")]
    case .terms(let accepted):
      return [("accepted", accepted ? "true" : "false")]
    case .recoveryCode(let code):
      return [("recovery_code", code)]
    case .pushResend:
      return [("action", "resend")]
    case .pushPoll:
      return [("action", "poll")]
    case .pushEnrollment(let token):
      return [("token", token)]
    case .pushEnrollmentCheck:
      return [("action", "check")]
    }
  }
}
