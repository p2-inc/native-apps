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
    case .unknown(let value): value
    }
  }

  /// Whether this SDK version has a `ChallengeAnswer` for the type. `otp`, `push`, `recovery_code`
  /// and `select` are specified but arrive with the Phase 2/3 server work.
  public var isSupported: Bool {
    switch self {
    case .username, .password, .passkey, .passkeyRegistration, .totp: true
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
  // EXTENSION POINT (Phase 2, spec/03 §3.4): `.redirectToWeb(RedirectToWebRequest)` is added together
  // with `WebFallback`. Today a `redirect_to_web` answer surfaces as `NativeAuthError` with that code.
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
  // EXTENSION POINT (Phase 2/3): otp(String), otpResend, push(poll|cancel), recoveryCode(String),
  // select(challengeId:) follow the server-side authenticators.

  public var challengeType: ChallengeType {
    switch self {
    case .username: .username
    case .password: .password
    case .totp: .totp
    case .passkey: .passkey
    case .passkeyRegistration: .passkeyRegistration
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
    }
  }
}
