import Foundation
import KeycloakNativeCore
import KeycloakNativePush

/// The JSON the module exchanges with JavaScript (spec/19 §4), the twin of `BridgeJson.kt`. Every
/// shape here has a TypeScript reader in `src/model.ts` / `src/KeycloakNative.ts`.
enum BridgeJSON {
  /// `NativeAuthErrorCode.notConfigured` of `src/model.ts`.
  static let notConfigured = "not_configured"

  /// `KeycloakNativeConfig` of `src/KeycloakNative.ts`.
  struct Config {
    let issuer: URL
    let clientId: String
    let dpop: DPoPMode
    let allowRpIdMismatch: Bool
    let ephemeralWebSession: Bool
    let metadataCacheTTL: TimeInterval?
    let storageNamespace: String?
    let keychainAccessGroup: String?
  }

  static func object(_ text: String) throws -> [String: JSONValue] {
    guard let object = JSONValue(jsonString: text)?.objectValue else { throw invalid("Expected a JSON object from JavaScript") }
    return object
  }

  static func config(_ text: String) throws -> Config {
    let o = try object(text)
    guard let issuerString = o["issuer"]?.stringValue, let issuer = URL(string: issuerString) else { throw invalid("issuer is required") }
    guard let clientId = o["clientId"]?.stringValue else { throw invalid("clientId is required") }
    let dpop: DPoPMode
    switch o["dpop"]?.stringValue ?? "automatic" {
    case "automatic": dpop = .automatic
    case "hardware": dpop = .secureEnclave
    case "software": dpop = .software
    case "disabled": dpop = .disabled
    case let mode: throw invalid("Unknown dpop mode '\(mode)'")
    }
    return Config(
      issuer: issuer,
      clientId: clientId,
      dpop: dpop,
      allowRpIdMismatch: o["allowRpIdMismatch"]?.boolValue ?? false,
      ephemeralWebSession: o["ephemeralWebSession"]?.boolValue ?? false,
      metadataCacheTTL: o["metadataCacheTtl"]?.doubleValue,
      storageNamespace: o["storageNamespace"]?.stringValue,
      keychainAccessGroup: o["keychainAccessGroup"]?.stringValue)
  }

  /// `LoginParameters` of `src/KeycloakNative.ts`.
  static func loginParameters(_ text: String) throws -> LoginParameters {
    let o = try object(text)
    return LoginParameters(
      // An absent scope is the SDK default; an explicit empty one sends none.
      scope: o.keys.contains("scope") ? o["scope"]?.stringValue : "openid",
      acrValues: o["acrValues"]?.stringValue,
      loginHint: o["loginHint"]?.stringValue,
      prompt: o["prompt"]?.stringValue,
      maxAge: o["maxAge"]?.intValue,
      nonce: o["nonce"]?.stringValue,
      uiLocales: o["uiLocales"]?.stringValue,
      deviceName: o["deviceName"]?.stringValue,
      deviceId: o["deviceId"]?.stringValue,
      additionalParameters: strings(o["additionalParameters"]),
      continuationParameters: strings(o["continuationParameters"]))
  }

  static func stringMap(_ text: String) throws -> [String: String] {
    strings(.object(try object(text)))
  }

  private static func strings(_ value: JSONValue?) -> [String: String] {
    (value?.objectValue ?? [:]).compactMapValues(\.stringValue)
  }

  /// `ChallengeAnswer` of `src/model.ts`. Ceremony answers (passkeys, push enrollment) run natively and
  /// are not accepted from JavaScript.
  static func answer(_ text: String, type: ChallengeType) throws -> ChallengeAnswer {
    let o = try object(text)
    let kind = o["kind"]?.stringValue ?? ""
    func field(_ name: String) throws -> String {
      guard let value = o[name]?.stringValue else { throw invalid("The \(kind) answer needs '\(name)'") }
      return value
    }
    switch kind {
    case "username": return .username(try field("username"))
    case "password": return .password(try field("password"))
    case "totp": return .totp(try field("code"), credentialId: o["credentialId"]?.stringValue)
    case "otp": return .otp(try field("code"))
    case "otpResend": return .otpResend
    case "recoveryCode": return .recoveryCode(try field("code"))
    case "updatePassword": return .updatePassword(try field("password"), confirm: try field("confirm"))
    case "verifyEmail": return .verifyEmail(code: try field("code"))
    case "verifyEmailResend": return .verifyEmailResend
    case "terms":
      guard let accepted = o["accepted"]?.boolValue else { throw invalid("The terms answer needs 'accepted'") }
      return .terms(accepted: accepted)
    case "pushResend": return .pushResend
    case "pushPoll": return .pushPoll
    case "pushEnrollmentCheck": return .pushEnrollmentCheck
    case "pin": return .pin(try field("pin"))
    case "pinSetup": return .pinSetup(pin: try field("pin"), confirm: try field("confirm"))
    case "skip": return .skip(type)
    case "custom":
      let fields = try (o["fields"]?.arrayValue ?? []).map { entry -> FormField in
        guard let name = entry["name"]?.stringValue else { throw invalid("custom field without a name") }
        return FormField(name, entry["value"]?.stringValue ?? "")
      }
      return .custom(type: type, fields: fields)
    default:
      throw NativeAuthError(code: NativeAuthError.Code.unsupportedChallenge, description: "Unknown answer kind '\(kind)'")
    }
  }

  /// `NativeFlowStep`: the descriptors and context as the server sent them.
  static func step(_ step: FlowStep, expiresIn: Int?) -> JSONValue {
    switch step {
    case .challenges(let challenges, let context):
      var o: [String: JSONValue] = [
        "kind": "challenges",
        "challenges": .array(challenges.map(\.raw)),
        "context": context.raw,
      ]
      if let expiresIn { o["expiresIn"] = .number(Double(expiresIn)) }
      return .object(o)
    case .authorized(let credentials):
      return .object(["kind": "authorized", "credentials": self.credentials(credentials)])
    case .redirectToWeb(let request):
      return .object(["kind": "redirectToWeb", "request": request.raw])
    }
  }

  /// `NativeCredentials`: everything but the refresh token and the post-login `auth_session`.
  static func credentials(_ c: Credentials) -> JSONValue {
    .object([
      "accessToken": .string(c.accessToken),
      "tokenType": .string(c.authorizationScheme),
      "idToken": c.idToken.map(JSONValue.string) ?? .null,
      "scope": c.scope.map(JSONValue.string) ?? .null,
      "expiresAt": millis(c.expiresAt),
      "refreshExpiresAt": millis(c.refreshExpiresAt),
      "issuedAt": millis(c.issuedAt),
      "hasRefreshToken": .bool(c.refreshToken != nil),
      "isDPoPBound": .bool(c.isDPoPBound),
    ])
  }

  /// Epoch milliseconds; `null` for none and for "never" (an offline token's `distantFuture`).
  private static func millis(_ date: Date?) -> JSONValue {
    guard let date, date < Date.distantFuture else { return .null }
    return .number((date.timeIntervalSince1970 * 1000).rounded())
  }

  /// `PushEnrollment` of `src/model.ts`; instants in epoch milliseconds.
  static func enrollment(_ e: PushEnrollment) -> JSONValue {
    .object([
      "credentialId": .string(e.credentialId),
      "deviceId": .string(e.deviceId),
      "userId": .string(e.userId),
      "username": e.username.map(JSONValue.string) ?? .null,
      "deviceLabel": .string(e.deviceLabel),
      "pushProviderType": .string(e.pushProviderType),
      "pushProviderId": e.pushProviderId.map(JSONValue.string) ?? .null,
      "deviceApiBase": .string(e.deviceApiBase.absoluteString),
      "keyThumbprint": .string(e.keyThumbprint),
      "enrolledAt": millis(e.enrolledAt),
    ])
  }

  static func payload(_ p: PushNotificationPayload) -> JSONValue {
    .object([
      "cid": .string(p.cid),
      "credentialId": p.credentialId.map(JSONValue.string) ?? .null,
      "expiresAt": millis(p.expiresAt),
    ])
  }

  static func string(_ value: JSONValue) throws -> String {
    String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
  }

  static func string(_ headers: [String: String]) throws -> String {
    try string(.object(headers.mapValues(JSONValue.string)))
  }

  private static func invalid(_ message: String) -> NativeAuthError {
    NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: message)
  }
}
