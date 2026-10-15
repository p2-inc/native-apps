import Foundation
import KeycloakNativeCore

/// What the SDK keeps about this device's push enrolment (Keychain, `ThisDeviceOnly`).
public struct PushEnrollment: Sendable, Equatable, Codable {
  /// App-local handle of the credential on the server (`credentialId` of the device JWT).
  public let credentialId: String
  /// Stable per-installation id (`deviceId` of the device JWT and of every proof).
  public let deviceId: String
  /// Keycloak user id (`sub`); the device API's `userId` query.
  public let userId: String
  public let username: String?
  public let deviceLabel: String
  /// `apns` | `none` | … (ba-itsys `pushProviderType`).
  public var pushProviderType: String
  /// The APNs device token (hex) when `pushProviderType == "apns"`, else a placeholder.
  public var pushProviderId: String?
  /// ba-itsys device API root (`…/realms/{realm}/push-mfa`).
  public let deviceApiBase: URL
  /// RFC 7638 thumbprint of the key the credential is bound to (the DPoP key, spec/14 D9).
  public var keyThumbprint: String
  public let enrolledAt: Date

  public init(credentialId: String, deviceId: String, userId: String, username: String?, deviceLabel: String, pushProviderType: String, pushProviderId: String?, deviceApiBase: URL, keyThumbprint: String, enrolledAt: Date = Date()) {
    self.credentialId = credentialId
    self.deviceId = deviceId
    self.userId = userId
    self.username = username
    self.deviceLabel = deviceLabel
    self.pushProviderType = pushProviderType
    self.pushProviderId = pushProviderId
    self.deviceApiBase = deviceApiBase
    self.keyThumbprint = keyThumbprint
    self.enrolledAt = enrolledAt
  }
}

/// One entry of `GET /push-mfa/login/pending` (spec/03 §7).
public struct PendingApproval: Sendable, Identifiable, Equatable {
  public var id: String { cid }
  public let cid: String
  public let userId: String?
  public let username: String?
  public let clientId: String?
  public let clientName: String?
  public let createdAt: Date?
  public let expiresAt: Date?
  /// Number match: the three numbers to offer; the browser / native client shows one of them.
  public let numbers: [String]
  /// `pin` user verification: the user types the PIN the other side shows.
  public let requiresPin: Bool
  public let raw: JSONValue

  public init?(json: JSONValue) {
    guard let cid = json["cid"]?.stringValue else { return nil }
    self.cid = cid
    userId = json["userId"]?.stringValue
    username = json["username"]?.stringValue
    clientId = json["clientId"]?.stringValue
    clientName = json["clientName"]?.stringValue
    createdAt = json["createdAt"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
    expiresAt = json["expiresAt"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
    let uv = json["userVerification"]
    numbers = uv?["numbers"]?.stringArray ?? (uv?["numbers"]?.arrayValue ?? []).compactMap { $0.intValue.map(String.init) ?? $0.stringValue }
    requiresPin = uv?["type"]?.stringValue == "pin"
    raw = json
  }

  public var isExpired: Bool {
    guard let expiresAt else { return false }
    return expiresAt <= Date()
  }

  /// What to show: the client's display name, else its id.
  public var clientDisplayName: String { clientName ?? clientId ?? "?" }
}

/// The device's answer to a pending approval (`POST /push-mfa/login/challenges/{cid}/respond`).
public enum PushApprovalAction: Sendable, Equatable {
  /// `userVerification`: the number the user picked (number match) or the PIN typed, `nil` when
  /// the challenge has no user verification.
  case approve(userVerification: String? = nil)
  case deny

  var wire: String {
    switch self {
    case .approve: "approve"
    case .deny: "deny"
    }
  }
}

/// The custom keys of a push-MFA notification (spec/14 D10 payload; ba-itsys `confirmToken`).
public struct PushNotificationPayload: Sendable, Equatable {
  /// Realm-signed; its claims (`cid`, `credId`, `exp`) are read unverified — the device API is
  /// the authority, the token only routes the notification.
  public let confirmToken: String
  public let cid: String
  public let credentialId: String?
  public let expiresAt: Date?

  public init?(userInfo: [AnyHashable: Any]) {
    guard let token = userInfo["confirmToken"] as? String, let claims = JWT.decodePayload(token), let cid = claims["cid"]?.stringValue ?? (userInfo["cid"] as? String) else {
      return nil
    }
    confirmToken = token
    self.cid = cid
    credentialId = claims["credId"]?.stringValue ?? (userInfo["credId"] as? String)
    expiresAt = claims["exp"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
  }

  public init?(json: JSONValue) {
    var dict: [AnyHashable: Any] = [:]
    for (key, value) in json.objectValue ?? [:] {
      if let s = value.stringValue { dict[key] = s }
    }
    self.init(userInfo: dict)
  }
}

/// The in-flow enrolment answer (spec/03 §4.15) together with what to remember once the server
/// accepted it (`Push.commit(_:)`).
public struct PreparedPushEnrollment: Sendable {
  public let answer: ChallengeAnswer
  public let enrollment: PushEnrollment
}
