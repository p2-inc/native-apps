import Foundation
import KeycloakNativeCore

/// Push MFA for this device (spec/05 §5, spec/03 §4.7, §4.15, §7; spec/14 D9): enrolment from inside
/// the app or mid-flow, the pending approvals of the user, approve / deny with number match, APNs
/// token sync, key rotation and the panic lockout. The device key is the SDK's DPoP key and the
/// device token is the user's DPoP-bound native access token (`DeviceTokenProvider`).
public struct Push: Sendable {
  private let kc: KeycloakNative
  private let tokenProvider: any DeviceTokenProvider
  private let logger: any NativeAuthLogger
  private let storeKey: String

  init(kc: KeycloakNative, tokenProvider: any DeviceTokenProvider) {
    self.kc = kc
    self.tokenProvider = tokenProvider
    self.logger = kc.options.logger
    self.storeKey = kc.scopedStorageKey("push-enrollment")
  }

  // MARK: - Local state

  /// The stored enrolment of this device, if any.
  public var enrollment: PushEnrollment? {
    guard let data = try? kc.secureStore.data(forKey: storeKey) else { return nil }
    return try? JSONDecoder().decode(PushEnrollment.self, from: data)
  }

  public var isEnrolled: Bool { enrollment != nil }

  /// Forgets the local enrolment (the server credential stays; an admin removes it).
  public func forgetEnrollment() throws {
    try kc.secureStore.removeData(forKey: storeKey)
  }

  func store(_ enrollment: PushEnrollment) throws {
    try kc.secureStore.set(try JSONEncoder().encode(enrollment), forKey: storeKey)
  }

  /// The server's `push` metadata block; `push_unavailable` when the extension is not installed.
  public func metadata() async throws -> NativeAuthMetadata.Push {
    guard let push = try await kc.metadata().push, push.enabled else {
      throw NativeAuthError(code: NativeAuthError.Code.pushUnavailable, description: "The server advertises no push block (spec/03 §1.1)")
    }
    return push
  }

  // MARK: - Enrolment

  /// Scenario C (spec/02 §3): `POST /native-auth/push/enroll/start` with the native token, then
  /// `POST {device_api_base}/enroll/complete` with a device JWT signed by the DPoP key. The
  /// enrolment is stored on success. `pushProviderType` `apns` needs the APNs device token
  /// (`pushProviderId`, hex); `none` enrols a device that pulls its approvals.
  @discardableResult
  public func enroll(deviceLabel: String, pushProviderType: String = "none", pushProviderId: String? = nil) async throws -> PushEnrollment {
    let push = try await metadata()
    let startURL = push.enrollStartEndpoint ?? kc.issuer.appending(path: "native-auth/push/enroll/start")
    let token = try await tokenProvider.deviceToken()
    let start = try await send(method: "POST", url: startURL, body: nil, token: token, deviceId: nil, userId: nil)
    guard start.statusCode == 200, let json = start.json, let enrollmentToken = json["enrollment_token"]?.stringValue else {
      throw Push.error(start, fallback: NativeAuthError.Code.invalidResponse)
    }
    let base = json["device_api_base"]?.stringValue.flatMap(URL.init(string:)) ?? push.deviceApiBase ?? kc.issuer.appending(path: "push-mfa")
    let prepared = try await prepare(enrollmentToken: enrollmentToken, userId: json["user_id"]?.stringValue, deviceApiBase: base, deviceLabel: deviceLabel, pushProviderType: pushProviderType, pushProviderId: pushProviderId)
    guard case .pushEnrollment(let deviceJWT) = prepared.answer else { preconditionFailure() }
    let completeURL = base.appending(path: "enroll/complete")
    let body = Data(JSONValue.object(["token": .string(deviceJWT)]).serialized().utf8)
    let complete = try await send(method: "POST", url: completeURL, body: body, token: token, deviceId: prepared.enrollment.deviceId, userId: prepared.enrollment.userId)
    guard complete.statusCode == 200 || complete.statusCode == 201 else {
      throw Push.error(complete, fallback: NativeAuthError.Code.invalidResponse)
    }
    try store(prepared.enrollment)
    logger.log(.info, "Push MFA enrolled (credential \(prepared.enrollment.credentialId), provider \(pushProviderType))")
    return prepared.enrollment
  }

  /// The §4.15 answer for a `push_enrollment` challenge: the device JWT signed by the DPoP key.
  /// Call `commit(_:)` once the flow accepted it (the next step is not an error on this challenge).
  public func prepareEnrollment(for params: PushEnrollmentParams, deviceLabel: String, pushProviderType: String = "none", pushProviderId: String? = nil) async throws -> PreparedPushEnrollment {
    guard let token = params.enrollmentToken else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "push_enrollment challenge without enrollment_token")
    }
    var base = params.deviceApiBase
    if base == nil { base = try? await metadata().deviceApiBase }
    return try await prepare(enrollmentToken: token, userId: params.userId, deviceApiBase: base ?? kc.issuer.appending(path: "push-mfa"), deviceLabel: deviceLabel, pushProviderType: pushProviderType, pushProviderId: pushProviderId)
  }

  /// Stores a prepared mid-flow enrolment the server accepted.
  public func commit(_ prepared: PreparedPushEnrollment) throws {
    try store(prepared.enrollment)
    logger.log(.info, "Push MFA enrolled in-flow (credential \(prepared.enrollment.credentialId))")
  }

  private func prepare(enrollmentToken: String, userId: String?, deviceApiBase: URL, deviceLabel: String, pushProviderType: String, pushProviderId: String?) async throws -> PreparedPushEnrollment {
    guard let claims = JWT.decodePayload(enrollmentToken), let enrollmentId = claims["enrollmentId"]?.stringValue, let nonce = claims["nonce"]?.stringValue else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Enrolment token without enrollmentId / nonce")
    }
    if let exp = claims["exp"]?.doubleValue, Date(timeIntervalSince1970: exp) <= Date() {
      // The server is the authority (it answers expired_code / 400); this only helps diagnostics.
      logger.log(.warning, "The enrolment token looks expired (exp \(Int(exp))); the server will decide")
    }
    guard let sub = claims["sub"]?.stringValue ?? userId else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Enrolment token without sub")
    }
    if pushProviderType != "none", (pushProviderId ?? "").isEmpty {
      throw NativeAuthError(code: NativeAuthError.Code.invalidRequest, description: "pushProviderId (the APNs device token) is required for pushProviderType \(pushProviderType)")
    }
    let key = try await kc.dpopKey()
    let existing = enrollment
    let deviceId = existing?.deviceId ?? UUID().uuidString.lowercased()
    let credentialId = Base64URL.encode(Push.randomBytes(16))
    var jwk = key.publicJWK.jsonValue.objectValue ?? [:]
    jwk["alg"] = .string(key.algorithm)
    var payload: [String: JSONValue] = [
      "sub": .string(sub),
      "enrollmentId": .string(enrollmentId),
      "nonce": .string(nonce),
      "exp": .number(Double(Int(Date().timeIntervalSince1970) + 120)),
      "cnf": .object(["jwk": .object(jwk)]),
      "credentialId": .string(credentialId),
      "deviceId": .string(deviceId),
      "deviceType": "ios",
      "deviceLabel": .string(deviceLabel),
      "pushProviderType": .string(pushProviderType),
    ]
    if let pushProviderId, !pushProviderId.isEmpty { payload["pushProviderId"] = .string(pushProviderId) }
    let deviceJWT = try DeviceJWT.sign(payload, with: key)
    let enrollment = PushEnrollment(
      credentialId: credentialId, deviceId: deviceId, userId: sub, username: claims["username"]?.stringValue, deviceLabel: deviceLabel,
      pushProviderType: pushProviderType, pushProviderId: pushProviderId, deviceApiBase: deviceApiBase, keyThumbprint: key.publicJWK.thumbprint)
    return PreparedPushEnrollment(answer: .pushEnrollment(token: deviceJWT), enrollment: enrollment)
  }

  // MARK: - Approvals

  /// `GET {device_api_base}/login/pending?userId=…`: what is waiting for this user. Poll it on
  /// foreground (and from the pull-to-refresh of an approvals screen): pushes may be delayed or
  /// dropped, and the simulator never receives any.
  public func pendingApprovals() async throws -> [PendingApproval] {
    let enrollment = try requireEnrollment()
    let token = try await tokenProvider.deviceToken()
    var components = URLComponents(url: enrollment.deviceApiBase.appending(path: "login/pending"), resolvingAgainstBaseURL: false)!
    components.queryItems = [URLQueryItem(name: "userId", value: enrollment.userId)]
    let response = try await send(method: "GET", url: components.url!, body: nil, token: token, deviceId: enrollment.deviceId, userId: enrollment.userId)
    guard response.statusCode == 200, let json = response.json else {
      throw Push.error(response, fallback: NativeAuthError.Code.invalidResponse)
    }
    return (json["challenges"]?.arrayValue ?? []).compactMap(PendingApproval.init(json:))
  }

  /// `POST …/login/challenges/{cid}/respond` with a device JWT (`cid`, `credId`, `deviceId`,
  /// `action`, `userVerification?`, `exp`). Returns the server's `status` (`approved` / `denied`).
  /// Number mismatch → `user_verification_mismatch`; resolved meanwhile → `push_conflict`.
  @discardableResult
  public func respond(to approval: PendingApproval, _ action: PushApprovalAction) async throws -> String {
    try await respond(cid: approval.cid, action)
  }

  @discardableResult
  public func respond(cid: String, _ action: PushApprovalAction) async throws -> String {
    let enrollment = try requireEnrollment()
    let token = try await tokenProvider.deviceToken()
    let key = try await kc.dpopKey()
    var payload: [String: JSONValue] = [
      "cid": .string(cid),
      "credId": .string(enrollment.credentialId),
      "deviceId": .string(enrollment.deviceId),
      "action": .string(action.wire),
      "exp": .number(Double(Int(Date().timeIntervalSince1970) + 120)),
    ]
    if case .approve(let verification) = action, let verification { payload["userVerification"] = .string(verification) }
    let body = Data(JSONValue.object(["token": .string(try DeviceJWT.sign(payload, with: key))]).serialized().utf8)
    let url = enrollment.deviceApiBase.appending(path: "login/challenges/\(cid)/respond")
    let response = try await send(method: "POST", url: url, body: body, token: token, deviceId: enrollment.deviceId, userId: enrollment.userId)
    guard response.statusCode == 200, let status = response.json?["status"]?.stringValue else {
      switch response.statusCode {
      case 403: throw Push.error(response, fallback: NativeAuthError.Code.userVerificationMismatch)
      case 409: throw Push.error(response, fallback: NativeAuthError.Code.pushConflict)
      default: throw Push.error(response, fallback: NativeAuthError.Code.invalidResponse)
      }
    }
    logger.log(.info, "Push challenge \(cid): \(status)")
    return status
  }

  /// Decodes a push-MFA notification (`confirmToken` and friends in `userInfo`). `nil` when it is
  /// not one, or it is for another credential than this device's.
  public func handleNotification(_ userInfo: [AnyHashable: Any]) -> PushNotificationPayload? {
    guard let payload = PushNotificationPayload(userInfo: userInfo) else { return nil }
    if let credentialId = payload.credentialId, let enrollment, credentialId != enrollment.credentialId {
      logger.log(.info, "Push notification for another credential; ignored")
      return nil
    }
    return payload
  }

  /// The pending approval a notification refers to, if it is still open.
  public func pendingApproval(for payload: PushNotificationPayload) async throws -> PendingApproval? {
    try await pendingApprovals().first { $0.cid == payload.cid }
  }

  // MARK: - Maintenance (spec/03 §7 "Maintenance")

  /// Call from `didRegisterForRemoteNotificationsWithDeviceToken`: `PUT …/device/push-provider`
  /// when the token differs from the stored one (`pushProviderType` `apns`).
  public func updateAPNsToken(_ deviceToken: Data) async throws {
    let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
    try await updatePushProvider(type: "apns", id: hex)
  }

  /// `PUT …/device/push-provider`; `type` `none` tells the server to skip delivery (the app then
  /// pulls its approvals). No request when nothing changed locally.
  public func updatePushProvider(type: String, id: String) async throws {
    var enrollment = try requireEnrollment()
    guard enrollment.pushProviderType != type || enrollment.pushProviderId != id else { return }
    let token = try await tokenProvider.deviceToken()
    let body = Data(JSONValue.object(["pushProviderId": .string(id), "pushProviderType": .string(type)]).serialized().utf8)
    let response = try await send(method: "PUT", url: enrollment.deviceApiBase.appending(path: "device/push-provider"), body: body, token: token, deviceId: enrollment.deviceId, userId: enrollment.userId)
    guard response.statusCode == 200 else { throw Push.error(response, fallback: NativeAuthError.Code.invalidResponse) }
    enrollment.pushProviderType = type
    enrollment.pushProviderId = id
    try store(enrollment)
    logger.log(.info, "Push provider updated (\(type)): \(response.json?["status"]?.stringValue ?? "?")")
  }

  /// `PUT …/device/rotate-key`: a fresh DPoP key is registered with a proof signed by the current
  /// one, then becomes the DPoP key (spec/14 D9). The stored native tokens were bound to the old key
  /// and are cleared: the user signs in again, which binds new tokens to the new key.
  public func rotateKey() async throws {
    var enrollment = try requireEnrollment()
    let token = try await tokenProvider.deviceToken()
    let newKey = try await kc.prepareDPoPKeyRotation()
    var jwk = newKey.publicJWK.jsonValue.objectValue ?? [:]
    jwk["alg"] = .string(newKey.algorithm)
    let body = Data(JSONValue.object(["publicKeyJwk": .object(jwk)]).serialized().utf8)
    let response = try await send(method: "PUT", url: enrollment.deviceApiBase.appending(path: "device/rotate-key"), body: body, token: token, deviceId: enrollment.deviceId, userId: enrollment.userId)
    guard response.statusCode == 200 else { throw Push.error(response, fallback: NativeAuthError.Code.invalidResponse) }
    try await kc.commitDPoPKeyRotation(newKey)
    enrollment.keyThumbprint = newKey.publicJWK.thumbprint
    try store(enrollment)
    try? await kc.credentialsManager().clear()
    logger.log(.info, "Push device key rotated; a new login is needed to bind tokens to it")
  }

  /// `POST …/login/lockout`: the panic button. ba-itsys disables the user account; an admin
  /// re-enables it.
  public func lockout() async throws {
    let enrollment = try requireEnrollment()
    let token = try await tokenProvider.deviceToken()
    let response = try await send(method: "POST", url: enrollment.deviceApiBase.appending(path: "login/lockout"), body: nil, token: token, deviceId: enrollment.deviceId, userId: enrollment.userId)
    guard response.statusCode == 200 else { throw Push.error(response, fallback: NativeAuthError.Code.invalidResponse) }
    logger.log(.warning, "Account locked out from this device")
  }

  // MARK: - Transport

  private func requireEnrollment() throws -> PushEnrollment {
    guard let enrollment else {
      throw NativeAuthError(code: NativeAuthError.Code.pushNotEnrolled, description: "This device is not enrolled for push MFA")
    }
    return enrollment
  }

  /// `Authorization: <scheme> <token>` plus a DPoP proof with `ath`, `sub` and `deviceId`
  /// (spec/03 §7.1); one retry on `use_dpop_nonce`.
  private func send(method: String, url: URL, body: Data?, token: DeviceToken, deviceId: String?, userId: String?) async throws -> HTTPResponse {
    var response = try await kc.transport.send(try await request(method: method, url: url, body: body, token: token, deviceId: deviceId, userId: userId))
    if let nonce = response.dpopNonceChallenge {
      await kc.rememberDPoPNonce(nonce, for: url)
      response = try await kc.transport.send(try await request(method: method, url: url, body: body, token: token, deviceId: deviceId, userId: userId))
    }
    return response
  }

  private func request(method: String, url: URL, body: Data?, token: DeviceToken, deviceId: String?, userId: String?) async throws -> HTTPRequest {
    var headers = ["Accept": "application/json", "Authorization": "\(token.scheme) \(token.accessToken)"]
    if body != nil { headers["Content-Type"] = "application/json" }
    var extra: [String: JSONValue] = [:]
    if let userId { extra["sub"] = .string(userId) }
    if let deviceId { extra["deviceId"] = .string(deviceId) }
    if let proof = try await kc.dpopProof(method: method, url: url, accessToken: token.accessToken, extraClaims: extra) {
      headers["DPoP"] = proof
    }
    return HTTPRequest(method: method, url: url, headers: headers, body: body)
  }

  /// ba-itsys puts a sentence in `error` ("User verification mismatch"), not a code, so the code
  /// is chosen here from the status and the server's text becomes the description.
  private static func error(_ response: HTTPResponse, fallback: String) -> NativeAuthError {
    let code = response.statusCode == 401 ? NativeAuthError.Code.invalidToken : fallback
    let json = response.json
    let text = json?["error_description"]?.stringValue ?? json?["error"]?.stringValue ?? "HTTP \(response.statusCode) from the push device API"
    return NativeAuthError(code: code, statusCode: response.statusCode, description: text, details: json, isRetryable: response.statusCode >= 500)
  }

  static func randomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }
}

extension KeycloakNative {
  /// Push MFA for this device (spec/05 §5). The default token provider is the instance's stored
  /// native login (`NativeDeviceTokenProvider`, spec/03 §7.1).
  public func push(tokenProvider: (any DeviceTokenProvider)? = nil) -> Push {
    Push(kc: self, tokenProvider: tokenProvider ?? NativeDeviceTokenProvider(credentials: credentialsManager()))
  }
}
