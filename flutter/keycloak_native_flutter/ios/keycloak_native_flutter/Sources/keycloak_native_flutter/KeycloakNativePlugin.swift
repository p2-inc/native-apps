import Flutter
import Foundation
import KeycloakNativeCore
import KeycloakNativePush
import UIKit

/// The iOS side of the Flutter plugin (spec/18): a thin bridge from the Pigeon host API to the iOS
/// SDK. SDK instances, flows and credentials live here and are named to Dart by handles; the
/// refresh token and the post-login `auth_session` never cross the channel. Passkey sheets and the
/// browser use the SDK's default anchor, the key window (Flutter's).
public final class KeycloakNativePlugin: NSObject, FlutterPlugin, KeycloakNativeHostApi {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let plugin = KeycloakNativePlugin(flutterApi: KeycloakNativeFlutterApi(binaryMessenger: registrar.messenger()))
    KeycloakNativeHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: plugin)
  }

  private let flutterApi: KeycloakNativeFlutterApi

  init(flutterApi: KeycloakNativeFlutterApi) {
    self.flutterApi = flutterApi
  }

  private final class FlowRecord {
    let instance: KeycloakNative
    let flow: NativeLoginFlow
    var redirect: RedirectToWebRequest?
    var handles: Set<String> = []

    init(instance: KeycloakNative, flow: NativeLoginFlow) {
      self.instance = instance
      self.flow = flow
    }
  }

  // Pigeon starts every call on the main actor, but async calls resume elsewhere: the tables are locked.
  private let lock = NSLock()
  private var instances: [String: KeycloakNative] = [:]
  private var flows: [String: FlowRecord] = [:]
  /// Credentials a flow produced that Dart has not stored yet, by handle.
  private var pendingCredentials: [String: Credentials] = [:]
  /// Per instance, the last error that handed back an `auth_session`: `continueAfterTokenChallenge`
  /// steps up with it, so the session value never reaches Dart.
  private var tokenChallenges: [String: NativeAuthError] = [:]

  // MARK: - KeycloakNativeHostApi

  func configure(config: ConfigureMessage) throws -> String {
    try bridged {
      guard let issuer = URL(string: config.issuer), issuer.scheme != nil else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "issuer is not a URL: \(config.issuer)")
      }
      var options = KeycloakNative.Options()
      options.dpop = switch config.dpop {
      case .automatic: .automatic
      case .hardware: .secureEnclave
      case .software: .software
      case .disabled: .disabled
      }
      options.allowRpIdMismatch = config.allowRpIdMismatch
      options.ephemeralWebSession = config.ephemeralWebSession
      if let ttl = config.metadataCacheTtlSeconds { options.metadataCacheTTL = TimeInterval(ttl) }
      let handle = UUID().uuidString
      if config.observeFlow == true { options.flowObserver = FlowLogForwarder(instance: handle, api: flutterApi) }
      let kc = KeycloakNative.configure(issuer: issuer, clientId: config.clientId, options: options)
      lock.withLock { instances[handle] = kc }
      return handle
    }
  }

  func startLogin(instance: String, parameters: LoginParametersMessage) throws -> String {
    try bridged {
      let kc = try self.instance(instance)
      return register(kc, kc.authentication().startLogin(parameters.sdk))
    }
  }

  func stepUp(instance: String, parameters: LoginParametersMessage) async throws -> String {
    try await bridgedAsync {
      let kc = try self.instance(instance)
      return register(kc, try await kc.authentication().stepUp(parameters.sdk))
    }
  }

  func continueAfterTokenChallenge(instance: String, parameters: LoginParametersMessage) async throws -> String {
    try await bridgedAsync {
      let kc = try self.instance(instance)
      guard let error = lock.withLock({ tokenChallenges.removeValue(forKey: instance) }) else {
        throw NativeAuthError(code: NativeAuthError.Code.reauthenticationRequired, description: "No token challenge with an auth_session is pending; start a new login")
      }
      return register(kc, try kc.authentication().continueAfterTokenChallenge(error, parameters: parameters.sdk))
    }
  }

  func start(flow: String) async throws -> FlowStepMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      return message(try await record.flow.start(), record)
    }
  }

  func respond(flow: String, challengeId: String, challengeType: String, answer: AnswerMessage, additionalFields: [String: String]) async throws -> FlowStepMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      guard let challenge = await record.flow.pendingChallenges.first(where: { $0.id == challengeId && $0.type.wire == challengeType }) else {
        throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(challengeType) (\(challengeId)) is not in the pending set")
      }
      return message(try await record.flow.respond(try answer.sdk(), to: challenge, additionalFields: additionalFields), record)
    }
  }

  func cancel(flow: String) async throws {
    let record = lock.withLock { flows[flow] }
    await record?.flow.cancel()
  }

  func disposeFlow(flow: String) throws {
    lock.withLock {
      if let record = flows.removeValue(forKey: flow) {
        for handle in record.handles { pendingCredentials.removeValue(forKey: handle) }
      }
    }
  }

  func completeWebFallback(flow: String) async throws -> CredentialsMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      guard let request = lock.withLock({ record.redirect }) else {
        throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "The flow has no redirect_to_web step")
      }
      let credentials = try await record.instance.webFallback().complete(request, flow: record.flow)
      lock.withLock { record.redirect = nil }
      return hold(credentials, record)
    }
  }

  func storeCredentials(instance: String, handle: String) async throws {
    try await bridgedAsync {
      guard let credentials = lock.withLock({ pendingCredentials.removeValue(forKey: handle) }) else {
        throw NativeAuthError(code: NativeAuthError.Code.credentialsNotFound, description: "Unknown or already stored credentials")
      }
      try await self.instance(instance).credentialsManager().store(credentials)
    }
  }

  func storedCredentials(instance: String) async throws -> CredentialsMessage? {
    try await bridgedAsync {
      try await self.instance(instance).credentialsManager().stored().map { Self.message($0, handle: "") }
    }
  }

  func credentials(instance: String, minTtlSeconds: Int64) async throws -> CredentialsMessage {
    try await bridgedAsync {
      try await rememberingTokenChallenge(instance) {
        Self.message(try await self.instance(instance).credentialsManager().credentials(minTTL: TimeInterval(minTtlSeconds)), handle: "")
      }
    }
  }

  func hasValidCredentials(instance: String, minTtlSeconds: Int64) async throws -> Bool {
    try await bridgedAsync { try await self.instance(instance).credentialsManager().hasValid(minTTL: TimeInterval(minTtlSeconds)) }
  }

  func logout(instance: String) async throws {
    try await bridgedAsync { try await self.instance(instance).credentialsManager().logout() }
  }

  func clearCredentials(instance: String) async throws {
    try await bridgedAsync { try await self.instance(instance).credentialsManager().clear() }
  }

  func resourceRequestHeaders(instance: String, method: String, url: String) async throws -> [String: String] {
    try await bridgedAsync {
      let kc = try self.instance(instance)
      guard let target = URL(string: url) else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "Not a URL: \(url)")
      }
      return try await rememberingTokenChallenge(instance) {
        try await kc.resourceRequestHeaders(for: kc.credentialsManager().credentials(), method: method, url: target)
      }
    }
  }

  func dpopKeyThumbprint(instance: String) async throws -> String? {
    try await bridgedAsync { try await self.instance(instance).dpopKeyThumbprint() }
  }

  func metadataJson(instance: String, forceRefresh: Bool) async throws -> String {
    try await bridgedAsync { Self.json(try await self.instance(instance).metadata(forceRefresh: forceRefresh).raw ?? .object([:])) }
  }

  // MARK: - Ceremonies that answer a challenge natively

  func usePasskey(flow: String, challengeId: String, preferImmediatelyAvailableCredentials: Bool) async throws -> FlowStepMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      let challenge = try await pending(record, challengeId, .passkey)
      guard let params = challenge.passkeyParams else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "passkey challenge without usable params")
      }
      let assertion = try await record.instance.passkeys().assert(params, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
      return message(try await record.flow.respond(.passkey(assertion), to: challenge), record)
    }
  }

  func registerPasskey(flow: String, challengeId: String, label: String?) async throws -> FlowStepMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      let challenge = try await pending(record, challengeId, .passkeyRegistration)
      guard let params = challenge.passkeyRegistrationParams else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "passkey_registration challenge without usable params")
      }
      let attestation = try await record.instance.passkeys().register(params)
      return message(try await record.flow.respond(.passkeyRegistration(attestation, label: label), to: challenge), record)
    }
  }

  func enrollPush(flow: String, challengeId: String, deviceLabel: String, pushProviderType: String, pushProviderId: String?) async throws -> FlowStepMessage {
    try await bridgedAsync {
      let record = try self.flow(flow)
      let challenge = try await pending(record, challengeId, .pushEnrollment)
      guard let params = challenge.pushEnrollmentParams else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "push_enrollment challenge without params")
      }
      let push = record.instance.push()
      let prepared = try await push.prepareEnrollment(for: params, deviceLabel: deviceLabel, pushProviderType: pushProviderType, pushProviderId: pushProviderId)
      let step = try await record.flow.respond(prepared.answer, to: challenge)
      // Kept only once the server moved on from the challenge (the iOS and Android UI models do the same).
      if !(step.challenges ?? []).contains(where: { $0.type == .pushEnrollment && $0.error != nil }) { try push.commit(prepared) }
      return message(step, record)
    }
  }

  // MARK: - Passkeys and passwords outside a flow

  func registerNewPasskey(instance: String, label: String?) async throws -> RegisteredPasskeyMessage {
    try await bridgedAsync {
      let kc = try self.instance(instance)
      return try await rememberingTokenChallenge(instance) {
        let registered = try await kc.passkeys().registerNewPasskey(label: label, credentials: kc.credentialsManager().credentials())
        return RegisteredPasskeyMessage(credentialId: registered.credentialId, label: registered.label)
      }
    }
  }

  func pickSavedPassword(instance: String) async throws -> SavedPasswordMessage {
    try await bridgedAsync {
      let saved = try await self.instance(instance).pickSavedPassword()
      return SavedPasswordMessage(username: saved.username, password: saved.password)
    }
  }

  /// iOS offers to save a typed password through AutoFill (the read-only username field and the
  /// `.password` content type of the default screens); there is no SDK call.
  func savePassword(instance: String, username: String, password: String) async throws {
    _ = try bridged { try self.instance(instance) }
  }

  // MARK: - Push

  func pushEnrollment(instance: String) async throws -> PushEnrollmentMessage? {
    try await bridgedAsync { try self.instance(instance).push().enrollment.map(Self.message) }
  }

  func pushEnroll(instance: String, deviceLabel: String, pushProviderType: String, pushProviderId: String?) async throws -> PushEnrollmentMessage {
    try await bridgedAsync {
      Self.message(try await self.instance(instance).push().enroll(deviceLabel: deviceLabel, pushProviderType: pushProviderType, pushProviderId: pushProviderId))
    }
  }

  func pushForgetEnrollment(instance: String) async throws {
    try await bridgedAsync { try self.instance(instance).push().forgetEnrollment() }
  }

  func pushPendingApprovals(instance: String) async throws -> [PendingApprovalMessage] {
    try await bridgedAsync {
      try await self.instance(instance).push().pendingApprovals().map { PendingApprovalMessage(cid: $0.cid, rawJson: Self.json($0.raw)) }
    }
  }

  func pushRespond(instance: String, cid: String, approve: Bool, userVerification: String?) async throws -> String {
    try await bridgedAsync {
      try await self.instance(instance).push().respond(cid: cid, approve ? .approve(userVerification: userVerification) : .deny)
    }
  }

  func pushHandleMessage(instance: String, data: [String: String]) async throws -> PushNotificationMessage? {
    try await bridgedAsync {
      let userInfo = Dictionary(uniqueKeysWithValues: data.map { (AnyHashable($0.key), $0.value as Any) })
      return try self.instance(instance).push().handleNotification(userInfo).map {
        PushNotificationMessage(cid: $0.cid, credentialId: $0.credentialId, expiresAtMillis: $0.expiresAt.map(Self.millis))
      }
    }
  }

  func pushUpdateProvider(instance: String, type: String, id: String) async throws {
    try await bridgedAsync { try await self.instance(instance).push().updatePushProvider(type: type, id: id) }
  }

  func pushRotateKey(instance: String) async throws {
    try await bridgedAsync { try await self.instance(instance).push().rotateKey() }
  }

  func pushLockout(instance: String) async throws {
    try await bridgedAsync { try await self.instance(instance).push().lockout() }
  }

  // MARK: - Helpers

  /// Keeps an error that carries an `auth_session` for `continueAfterTokenChallenge`.
  private func rememberingTokenChallenge<T>(_ instance: String, _ body: () async throws -> T) async throws -> T {
    do {
      return try await body()
    } catch let error as NativeAuthError {
      if error.authSession != nil { lock.withLock { tokenChallenges[instance] = error } }
      throw error
    }
  }

  private func pending(_ record: FlowRecord, _ challengeId: String, _ type: ChallengeType) async throws -> Challenge {
    guard let challenge = await record.flow.pendingChallenges.first(where: { $0.id == challengeId && $0.type == type }) else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(type.wire) (\(challengeId)) is not in the pending set")
    }
    return challenge
  }

  private static func message(_ enrollment: PushEnrollment) -> PushEnrollmentMessage {
    PushEnrollmentMessage(
      credentialId: enrollment.credentialId, deviceId: enrollment.deviceId, userId: enrollment.userId, username: enrollment.username,
      deviceLabel: enrollment.deviceLabel, pushProviderType: enrollment.pushProviderType, pushProviderId: enrollment.pushProviderId,
      deviceApiBase: enrollment.deviceApiBase.absoluteString, keyThumbprint: enrollment.keyThumbprint, enrolledAtMillis: millis(enrollment.enrolledAt))
  }

  private func instance(_ handle: String) throws -> KeycloakNative {
    guard let kc = lock.withLock({ instances[handle] }) else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Unknown KeycloakNative instance; call configure first")
    }
    return kc
  }

  private func flow(_ handle: String) throws -> FlowRecord {
    guard let record = lock.withLock({ flows[handle] }) else { throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Unknown or disposed flow") }
    return record
  }

  private func register(_ kc: KeycloakNative, _ flow: NativeLoginFlow) -> String {
    let handle = UUID().uuidString
    lock.withLock { flows[handle] = FlowRecord(instance: kc, flow: flow) }
    return handle
  }

  private func message(_ step: FlowStep, _ record: FlowRecord) -> FlowStepMessage {
    switch step {
    case .challenges(let challenges, let context):
      return FlowStepMessage(kind: .challenges, challenges: challenges.map(Self.message), contextJson: Self.json(context.raw))
    case .authorized(let credentials):
      return FlowStepMessage(kind: .authorized, challenges: [], credentials: hold(credentials, record))
    case .redirectToWeb(let request):
      lock.withLock { record.redirect = request }
      return FlowStepMessage(
        kind: .redirectToWeb, challenges: [],
        redirectToWeb: RedirectToWebMessage(
          redirectUri: request.redirectUri, expiresIn: request.expiresIn.map(Int64.init), state: request.state, reason: request.reason,
          errorDescription: request.errorDescription, rawJson: Self.json(request.raw)))
    }
  }

  private func hold(_ credentials: Credentials, _ record: FlowRecord) -> CredentialsMessage {
    let handle = UUID().uuidString
    lock.withLock {
      pendingCredentials[handle] = credentials
      record.handles.insert(handle)
    }
    return Self.message(credentials, handle: handle)
  }

  private static func message(_ challenge: Challenge) -> ChallengeMessage {
    ChallengeMessage(
      id: challenge.id, type: challenge.type.wire, label: challenge.label, required: challenge.required, errorCode: challenge.error?.code,
      errorMessage: challenge.error?.message, hasRetry: challenge.retry != nil, retryRemaining: challenge.retry?.remaining.map(Int64.init),
      skippable: challenge.isSkippable, paramsJson: json(challenge.params))
  }

  /// Dart's `DateTime` ends at 8.64e15 ms; offline tokens carry `Date.distantFuture`, which is earlier, so no clamp is needed.
  fileprivate static func millis(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded(.down)) }

  private static func message(_ credentials: Credentials, handle: String) -> CredentialsMessage {
    CredentialsMessage(
      handle: handle, accessToken: credentials.accessToken, tokenType: credentials.tokenType, idToken: credentials.idToken, scope: credentials.scope,
      expiresAtMillis: millis(credentials.expiresAt), refreshExpiresAtMillis: credentials.refreshExpiresAt.map(millis),
      issuedAtMillis: millis(credentials.issuedAt), hasRefreshToken: credentials.refreshToken != nil)
  }

  private static func json(_ value: JSONValue) -> String {
    guard let data = try? JSONEncoder().encode(value) else { return "{}" }
    return String(decoding: data, as: UTF8.self)
  }
}

/// A `NativeAuthError` reaches Dart as a `PlatformException` with its code.
private func bridged<T>(_ body: () throws -> T) throws -> T {
  do {
    return try body()
  } catch let error as NativeAuthError {
    throw error.pigeonError
  }
}

private func bridgedAsync<T>(_ body: () async throws -> T) async throws -> T {
  do {
    return try await body()
  } catch let error as NativeAuthError {
    throw error.pigeonError
  }
}

extension NativeAuthError {
  var pigeonError: PigeonError {
    var detailsJson: String?
    if let details, let data = try? JSONEncoder().encode(details) { detailsJson = String(decoding: data, as: UTF8.self) }
    return PigeonError(
      code: code, message: errorDescription ?? code,
      details: [
        "statusCode": statusCode.map(Int64.init) as Any,
        "isNetworkError": isNetworkError,
        "isRetryable": isRetryable,
        "retryAfter": retryAfter as Any,
        "maxAge": maxAge.map(Int64.init) as Any,
        "detailsJson": detailsJson as Any,
      ])
  }
}

extension LoginParametersMessage {
  var sdk: LoginParameters {
    LoginParameters(
      scope: scope, acrValues: acrValues, loginHint: loginHint, prompt: prompt, maxAge: maxAge.map(Int.init), nonce: nonce, uiLocales: uiLocales,
      deviceName: deviceName, deviceId: deviceId, additionalParameters: additionalParameters, continuationParameters: continuationParameters)
  }
}

extension AnswerMessage {
  func sdk() throws -> ChallengeAnswer {
    func required(_ name: String, _ value: String?) throws -> String {
      guard let value else { throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "A \(kind) answer needs \(name)") }
      return value
    }
    switch kind {
    case .username: return .username(try required("value", value))
    case .password: return .password(try required("value", value))
    case .totp: return .totp(try required("value", value), credentialId: credentialId)
    case .otp: return .otp(try required("value", value))
    case .otpResend: return .otpResend
    case .updatePassword: return .updatePassword(try required("value", value), confirm: try required("confirm", confirm))
    case .verifyEmail: return .verifyEmail(code: try required("value", value))
    case .verifyEmailResend: return .verifyEmailResend
    case .terms: return .terms(accepted: accepted ?? false)
    case .recoveryCode: return .recoveryCode(try required("value", value))
    case .pushResend: return .pushResend
    case .pushPoll: return .pushPoll
    case .pushEnrollmentCheck: return .pushEnrollmentCheck
    case .pin: return .pin(try required("value", value))
    case .pinSetup: return .pinSetup(pin: try required("value", value), confirm: try required("confirm", confirm))
    case .skip: return .skip(ChallengeType(wire: try required("type", type)))
    case .custom:
      return .custom(type: ChallengeType(wire: try required("type", type)), fields: (fields ?? []).map { FormField($0.name, $0.value) })
    }
  }
}

/// Forwards the SDK's redacted flow log to Dart on the main thread.
private final class FlowLogForwarder: FlowObserver, @unchecked Sendable {
  private let instance: String
  private let api: KeycloakNativeFlutterApi

  init(instance: String, api: KeycloakNativeFlutterApi) {
    self.instance = instance
    self.api = api
  }

  func record(_ entry: FlowLogEntry) {
    let message = FlowLogMessage(
      id: entry.id.uuidString, timestampMillis: KeycloakNativePlugin.millis(entry.timestamp), method: entry.method, url: entry.url.absoluteString,
      requestHeaders: entry.requestHeaders, requestBody: entry.requestBody, statusCode: entry.statusCode.map(Int64.init),
      responseHeaders: entry.responseHeaders, responseBody: entry.responseBody, durationMilliseconds: Int64(entry.durationMilliseconds),
      errorCode: entry.errorCode)
    let instance = instance
    let api = api
    Task { @MainActor in try? await api.onFlowLog(instance: instance, entry: message) }
  }
}
