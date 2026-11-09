import Foundation
import KeycloakNativeCore

/// The Swift half of the TurboModule (spec/19 §4–§5): `KeycloakNativeModule.mm` conforms to the
/// Codegen protocol and forwards every call here. Each JavaScript `KeycloakNative` is one
/// `KeycloakNative` instance of `KeycloakNativeCore` with its Keychain store, Secure Enclave DPoP key,
/// passkey sheets and `ASWebAuthenticationSession` (anchored on the key window); each flow stays here
/// with its PKCE verifier and pending challenges, and JavaScript holds its id.
///
/// Async SDK calls run in a `Task` and settle the promise; errors reject with the SDK's
/// `NativeAuthError` code.
@objc(KeycloakNativeBridge)
public final class KeycloakNativeBridge: NSObject {
  public typealias Resolve = (Any?) -> Void
  public typealias Reject = (String?, String?, NSError?) -> Void

  private let registry = Registry()

  @objc public func configure(_ instanceId: String, config: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let c = try BridgeJSON.config(config)
      var options = KeycloakNative.Options()
      options.dpop = c.dpop
      options.allowRpIdMismatch = c.allowRpIdMismatch
      options.ephemeralWebSession = c.ephemeralWebSession
      if let ttl = c.metadataCacheTTL { options.metadataCacheTTL = ttl }
      if let service = c.storageNamespace { options.keychainService = service }
      options.keychainAccessGroup = c.keychainAccessGroup
      await registry.setInstance(KeycloakNative.configure(issuer: c.issuer, clientId: c.clientId, options: options), id: instanceId)
      return nil
    }
  }

  @objc public func createFlow(_ instanceId: String, parameters: String, stepUp: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      let loginParameters = try BridgeJSON.loginParameters(parameters)
      let flow = stepUp ? try await kc.authentication().stepUp(loginParameters) : kc.authentication().startLogin(loginParameters)
      return await registry.addFlow(FlowHandle(kc: kc, flow: flow))
    }
  }

  @objc public func start(_ flowId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let handle = try await registry.flow(flowId)
      return try await handle.encode(handle.flow.start())
    }
  }

  @objc public func respond(
    _ flowId: String, challengeId: String, challengeType: String, answer: String, additionalFields: String,
    resolve: @escaping Resolve, reject: @escaping Reject
  ) {
    settle(resolve, reject) { [registry] in
      let handle = try await registry.flow(flowId)
      let type = ChallengeType(wire: challengeType)
      guard let challenge = await handle.flow.pendingChallenges.first(where: { $0.id == challengeId && $0.type == type }) else {
        throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Challenge \(challengeType) is not in the pending set")
      }
      let step = try await handle.flow.respond(
        try BridgeJSON.answer(answer, type: type), to: challenge, additionalFields: try BridgeJSON.stringMap(additionalFields))
      return try await handle.encode(step)
    }
  }

  @objc public func cancel(_ flowId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      if let handle = try? await registry.flow(flowId) { await handle.flow.cancel() }
      return nil
    }
  }

  @objc public func completeWebFallback(_ flowId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let handle = try await registry.flow(flowId)
      guard let request = await handle.redirect else {
        throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "This flow did not end in redirectToWeb")
      }
      let credentials = try await handle.kc.webFallback().complete(request, flow: handle.flow)
      await handle.setCredentials(credentials)
      return try BridgeJSON.string(BridgeJSON.credentials(credentials))
    }
  }

  @objc public func storeCredentials(_ flowId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let handle = try await registry.flow(flowId)
      guard let credentials = await handle.credentials else {
        throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "This flow has not produced credentials")
      }
      try await handle.kc.credentialsManager().store(credentials)
      return nil
    }
  }

  @objc public func releaseFlow(_ flowId: String) {
    Task { [registry] in await registry.removeFlow(flowId) }
  }

  @objc public func credentials(_ instanceId: String, minTtlSeconds: Double, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      return try BridgeJSON.string(BridgeJSON.credentials(try await kc.credentialsManager().credentials(minTTL: minTtlSeconds)))
    }
  }

  @objc public func storedCredentials(_ instanceId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      guard let stored = try await kc.credentialsManager().stored() else { return nil }
      return try BridgeJSON.string(BridgeJSON.credentials(stored))
    }
  }

  @objc public func hasValidCredentials(_ instanceId: String, minTtlSeconds: Double, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      return NSNumber(value: try await kc.credentialsManager().hasValid(minTTL: minTtlSeconds))
    }
  }

  @objc public func resourceRequestHeaders(
    _ instanceId: String, method: String, url: String, resolve: @escaping Resolve, reject: @escaping Reject
  ) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      guard let target = URL(string: url) else {
        throw NativeAuthError(code: NativeAuthError.Code.invalidParameter, description: "Not a URL: \(url)")
      }
      let credentials = try await kc.credentialsManager().credentials()
      let headers = try await kc.resourceRequestHeaders(for: credentials, method: method, url: target)
      return try BridgeJSON.string(headers)
    }
  }

  @objc public func logout(_ instanceId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let kc = try await registry.instance(instanceId)
      await kc.credentialsManager().logout()
      return nil
    }
  }

  @objc public func clearCredentials(_ instanceId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      try await registry.instance(instanceId).credentialsManager().clear()
      return nil
    }
  }

  @objc public func metadata(_ instanceId: String, forceRefresh: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      let metadata = try await registry.instance(instanceId).metadata(forceRefresh: forceRefresh)
      return try metadata.raw.map(BridgeJSON.string) ?? "{}"
    }
  }

  @objc public func dpopKeyThumbprint(_ instanceId: String, resolve: @escaping Resolve, reject: @escaping Reject) {
    settle(resolve, reject) { [registry] in
      try await registry.instance(instanceId).dpopKeyThumbprint()
    }
  }

  // MARK: -

  /// Runs `body` in a task and settles the promise with its result or the SDK's error code.
  private func settle(_ resolve: @escaping Resolve, _ reject: @escaping Reject, _ body: @escaping @Sendable () async throws -> Any?) {
    let callbacks = Callbacks(resolve: resolve, reject: reject)
    Task {
      do {
        callbacks.resolve(try await body())
      } catch let error as NativeAuthError {
        var info: [String: Any] = ["isNetworkError": error.isNetworkError, "isRetryable": error.isRetryable]
        if let statusCode = error.statusCode { info["statusCode"] = statusCode }
        if let retryAfter = error.retryAfter { info["retryAfter"] = retryAfter }
        callbacks.reject(
          error.code, error.errorDescription ?? error.code, NSError(domain: "io.phasetwo.keycloak.native", code: error.statusCode ?? 0, userInfo: info))
      } catch {
        callbacks.reject(NativeAuthError.Code.invalidResponse, String(describing: error), error as NSError)
      }
    }
  }
}

/// The promise blocks, which React Native calls from any thread.
private final class Callbacks: @unchecked Sendable {
  let resolve: KeycloakNativeBridge.Resolve
  let reject: KeycloakNativeBridge.Reject

  init(resolve: @escaping KeycloakNativeBridge.Resolve, reject: @escaping KeycloakNativeBridge.Reject) {
    self.resolve = resolve
    self.reject = reject
  }
}

/// A flow and what it ended with, for the browser fallback and `storeCredentials`.
private actor FlowHandle {
  nonisolated let kc: KeycloakNative
  nonisolated let flow: NativeLoginFlow
  private(set) var redirect: RedirectToWebRequest?
  private(set) var credentials: Credentials?

  init(kc: KeycloakNative, flow: NativeLoginFlow) {
    self.kc = kc
    self.flow = flow
  }

  func setCredentials(_ credentials: Credentials) {
    self.credentials = credentials
  }

  func encode(_ step: FlowStep) async throws -> String {
    switch step {
    case .authorized(let credentials): self.credentials = credentials
    case .redirectToWeb(let request): redirect = request
    case .challenges: break
    }
    return try BridgeJSON.string(BridgeJSON.step(step, expiresIn: await flow.expiresIn))
  }
}

private actor Registry {
  private var instances: [String: KeycloakNative] = [:]
  private var flows: [String: FlowHandle] = [:]

  func setInstance(_ kc: KeycloakNative, id: String) {
    instances[id] = kc
  }

  func instance(_ id: String) throws -> KeycloakNative {
    guard let kc = instances[id] else {
      throw NativeAuthError(code: BridgeJSON.notConfigured, description: "KeycloakNative instance \(id) is not configured")
    }
    return kc
  }

  func addFlow(_ handle: FlowHandle) -> String {
    let id = UUID().uuidString
    flows[id] = handle
    return id
  }

  func flow(_ id: String) throws -> FlowHandle {
    guard let handle = flows[id] else {
      throw NativeAuthError(code: NativeAuthError.Code.flowState, description: "Unknown or released flow \(id)")
    }
    return handle
  }

  func removeFlow(_ id: String) {
    flows[id] = nil
  }
}
