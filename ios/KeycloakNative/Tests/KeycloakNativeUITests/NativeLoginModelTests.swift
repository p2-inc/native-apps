import Foundation
import KeycloakNativeCore
import Testing
@testable import KeycloakNativeUI

/// Tests of the UI product itself (spec/05 §4, spec/14 D7): the model behind `NativeLoginView`
/// (which entry is shown, switching, submitting, cancelling, terminal errors) and the string
/// catalogue with its override chain. Views are not rendered; the model is what the screens bind to.
@Suite(.serialized) struct NativeLoginModelTests {
  static let issuer = URL(string: "https://idp.example.com/realms/demo")!

  static let metadata: JSONValue = [
    "protocol_version": "1",
    "authorization_challenge_endpoint": "https://idp.example.com/realms/demo/native-auth/challenge",
    "token_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/token",
    "passkey": ["rp_id": "idp.example.com"],
  ]

  static func set(_ challenges: [JSONValue], session: String = "s") -> JSONValue {
    ["error": "insufficient_authorization", "auth_session": .string(session), "expires_in": 500, "challenges": .array(challenges), "context": ["username": "alice"]]
  }

  static let passwordAndTotp: [JSONValue] = [
    ["type": "password", "id": "p", "required": false, "params": ["username_known": true]],
    ["type": "totp", "id": "t", "required": false, "params": ["digits": 6]],
  ]

  static func tokens() -> JSONValue {
    let claims = Data("{\"preferred_username\":\"alice\",\"acr\":\"1\"}".utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")
    let jwt = "eyJhbGciOiJub25lIn0.\(claims)."
    return ["access_token": .string(jwt), "token_type": "Bearer", "expires_in": 300, "refresh_token": "r", "id_token": .string(jwt), "scope": "openid"]
  }

  @MainActor
  final class Collector {
    var results: [NativeLoginResult] = []
  }

  @MainActor
  func makeModel(_ handlers: [(HTTPRequest) throws -> HTTPResponse], autoSelectPasskey: Bool = false) -> (NativeLoginModel, ScriptedTransport, Collector) {
    let transport = ScriptedTransport(handlers)
    var options = KeycloakNative.Options()
    options.transport = transport
    options.secureStore = InMemorySecureStore()
    options.dpop = .disabled
    options.logger = NoopLogger()
    let kc = KeycloakNative.configure(issuer: Self.issuer, clientId: "c", options: options)
    let collector = Collector()
    let model = NativeLoginModel(kc: kc, flow: kc.authentication().startLogin(), autoSelectPasskey: autoSelectPasskey) { collector.results.append($0) }
    return (model, transport, collector)
  }

  /// Waits for the model's background task to settle.
  @MainActor
  func settle(_ model: NativeLoginModel, until condition: @MainActor () -> Bool) async {
    for _ in 0..<200 {
      if condition() { return }
      try? await Task.sleep(for: .milliseconds(10))
    }
  }

  @MainActor
  func selected(_ model: NativeLoginModel) -> Challenge? {
    if case .challenge(_, _, let selected) = model.phase { return selected }
    return nil
  }

  @Test @MainActor func startShowsTheFirstSupportedEntryAndSwitchingKeepsTheSet() async throws {
    let (model, _, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set([["type": "x-vendor-foo", "id": "x", "required": false]] + Self.passwordAndTotp)) },
    ])
    await model.startIfNeeded()
    let first = try #require(selected(model))
    #expect(first.type == .password, "unknown types are skipped, the first supported entry is shown")
    guard case .challenge(let challenges, let context, _) = model.phase else { Issue.record("expected a challenge phase"); return }
    #expect(challenges.count == 3 && context.username == "alice")
    let presentation = ChallengePresentationContext(challenge: first, challenges: challenges, flowContext: context, isSubmitting: false, model: model)
    #expect(presentation.alternatives.map(\.id) == ["x", "t"])
    model.select(try #require(challenges.first { $0.type == .totp }))
    #expect(selected(model)?.type == .totp)
    #expect(DefaultChallengeChooser.title(for: first, strings: NativeLoginStrings()) == "Use your password")
  }

  @Test @MainActor func aFailedEntryIsShownAgainAndSuccessReportsCredentials() async throws {
    let (model, transport, collector) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.passwordAndTotp)) },
      { _ in
        // The TOTP was answered (checked on transport.sent below): wrong → the set comes back with
        // the error on the totp entry.
        return ScriptedTransport.json(403, Self.set([
          ["type": "password", "id": "p", "required": false, "params": ["username_known": true]],
          ["type": "totp", "id": "t", "required": false, "error": ["code": "invalid_credential", "message": "Invalid code"], "retry": ["remaining": 2], "params": ["digits": 6]],
        ], session: "s2"))
      },
      { _ in ScriptedTransport.json(200, ["authorization_code": "code", "auth_session": "post"]) },
      { _ in ScriptedTransport.json(200, Self.tokens()) },
    ])
    await model.startIfNeeded()
    let totp = try #require((model.phase.challenges ?? []).first { $0.type == .totp })
    model.select(totp)
    model.submit(.totp("000000"), to: totp)
    await settle(model) { self.selected(model)?.error != nil }
    let failed = try #require(selected(model))
    #expect(failed.type == .totp && failed.error?.code == "invalid_credential" && failed.retry?.remaining == 2, "the entry that failed is shown, not the first one")
    #expect(model.isSubmitting == false)
    #expect(transport.sent[2].formFields?.contains { $0.name == "totp" && $0.value == "000000" } == true)

    model.submit(.totp("123456"), to: failed)
    await settle(model) { !collector.results.isEmpty }
    guard case .authorized(let credentials)? = collector.results.first else { Issue.record("expected .authorized, got \(collector.results)"); return }
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(transport.sent.count == 5)
    if case .finished = model.phase {} else { Issue.record("expected .finished") }
  }

  @Test @MainActor func cancelSendsActionCancelAndReportsCancelled() async throws {
    let (model, transport, collector) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.passwordAndTotp)) },
      { _ in ScriptedTransport.json(400, ["error": "invalid_session", "error_description": "cancelled"]) },
    ])
    await model.startIfNeeded()
    model.cancel()
    await settle(model) { !collector.results.isEmpty }
    guard case .cancelled? = collector.results.first else { Issue.record("expected .cancelled, got \(collector.results)"); return }
    #expect(transport.sent.count == 3)
    #expect(transport.sent[2].formFields?.contains { $0.name == "action" && $0.value == "cancel" } == true)
  }

  @Test @MainActor func terminalErrorsEndTheViewAndTransientOnesKeepIt() async throws {
    let (model, _, collector) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.passwordAndTotp)) },
      { _ in throw NativeAuthError(code: NativeAuthError.Code.networkError, description: "offline", isNetworkError: true, isRetryable: true) },
      { _ in ScriptedTransport.json(403, ["error": "access_denied", "error_description": "Account temporarily locked"]) },
    ])
    await model.startIfNeeded()
    let password = try #require(selected(model))
    model.submit(.password("x"), to: password)
    await settle(model) { model.message != nil }
    #expect(model.message == "offline" && collector.results.isEmpty, "a network error is shown inline, the set stays")
    #expect(selected(model)?.type == .password)

    model.submit(.password("x"), to: password)
    await settle(model) { !collector.results.isEmpty }
    guard case .failed(let error)? = collector.results.first else { Issue.record("expected .failed, got \(collector.results)"); return }
    #expect(error.code == NativeAuthError.Code.accessDenied)
  }

  @Test @MainActor func redirectToWebBecomesItsOwnPhase() async throws {
    let (model, _, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, ["error": "redirect_to_web", "request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60, "redirect_uri": "demoapp://auth/callback", "state": "st", "reason": "required_action:UPDATE_PROFILE"]) },
    ])
    await model.startIfNeeded()
    guard case .redirectToWeb(let request) = model.phase else { Issue.record("expected .redirectToWeb, got \(model.phase)"); return }
    #expect(request.reason == "required_action:UPDATE_PROFILE" && request.callbackScheme == "demoapp")
  }
}

@Suite struct NativeLoginStringsTests {
  @Test func packageCatalogueResolvesEnglishAndGerman() throws {
    let english = NativeLoginStrings()
    #expect(english("Cancel") == "Cancel")
    #expect(english("%lld attempts left", 3) == "3 attempts left")
    #expect(english("We sent a %lld-digit code to %@.", 6, "a***@example.com") == "We sent a 6-digit code to a***@example.com.")
    // The German table shipped in Localizable.xcstrings, read directly from the package bundle.
    let de = try #require(Bundle.module.path(forResource: "Localizable", ofType: "strings", inDirectory: nil, forLocalization: "de"))
    let german = try #require(Bundle(path: (de as NSString).deletingLastPathComponent))
    #expect(german.localizedString(forKey: "Cancel", value: nil, table: nil) == "Abbrechen")
    #expect(NativeLoginStrings(override: german)("Try another way") == "Anderen Weg versuchen")
  }

  @Test func overrideBundleWinsAndMissingKeysFallBack() throws {
    let dir = FileManager.default.temporaryDirectory.appending(path: "kc-strings-\(UUID().uuidString)/Override.bundle/en.lproj")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try "\"Cancel\" = \"Abort\";\n\"Sign in\" = \"Let me in\";\n".write(to: dir.appending(path: "Localizable.strings"), atomically: true, encoding: .utf8)
    let bundle = try #require(Bundle(url: dir.deletingLastPathComponent()))
    let strings = NativeLoginStrings(override: bundle)
    #expect(strings("Cancel") == "Abort" && strings("Sign in") == "Let me in")
    #expect(strings("Continue") == "Continue", "keys the override does not define keep the package's text")
    #expect(strings("Resend code in %lld s", 7) == "Resend code in 7 s")
  }
}

// MARK: - Support (the Core test target's helpers are not visible from here)

final class ScriptedTransport: Transport, @unchecked Sendable {
  private let lock = NSLock()
  private var handlers: [(HTTPRequest) throws -> HTTPResponse]
  private(set) var sent: [HTTPRequest] = []

  init(_ handlers: [(HTTPRequest) throws -> HTTPResponse]) {
    self.handlers = handlers
  }

  func send(_ request: HTTPRequest) async throws -> HTTPResponse {
    let handler: ((HTTPRequest) throws -> HTTPResponse)? = lock.withLock {
      sent.append(request)
      return handlers.isEmpty ? nil : handlers.removeFirst()
    }
    guard let handler else { throw NativeAuthError(code: "scripted_transport_exhausted", description: "no handler for \(request.method) \(request.url)") }
    return try handler(request)
  }

  static func json(_ status: Int, _ json: JSONValue) -> HTTPResponse {
    HTTPResponse(statusCode: status, headers: ["Content-Type": "application/json"], body: Data(json.serialized().utf8))
  }
}

extension NativeLoginModel.Phase {
  var challenges: [Challenge]? {
    if case .challenge(let challenges, _, _) = self { return challenges }
    return nil
  }
}
