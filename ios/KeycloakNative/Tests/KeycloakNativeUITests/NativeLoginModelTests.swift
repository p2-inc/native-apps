import Foundation
import KeycloakNativeCore
import KeycloakNativePush
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
  func makeModel(_ handlers: [(HTTPRequest) throws -> HTTPResponse], autoSelectPasskey: Bool = false, dpop: DPoPMode = .disabled, savedPasswords: (any SavedPasswordPlatform)? = nil) -> (NativeLoginModel, ScriptedTransport, Collector, KeycloakNative) {
    let transport = ScriptedTransport(handlers)
    var options = KeycloakNative.Options()
    options.savedPasswordPlatform = savedPasswords
    options.transport = transport
    options.secureStore = InMemorySecureStore()
    options.dpop = dpop
    options.logger = NoopLogger()
    let kc = KeycloakNative.configure(issuer: Self.issuer, clientId: "c", options: options)
    let collector = Collector()
    let model = NativeLoginModel(kc: kc, flow: kc.authentication().startLogin(), autoSelectPasskey: autoSelectPasskey) { collector.results.append($0) }
    return (model, transport, collector, kc)
  }

  @MainActor
  func makeModel(_ handlers: [(HTTPRequest) throws -> HTTPResponse], autoSelectPasskey: Bool = false) -> (NativeLoginModel, ScriptedTransport, Collector) {
    let (model, transport, collector, _) = makeModel(handlers, autoSelectPasskey: autoSelectPasskey, dpop: .disabled)
    return (model, transport, collector)
  }

  /// A `push_enrollment` set (spec/03 §4.15) with an unsigned enrolment token.
  static func pushEnrollmentSet(error: String? = nil) -> JSONValue {
    let claims = Base64URL.encode(Data("{\"sub\":\"u1\",\"username\":\"judy\",\"enrollmentId\":\"e1\",\"nonce\":\"n1\",\"exp\":1900000000}".utf8))
    var descriptor: [String: JSONValue] = [
      "type": "push_enrollment", "id": "native-push-enroll", "required": true,
      "params": ["enrollment_token": .string("eyJhbGciOiJub25lIn0.\(claims)."), "expires_in": 240, "device_api_base": "https://idp.example.com/realms/demo/push-mfa", "user_id": "u1"],
    ]
    if let error { descriptor["error"] = ["code": .string(error)] }
    return set([.object(descriptor)])
  }

  @Test @MainActor func pushEnrolmentIsCommittedOnlyWhenTheServerMovesOn() async throws {
    // First attempt: the server re-challenges with an error → nothing stored; second: tokens → stored.
    let (model, transport, collector, kc) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.pushEnrollmentSet()) },
      { _ in ScriptedTransport.json(403, Self.pushEnrollmentSet(error: "invalid_credential")) },
      { _ in ScriptedTransport.json(200, ["authorization_code": "code", "auth_session": "post"]) },
      { _ in ScriptedTransport.json(200, Self.tokens()) },
    ], dpop: .software)
    await model.startIfNeeded()
    let challenge = try #require(selected(model))
    #expect(challenge.type == .pushEnrollment)
    let presentation = ChallengePresentationContext(challenge: challenge, challenges: [challenge], flowContext: .empty, isSubmitting: false, model: model)
    presentation.enrolPush(deviceLabel: "Judy's phone")
    await settle(model) { self.selected(model)?.error != nil }
    #expect(selected(model)?.error?.code == "invalid_credential" && !kc.push().isEnrolled)
    let again = try #require(selected(model))
    ChallengePresentationContext(challenge: again, challenges: [again], flowContext: .empty, isSubmitting: false, model: model).enrolPush(deviceLabel: "Judy's phone")
    await settle(model) { !collector.results.isEmpty }
    guard case .authorized? = collector.results.first else { Issue.record("expected authorized"); return }
    let enrollment = try #require(kc.push().enrollment)
    #expect(enrollment.userId == "u1" && enrollment.username == "judy" && enrollment.deviceLabel == "Judy's phone" && enrollment.pushProviderType == "none")
    #expect(enrollment.deviceApiBase.absoluteString == "https://idp.example.com/realms/demo/push-mfa")
    let form = transport.sent[2].formFields ?? []
    #expect(form.contains { $0.name == "challenge_type" && $0.value == "push_enrollment" } && form.contains { $0.name == "token" })
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

  /// Returns `result` from the saved-password sheet.
  struct StubSavedPasswords: SavedPasswordPlatform {
    let result: Result<SavedPassword, NativeAuthError>
    func pick() async throws -> SavedPassword { try result.get() }
  }

  static let usernameSet: [JSONValue] = [["type": "username", "id": "u", "required": true, "params": ["allow_email": true]]]

  @Test @MainActor func aSavedPasswordAnswersTheUsernameAndThenThePassword() async throws {
    let (model, transport, collector, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.usernameSet)) },
      { _ in ScriptedTransport.json(403, Self.set(Self.passwordAndTotp, session: "s2")) },
      { _ in ScriptedTransport.json(200, ["authorization_code": "code", "auth_session": "post"]) },
      { _ in ScriptedTransport.json(200, Self.tokens()) },
    ], savedPasswords: StubSavedPasswords(result: .success(SavedPassword(username: "alice", password: "s3cret"))))
    await model.startIfNeeded()
    let username = try #require(selected(model))
    let presentation = ChallengePresentationContext(challenge: username, challenges: [username], flowContext: .empty, isSubmitting: false, model: model)
    #expect(presentation.offersSavedPasswords)
    presentation.useSavedPassword()
    await settle(model) { !collector.results.isEmpty }
    guard case .authorized? = collector.results.first else { Issue.record("expected authorized, got \(collector.results)"); return }
    #expect(transport.sent[2].formFields?.contains { $0.name == "username" && $0.value == "alice" } == true)
    #expect(transport.sent[3].formFields?.contains { $0.name == "password" && $0.value == "s3cret" } == true, "the picked password answers the password challenge without a tap")
  }

  @Test @MainActor func closingTheSavedPasswordSheetKeepsTheUsernameScreen() async throws {
    let (model, transport, collector, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.usernameSet)) },
    ], savedPasswords: StubSavedPasswords(result: .failure(NativeAuthError(code: NativeAuthError.Code.savedPasswordCancelled, description: "closed"))))
    await model.startIfNeeded()
    let username = try #require(selected(model))
    ChallengePresentationContext(challenge: username, challenges: [username], flowContext: .empty, isSubmitting: false, model: model).useSavedPassword()
    await settle(model) { !model.isSubmitting }
    try? await Task.sleep(for: .milliseconds(50))
    #expect(selected(model)?.type == .username && model.message == nil && collector.results.isEmpty)
    #expect(transport.sent.count == 2, "nothing is sent when the sheet is closed")
  }

  @Test @MainActor func aSavedPasswordIsDroppedWhenNoPasswordChallengeFollows() async throws {
    let (model, transport, _, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.set(Self.usernameSet)) },
      { _ in ScriptedTransport.json(403, Self.set([["type": "totp", "id": "t", "required": true, "params": ["digits": 6]]], session: "s2")) },
    ], savedPasswords: StubSavedPasswords(result: .success(SavedPassword(username: "alice", password: "s3cret"))))
    await model.startIfNeeded()
    let username = try #require(selected(model))
    ChallengePresentationContext(challenge: username, challenges: [username], flowContext: .empty, isSubmitting: false, model: model).useSavedPassword()
    await settle(model) { self.selected(model)?.type == .totp }
    try? await Task.sleep(for: .milliseconds(50))
    #expect(selected(model)?.type == .totp && transport.sent.count == 3, "the password is not sent to a set without a password challenge")
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

  static func pinSet(_ type: String = "pin", error: String? = nil, remaining: Int? = nil) -> JSONValue {
    var descriptor: [String: JSONValue] = ["type": .string(type), "id": type == "pin" ? "pin-exec" : "native-configure-pin", "required": true, "params": ["length": 6]]
    if let error { descriptor["error"] = ["code": .string(error)] }
    if let remaining { descriptor["retry"] = ["remaining": .number(Double(remaining))] }
    return set([.object(descriptor)])
  }

  @Test @MainActor func aWrongPinStaysOnThePinAndALockedPinOnlyOffersCancel() async throws {
    let (model, transport, collector) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.pinSet()) },
      { _ in ScriptedTransport.json(403, Self.pinSet(error: "invalid_credential", remaining: 1)) },
      { _ in ScriptedTransport.json(403, Self.pinSet(error: "credential_locked", remaining: 0)) },
      { _ in ScriptedTransport.json(400, ["error": "invalid_session", "error_description": "auth_session cancelled"]) },
    ])
    await model.startIfNeeded()
    let pin = try #require(selected(model))
    #expect(pin.type == .pin && pin.pinParams?.length == 6)
    model.submit(.pin("000000"), to: pin)
    await settle(model) { self.selected(model)?.error != nil }
    let wrong = try #require(selected(model))
    #expect(wrong.error?.code == "invalid_credential" && wrong.retry?.remaining == 1 && !wrong.isLocked)
    #expect(PinScreen.errorText(wrong.error, NativeLoginStrings()) == "Incorrect PIN")
    model.submit(.pin("111111"), to: wrong)
    await settle(model) { self.selected(model)?.isLocked == true }
    let locked = try #require(selected(model))
    #expect(locked.isLocked && locked.retry?.remaining == 0)
    model.cancel()
    await settle(model) { !collector.results.isEmpty }
    guard case .cancelled? = collector.results.first else { Issue.record("expected .cancelled, got \(collector.results)"); return }
    let pins = transport.sent.compactMap(\.formFields).flatMap { $0 }.filter { $0.name == "pin" }.map(\.value)
    #expect(pins == ["000000", "111111"])
  }

  @Test @MainActor func setPinErrorsAreLocalized() async throws {
    let (model, transport, _) = makeModel([
      { _ in ScriptedTransport.json(200, Self.metadata) },
      { _ in ScriptedTransport.json(403, Self.pinSet("pin_setup")) },
      { _ in ScriptedTransport.json(403, Self.pinSet("pin_setup", error: "weak_pin")) },
    ])
    await model.startIfNeeded()
    let setup = try #require(selected(model))
    #expect(setup.type == .pinSetup && setup.pinSetupParams?.length == 6)
    model.submit(.pinSetup(pin: "123456", confirm: "123456"), to: setup)
    await settle(model) { self.selected(model)?.error != nil }
    #expect(selected(model)?.error?.code == "weak_pin")
    let form = transport.sent[2].formFields?.map { "\($0.name)=\($0.value)" } ?? []
    #expect(form.contains("pin=123456") && form.contains("pin_confirm=123456") && form.contains("challenge_type=pin_setup"))
    let l = NativeLoginStrings()
    #expect(PinSetupScreen.errorText(ChallengeError(code: "pin_mismatch", message: nil), length: 6, l) == "The PINs do not match. Try again.")
    #expect(PinSetupScreen.errorText(ChallengeError(code: "weak_pin", message: nil), length: 6, l) == "This PIN is too easy to guess. Choose another one.")
    #expect(PinSetupScreen.errorText(ChallengeError(code: "invalid_format", message: nil), length: 6, l) == "The PIN must be exactly 6 digits.")
    #expect(PinSetupScreen.errorText(ChallengeError(code: "x-other", message: "m"), length: 6, l) == nil, "unknown codes keep the server's message")
    #expect(DefaultChallengeChooser.title(for: Challenge(id: "p", type: .pin), strings: l) == "Use your PIN")
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
    // The German translations of Localizable.xcstrings, whether the build compiled the catalogue
    // into de.lproj (Xcode, default build system) or copied the file (CLT-only native build).
    let german = NativeLoginStrings(preferredLanguages: ["de"])
    #expect(german("Cancel") == "Abbrechen")
    #expect(german("Try another way") == "Anderen Weg versuchen")
    #expect(german("%lld attempts left", 3) == "Noch 3 Versuche")
    #expect(german("XXXX-XXXX-XXXX") == "XXXX-XXXX-XXXX", "untranslated keys stay as they are")
    #expect(NativeLoginStrings(preferredLanguages: ["fr", "de"])("Accept") == "Akzeptieren", "the first available language wins")
    #expect(NativeLoginStrings(preferredLanguages: ["fr"])("Accept") == "Accept", "unknown languages fall back to the source text")
  }

  @Test func pinStringsAreTranslated() throws {
    let german = NativeLoginStrings(preferredLanguages: ["de"])
    #expect(german("Enter your PIN") == "PIN eingeben")
    #expect(german("Enter your %lld-digit PIN.", 4) == "Geben Sie Ihre 4-stellige PIN ein.")
    #expect(german("PIN locked") == "PIN gesperrt")
    #expect(german("The PIN must be exactly %lld digits.", 6) == "Die PIN muss genau 6 Ziffern haben.")
    #expect(german("%lld of %lld digits entered", 2, 4) == "2 von 4 Ziffern eingegeben")
    #expect(PinSetupScreen.errorText(ChallengeError(code: "weak_pin", message: nil), length: 4, german) == "Diese PIN ist zu leicht zu erraten. Wählen Sie eine andere.")
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
