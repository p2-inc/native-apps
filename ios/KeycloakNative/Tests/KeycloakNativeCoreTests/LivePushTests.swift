import Foundation
import Testing
@testable import KeycloakNativeCore
@testable import KeycloakNativePush

/// Push MFA end to end against the demo compose stack (`KEYCLOAK_NATIVE_LIVE_BASE`), spec/06 S9,
/// S10, S12 and judy with the real transport: the SDK is both the native client and the "phone".
/// The browser of S9 is a cookie-keeping `URLSession` here; the wait page's form is posted by the
/// test. Each test removes the push credential it created (through the admin API, admin / admin)
/// so the other live tests see an unenrolled alice.
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_BASE"] != nil))
struct LivePushTests {
  static let base = LiveServerTests.base
  static let issuer = LiveServerTests.issuer

  func sdk() -> KeycloakNative {
    var options = KeycloakNative.Options()
    options.secureStore = InMemorySecureStore()
    options.dpop = .software
    options.logger = NoopLogger()
    return KeycloakNative.configure(issuer: Self.issuer, clientId: "demo-native", options: options)
  }

  /// alice through password + TOTP (or push when offered and `approve` is given), tokens stored.
  @discardableResult
  func loginAlice(_ kc: KeycloakNative) async throws -> Credentials {
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LivePushTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp(TOTP.code(secret: LiveServerTests.aliceTotpSecret)), to: try #require(step.challenges?.first(.totp)))
    let credentials = try #require(step.credentials)
    try await kc.credentialsManager().store(credentials)
    return credentials
  }

  @Test func s9EnrolThenApproveABrowserLogin() async throws {
    try await LiveAdmin.deletePushCredentials("alice")
    let kc = sdk()
    defer { Task { try? await LiveAdmin.deletePushCredentials("alice") } }
    try await loginAlice(kc)
    let push = kc.push()
    let metadata = try await push.metadata()
    #expect(metadata.deviceToken == "native" && metadata.pushProviderTypes.contains("apns"))
    let enrollment = try await push.enroll(deviceLabel: "LivePushTests phone")
    #expect(enrollment.username == "alice" && push.isEnrolled)
    #expect(try await LiveAdmin.pushCredentials("alice").count == 1)

    // A browser login on the realm's browser-push flow lands on the wait page …
    let browser = LiveBrowser()
    let pkce = PKCE.generate()
    var page = try await browser.get(Self.issuer.absoluteString + "/protocol/openid-connect/auth?client_id=web-app&response_type=code&scope=openid&state=s9&code_challenge=\(pkce.challenge)&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb")
    for _ in 0..<3 where page.status == 302 { page = try await browser.get(try #require(page.location)) }
    #expect(page.status == 200)
    let wait = try await browser.post(LiveBrowser.formAction(page.body), "username=alice&password=alice-password")
    #expect(wait.status == 200 && wait.body.contains("challengeId"), "status \(wait.status), location \(wait.location ?? "-"), body: \(wait.body.split(separator: "\n").filter { $0.localizedCaseInsensitiveContains("error") || $0.localizedCaseInsensitiveContains("cookie") || $0.localizedCaseInsensitiveContains("expired") }.joined(separator: " | ").prefix(800))")
    let cid = try #require(LiveBrowser.value(named: "challengeId", in: wait.body))

    // … which the phone approves (no number match on the browser flow of the demo realm).
    let pending = try await push.pendingApprovals()
    let approval = try #require(pending.first { $0.cid == cid })
    #expect(approval.clientId == "web-app" && approval.username == "alice" && approval.numbers.isEmpty)
    #expect(try await push.respond(to: approval, .approve()) == "approved")
    let done = try await browser.post(LiveBrowser.formAction(wait.body), "challengeId=\(cid)&refresh=")
    #expect(done.status == 302)
    let location = try #require(done.location)
    #expect(location.hasPrefix("http://localhost:3000/cb?") && location.contains("code=") && location.contains("state=s9"), "\(location)")
  }

  @Test func s10NativeLoginWithPushAndNumberMatch() async throws {
    try await LiveAdmin.deletePushCredentials("alice")
    let kc = sdk()
    defer { Task { try? await LiveAdmin.deletePushCredentials("alice") } }
    try await loginAlice(kc)
    let push = kc.push()
    try await push.enroll(deviceLabel: "LivePushTests phone")

    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LivePushTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.types == ["totp", "push"])
    var challenge = try #require(step.challenges?.first(.push))
    #expect(challenge.pushParams?.sent == false && challenge.pushParams?.devices == ["LivePushTests phone"])
    step = try await flow.respond(.pushResend, to: challenge)
    challenge = try #require(step.challenges?.first(.push))
    let params = try #require(challenge.pushParams)
    #expect(params.isPending && params.pollInterval == 3)
    let number = try #require(params.userVerificationNumber)

    let approval = try #require(try await push.pendingApprovals().first { $0.cid == params.cid })
    #expect(approval.numbers.count == 3 && approval.numbers.contains(number))
    let wrong = try #require(approval.numbers.first { $0 != number })
    await #expect(throws: NativeAuthError.self) { try await push.respond(to: approval, .approve(userVerification: wrong)) }
    #expect(try await push.respond(to: approval, .approve(userVerification: number)) == "approved")

    step = try await flow.respond(.pushPoll, to: challenge)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice" && credentials.isDPoPBound)
  }

  @Test func s12ApnsTokenRotateKeyAndLockout() async throws {
    try await LiveAdmin.deletePushCredentials("alice")
    let kc = sdk()
    defer { Task { try? await LiveAdmin.deletePushCredentials("alice"); try? await LiveAdmin.enable("alice") } }
    try await loginAlice(kc)
    let push = kc.push()
    try await push.enroll(deviceLabel: "LivePushTests phone")
    let before = try await kc.dpopKeyThumbprint()

    try await push.updateAPNsToken(Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
    #expect(push.enrollment?.pushProviderType == "apns")

    try await push.rotateKey()
    let after = try await kc.dpopKeyThumbprint()
    #expect(after != before && push.enrollment?.keyThumbprint == after)
    #expect(try await kc.credentialsManager().stored() == nil, "tokens bound to the old key are dropped")
    await #expect(throws: NativeAuthError.self, "no device token until the next login") { try await push.pendingApprovals() }

    try await loginAlice(kc)
    #expect(try await push.pendingApprovals().isEmpty, "the device API works with the new key")

    try await push.lockout()
    #expect(try await LiveAdmin.user("alice")?["enabled"]?.boolValue == false)
    try await LiveAdmin.enable("alice")
  }

  @Test func judyEnrolsMidFlow() async throws {
    try await LiveAdmin.deletePushCredentials("judy")
    try await LiveAdmin.setRequiredActions("judy", ["push-mfa-register"])
    let kc = sdk()
    defer { Task { try? await LiveAdmin.deletePushCredentials("judy"); try? await LiveAdmin.setRequiredActions("judy", ["push-mfa-register"]) } }
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LivePushTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("judy"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("judy-password"), to: try #require(step.challenges?.first(.password)))
    let challenge = try #require(step.challenges?.first(.pushEnrollment))
    #expect(challenge.id == "native-push-enroll")
    let push = kc.push()
    let prepared = try await push.prepareEnrollment(for: try #require(challenge.pushEnrollmentParams), deviceLabel: "Judy's live phone")
    step = try await flow.respond(prepared.answer, to: challenge)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "judy")
    try push.commit(prepared)
    #expect(try await LiveAdmin.pushCredentials("judy").count == 1)

    let again = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LivePushTests"))
    step = try await again.start()
    step = try await again.respond(.username("judy"), to: try #require(step.challenges?.first(.username)))
    step = try await again.respond(.password("judy-password"), to: try #require(step.challenges?.first(.password)))
    let pushChallenge = try #require(step.challenges?.first(.push))
    #expect(step.challenges?.count == 1 && pushChallenge.pushParams?.sent == true)
    await again.cancel()
  }
}

/// A browser with a hand-rolled cookie jar that does not follow redirects: Keycloak marks its
/// cookies `Secure` even on the plain-http compose stack, which Foundation would refuse to send.
final class LiveBrowser: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  struct Page {
    let status: Int
    let location: String?
    let body: String
  }

  private let lock = NSLock()
  private var cookies: [String: String] = [:]
  private lazy var session: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
  }()

  func get(_ url: String) async throws -> Page { try await send(URLRequest(url: URL(string: url)!)) }

  func post(_ url: String, _ form: String) async throws -> Page {
    var request = URLRequest(url: URL(string: url)!)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = Data(form.utf8)
    return try await send(request)
  }

  private func send(_ original: URLRequest) async throws -> Page {
    var request = original
    let jar = lock.withLock { cookies }
    if !jar.isEmpty {
      request.setValue(jar.map { "\($0.key)=\($0.value)" }.joined(separator: "; "), forHTTPHeaderField: "Cookie")
    }
    let (data, response) = try await session.data(for: request)
    let http = response as? HTTPURLResponse
    if let merged = http?.value(forHTTPHeaderField: "Set-Cookie") {
      lock.withLock {
        for (name, value, expired) in LiveBrowser.parseSetCookie(merged) {
          if expired { cookies.removeValue(forKey: name) } else { cookies[name] = value }
        }
      }
    }
    return Page(status: http?.statusCode ?? 0, location: http?.value(forHTTPHeaderField: "Location"), body: String(data: data, encoding: .utf8) ?? "")
  }

  func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil)
  }

  /// Foundation joins several `Set-Cookie` headers with ", " and refuses `Secure` cookies on http,
  /// so the header is split by hand (Keycloak's values contain no commas).
  static func parseSetCookie(_ merged: String) -> [(name: String, value: String, expired: Bool)] {
    let splitter = try! NSRegularExpression(pattern: ", (?=[A-Za-z0-9_\\-]+=)")
    let ns = merged as NSString
    var pieces: [String] = []
    var last = 0
    for match in splitter.matches(in: merged, range: NSRange(location: 0, length: ns.length)) {
      pieces.append(ns.substring(with: NSRange(location: last, length: match.range.location - last)))
      last = match.range.location + match.range.length
    }
    pieces.append(ns.substring(from: last))
    return pieces.compactMap { piece in
      let parts = piece.split(separator: ";", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
      guard let pair = parts.first, let eq = pair.firstIndex(of: "=") else { return nil }
      let name = String(pair[..<eq])
      let value = String(pair[pair.index(after: eq)...])
      let expired = value.isEmpty || piece.localizedCaseInsensitiveContains("Max-Age=0")
      return (name, value, expired)
    }
  }

  static func formAction(_ html: String) -> String {
    let pattern = try! NSRegularExpression(pattern: "action=\"([^\"]+)\"")
    let match = pattern.firstMatch(in: html, range: NSRange(html.startIndex..., in: html))!
    return String(html[Range(match.range(at: 1), in: html)!]).replacingOccurrences(of: "&amp;", with: "&")
  }

  static func value(named name: String, in html: String) -> String? {
    let pattern = try! NSRegularExpression(pattern: "name=\"\(name)\" value=\"([^\"]+)\"")
    guard let match = pattern.firstMatch(in: html, range: NSRange(html.startIndex..., in: html)) else { return nil }
    return String(html[Range(match.range(at: 1), in: html)!])
  }
}

/// The compose stack's admin API (admin / admin).
enum LiveAdmin {
  static var base: String { LiveServerTests.base }

  static func token() async throws -> String {
    var request = URLRequest(url: URL(string: base + "/realms/master/protocol/openid-connect/token")!)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = Data("grant_type=password&client_id=admin-cli&username=admin&password=admin".utf8)
    let (data, _) = try await URLSession.shared.data(for: request)
    return JSONValue(jsonData: data)?["access_token"]?.stringValue ?? ""
  }

  static func call(_ method: String, _ path: String, body: JSONValue? = nil) async throws -> JSONValue? {
    var request = URLRequest(url: URL(string: base + "/admin/realms/demo" + path)!)
    request.httpMethod = method
    request.setValue("Bearer \(try await token())", forHTTPHeaderField: "Authorization")
    if let body {
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.httpBody = Data(body.serialized().utf8)
    }
    let (data, _) = try await URLSession.shared.data(for: request)
    return JSONValue(jsonData: data)
  }

  static func user(_ username: String) async throws -> JSONValue? {
    try await call("GET", "/users?username=\(username)&exact=true")?.arrayValue?.first
  }

  static func pushCredentials(_ username: String) async throws -> [JSONValue] {
    guard let id = try await user(username)?["id"]?.stringValue else { return [] }
    return (try await call("GET", "/users/\(id)/credentials")?.arrayValue ?? []).filter { $0["type"]?.stringValue == "push-mfa" }
  }

  static func deletePushCredentials(_ username: String) async throws {
    guard let id = try await user(username)?["id"]?.stringValue else { return }
    for credential in try await pushCredentials(username) {
      _ = try await call("DELETE", "/users/\(id)/credentials/\(credential["id"]?.stringValue ?? "")")
    }
  }

  static func enable(_ username: String) async throws {
    try await update(username) { $0["enabled"] = true }
  }

  static func setRequiredActions(_ username: String, _ actions: [String]) async throws {
    try await update(username) { $0["requiredActions"] = .array(actions.map(JSONValue.string)) }
  }

  /// Read-modify-write (a partial PUT wipes the declarative profile).
  private static func update(_ username: String, _ change: (inout [String: JSONValue]) -> Void) async throws {
    guard var representation = try await user(username)?.objectValue, let id = representation["id"]?.stringValue else { return }
    change(&representation)
    _ = try await call("PUT", "/users/\(id)", body: .object(representation))
  }
}
