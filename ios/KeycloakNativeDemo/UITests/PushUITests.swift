import CryptoKit
import XCTest

/// Push MFA on the simulator against the compose stack (spec/06 S9, S10, S12, judy; spec/14 D9).
/// The simulator receives no APNs, so every approval is pulled from `/push-mfa/login/pending`
/// through Home → "Sign-in requests". The "browser" of S9 is a URLSession with a cookie jar inside
/// the test process; the ba-itsys wait page's form is posted by the test (what its SSE listener
/// would do). Tests run in name order and share the enrolment; the last one cleans the realm up
/// through the admin API so the other suites see an unenrolled alice.
final class PushUITests: XCTestCase {
  static let aliceTotpSecret = "alice-totp-secret-20261014"
  let timeout: TimeInterval = 20

  override func setUpWithError() throws {
    continueAfterFailure = false
  }

  // MARK: - S9

  func testPush1EnrolAndApproveABrowserLogin() throws {
    Admin.deletePushCredentials("alice")
    let app = XCUIApplication()
    app.launch()
    app.tabBars.buttons["Home"].tap()
    if find(app, app.buttons["pushForget"]) { app.buttons["pushForget"].tap() }
    loginAlice(app, scenario: "s9PushEnrolAndApprove")

    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["pushEnrol"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Push MFA enrolled") }, "\(status(app)) / \(texts(app))")
    XCTAssertTrue(find(app, app.staticTexts["pushEnrolledDevice"]))
    XCTAssertEqual(Admin.pushCredentials("alice").count, 1, "one push-mfa credential on the server")

    // A browser login of alice (realm browser flow browser-push): the wait page appears.
    let browser = Browser()
    let pkce = PKCE()
    var page = browser.get(Admin.realm + "/protocol/openid-connect/auth?client_id=web-app&response_type=code&scope=openid&state=s9&code_challenge=\(pkce.challenge)&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb")
    for _ in 0..<3 where page.status == 302 { page = browser.get(page.location!) }
    XCTAssertEqual(page.status, 200, page.body.prefix(300).description)
    let waitPage = browser.post(formAction(page.body), "username=alice&password=alice-password")
    XCTAssertEqual(waitPage.status, 200, waitPage.body.prefix(300).description)
    XCTAssertTrue(waitPage.body.contains("challengeId"), "push wait page expected")
    let cid = try XCTUnwrap(value(named: "challengeId", in: waitPage.body))

    // The phone lists and approves it.
    tap(app, app.buttons["pushApprovals"])
    let approve = app.buttons["pushApprove"]
    if !approve.waitForExistence(timeout: 3) { tap(app, app.buttons["pushRefresh"]) }
    XCTAssertTrue(approve.waitForExistence(timeout: timeout), "no pending approval shown: \(label(app.staticTexts["pushApprovalsMessage"]))")
    approve.tap()
    XCTAssertTrue(wait(timeout) { !app.buttons["pushApprove"].exists }, "the row goes away after approval")

    // The browser's waiting form completes the login with a code for the web app.
    let done = browser.post(formAction(waitPage.body), "challengeId=\(cid)&refresh=")
    XCTAssertEqual(done.status, 302, done.body.prefix(300).description)
    let location = try XCTUnwrap(done.location)
    XCTAssertTrue(location.hasPrefix("http://localhost:3000/cb?") && location.contains("code=") && location.contains("state=s9"), location)
    app.navigationBars.buttons.element(boundBy: 0).tap()
  }

  // MARK: - S10

  func testPush2NativeLoginWithPushAndNumberMatch() throws {
    let app = XCUIApplication()
    app.launch()
    ensureEnrolled(app)

    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-s10PushNativeLogin"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["Start login"].tap()
    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), status(app))
    app.buttons["Continue"].tap()
    let password = app.secureTextFields["password"]
    XCTAssertTrue(password.waitForExistence(timeout: timeout), status(app))
    password.tap()
    password.typeText("alice-password")
    app.buttons["Sign in with password"].tap()

    // [totp, push]: nothing is sent until the user asks.
    XCTAssertTrue(app.textFields["totp"].waitForExistence(timeout: timeout), status(app))
    tap(app, app.buttons["pushSend"])
    let numberLabel = app.staticTexts["pushNumber"]
    XCTAssertTrue(numberLabel.waitForExistence(timeout: timeout), "number match number expected: \(status(app))")
    let number = numberLabel.label.trimmingCharacters(in: .whitespaces)
    XCTAssertFalse(number.isEmpty)

    // The phone (same app): three numbers, pick the one the login shows.
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["pushApprovals"])
    let pick = app.buttons["pushNumber-\(number)"]
    if !pick.waitForExistence(timeout: 3) { tap(app, app.buttons["pushRefresh"]) }
    XCTAssertTrue(pick.waitForExistence(timeout: timeout), "number buttons expected: \(label(app.staticTexts["pushApprovalsMessage"]))")
    pick.tap()
    XCTAssertTrue(wait(timeout) { !app.buttons["pushNumber-\(number)"].exists }, "row did not go away: \(label(app.staticTexts["pushApprovalsMessage"]))")

    // Back on Login the poll picks the approval up and the login completes.
    app.navigationBars.buttons.element(boundBy: 0).tap()
    XCTAssertTrue(wait(timeout) { self.status(app).contains("approved") }, status(app))
    app.tabBars.buttons["Login"].tap()
    // The screen polls every poll_interval seconds; "Check now" is the manual equivalent.
    if !app.staticTexts["signedInTokenType"].waitForExistence(timeout: 8), app.buttons["pushPoll"].exists {
      app.buttons["pushPoll"].tap()
    }
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in after approval: \(status(app)) / \(texts(app))")
    XCTAssertTrue(status(app).contains("Signed in as alice"), status(app))
  }

  // MARK: - S12

  func testPush3MaintenanceApnsTokenRotateKeyAndLockout() throws {
    let app = XCUIApplication()
    app.launch()
    ensureEnrolled(app)
    app.tabBars.buttons["Home"].tap()

    tap(app, app.buttons["pushSimulateToken"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Push provider updated") }, status(app))
    XCTAssertTrue(label(app.staticTexts["pushProvider"]).contains("apns"), label(app.staticTexts["pushProvider"]))

    tap(app, app.buttons["pushRotate"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Device key rotated") }, status(app))
    XCTAssertTrue(find(app, app.staticTexts["notSignedIn"]), "the old tokens were cleared")

    // A new login binds tokens to the rotated key; the device API works again.
    loginAlice(app, scenario: "s12PushMaintenance")
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["pushApprovals"])
    // The list loads with the rotated key: either nothing is waiting or an older request (a failed
    // earlier run) is listed — but no error.
    XCTAssertTrue(wait(timeout) { app.staticTexts["pushNoApprovals"].exists || app.buttons["pushDeny"].exists }, "approvals did not load: \(label(app.staticTexts["pushApprovalsMessage"]))")
    XCTAssertFalse(app.staticTexts["pushApprovalsMessage"].exists, label(app.staticTexts["pushApprovalsMessage"]))
    app.navigationBars.buttons.element(boundBy: 0).tap()

    tap(app, app.buttons["pushLockout"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("locked out") }, status(app))
    XCTAssertEqual(Admin.user("alice")?["enabled"] as? Bool, false, "ba-itsys disabled the account")
    Admin.enable("alice")
  }

  // MARK: - judy

  func testPush4JudyEnrolsMidFlowThenIsAskedForPush() throws {
    Admin.deletePushCredentials("judy")
    Admin.setRequiredActions("judy", ["push-mfa-register"])
    let app = XCUIApplication()
    app.launch()
    app.tabBars.buttons["Home"].tap()
    if find(app, app.buttons["pushForget"]) { app.buttons["pushForget"].tap() }

    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-judyPushEnrol"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["Start login"].tap()
    XCTAssertTrue(app.textFields["username"].waitForExistence(timeout: timeout), status(app))
    app.buttons["Continue"].tap()
    let password = app.secureTextFields["password"]
    XCTAssertTrue(password.waitForExistence(timeout: timeout), status(app))
    password.tap()
    password.typeText("judy-password")
    app.buttons["Sign in with password"].tap()

    tap(app, app.buttons["pushEnrolInFlow"])
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in after enrolment: \(status(app)) / \(texts(app))")
    XCTAssertEqual(Admin.pushCredentials("judy").count, 1)
    app.tabBars.buttons["Home"].tap()
    XCTAssertTrue(find(app, app.staticTexts["pushEnrolledDevice"]))

    // Next login: push is the single second factor and is sent at once.
    app.tabBars.buttons["Login"].tap()
    tap(app, app.buttons["Start login"])
    XCTAssertTrue(app.textFields["username"].waitForExistence(timeout: timeout), status(app))
    app.buttons["Continue"].tap()
    XCTAssertTrue(password.waitForExistence(timeout: timeout), status(app))
    password.tap()
    password.typeText("judy-password")
    app.buttons["Sign in with password"].tap()
    XCTAssertTrue(app.buttons["pushPoll"].waitForExistence(timeout: timeout), "push challenge (sent at once) expected: \(status(app))")
    tap(app, app.buttons["Cancel"])

    // Leave the realm as the other suites expect it.
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["pushForget"])
    Admin.deletePushCredentials("judy")
    Admin.setRequiredActions("judy", ["push-mfa-register"])
    Admin.deletePushCredentials("alice")
    Admin.enable("alice")
  }

  // MARK: - helpers

  /// alice through S3 (password + TOTP) on `scenario`.
  private func loginAlice(_ app: XCUIApplication, scenario: String) {
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-\(scenario)"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["Start login"].tap()
    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), "username challenge not shown: \(status(app))")
    app.buttons["Continue"].tap()
    let password = app.secureTextFields["password"]
    XCTAssertTrue(password.waitForExistence(timeout: timeout), "password challenge not shown: \(status(app))")
    password.tap()
    password.typeText("alice-password")
    app.buttons["Sign in with password"].tap()
    let totp = app.textFields["totp"]
    XCTAssertTrue(totp.waitForExistence(timeout: timeout), "totp challenge not shown: \(status(app))")
    totp.tap()
    totp.typeText(TOTP.code(secret: Self.aliceTotpSecret))
    app.buttons["Verify code"].tap()
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
  }

  /// Enrols alice when the device is not enrolled yet (each test is runnable on its own).
  private func ensureEnrolled(_ app: XCUIApplication) {
    app.tabBars.buttons["Home"].tap()
    if find(app, app.staticTexts["pushEnrolledDevice"]) { return }
    Admin.deletePushCredentials("alice")
    loginAlice(app, scenario: "s9PushEnrolAndApprove")
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["pushEnrol"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Push MFA enrolled") }, "\(status(app)) / \(texts(app))")
  }

  private func formAction(_ html: String) -> String {
    let pattern = try! NSRegularExpression(pattern: "action=\"([^\"]+)\"")
    let match = pattern.firstMatch(in: html, range: NSRange(html.startIndex..., in: html))!
    return String(html[Range(match.range(at: 1), in: html)!]).replacingOccurrences(of: "&amp;", with: "&")
  }

  private func value(named name: String, in html: String) -> String? {
    let pattern = try! NSRegularExpression(pattern: "name=\"\(name)\" value=\"([^\"]+)\"")
    guard let match = pattern.firstMatch(in: html, range: NSRange(html.startIndex..., in: html)) else { return nil }
    return String(html[Range(match.range(at: 1), in: html)!])
  }

  /// Form rows are lazy: scroll down, then back up, until the element is materialised.
  @discardableResult
  private func find(_ app: XCUIApplication, _ element: XCUIElement) -> Bool {
    if element.waitForExistence(timeout: 1) { return true }
    for _ in 0..<6 where !element.exists { app.swipeUp() }
    for _ in 0..<12 where !element.exists { app.swipeDown() }
    return element.waitForExistence(timeout: 2)
  }

  private func tap(_ app: XCUIApplication, _ element: XCUIElement) {
    XCTAssertTrue(find(app, element), "not found after scrolling: \(element); texts: \(texts(app))")
    element.tap()
  }

  private func status(_ app: XCUIApplication) -> String {
    let status = app.staticTexts["status"].firstMatch
    if !status.exists {
      for _ in 0..<8 where !status.exists { app.swipeDown() }
    }
    return label(status)
  }

  /// All visible static texts, for failure messages.
  private func texts(_ app: XCUIApplication) -> String {
    app.staticTexts.allElementsBoundByIndex.prefix(40).map { $0.label }.joined(separator: " | ").prefix(700).description
  }

  private func label(_ element: XCUIElement) -> String {
    element.exists ? element.label : ""
  }

  private func wait(_ seconds: TimeInterval, _ condition: @escaping () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
      if condition() { return true }
      RunLoop.current.run(until: Date().addingTimeInterval(0.5))
    }
    return condition()
  }
}

/// A browser with a hand-rolled cookie jar that does not follow redirects (the app callback stays
/// observable). Keycloak marks its cookies `Secure` even on the plain-http compose stack, which
/// Foundation would refuse to send, hence the manual jar.
final class Browser: NSObject, URLSessionTaskDelegate {
  struct Page {
    let status: Int
    let location: String?
    let body: String
  }

  private var cookies: [String: String] = [:]
  private lazy var session: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
  }()

  func get(_ url: String) -> Page { send(URLRequest(url: URL(string: url)!)) }

  func post(_ url: String, _ form: String) -> Page {
    var request = URLRequest(url: URL(string: url)!)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = Data(form.utf8)
    return send(request)
  }

  private func send(_ original: URLRequest) -> Page {
    var request = original
    if !cookies.isEmpty {
      request.setValue(cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; "), forHTTPHeaderField: "Cookie")
    }
    let semaphore = DispatchSemaphore(value: 0)
    var page = Page(status: 0, location: nil, body: "")
    var setCookie: String?
    session.dataTask(with: request) { data, response, _ in
      let http = response as? HTTPURLResponse
      setCookie = http?.value(forHTTPHeaderField: "Set-Cookie")
      page = Page(status: http?.statusCode ?? 0, location: http?.value(forHTTPHeaderField: "Location"), body: String(data: data ?? Data(), encoding: .utf8) ?? "")
      semaphore.signal()
    }.resume()
    semaphore.wait()
    // Foundation joins several Set-Cookie headers with ", " and refuses Secure cookies on http,
    // so the header is split by hand (Keycloak's values contain no commas).
    if let setCookie {
      let splitter = try! NSRegularExpression(pattern: ", (?=[A-Za-z0-9_\\-]+=)")
      let ns = setCookie as NSString
      var pieces: [String] = []
      var last = 0
      for match in splitter.matches(in: setCookie, range: NSRange(location: 0, length: ns.length)) {
        pieces.append(ns.substring(with: NSRange(location: last, length: match.range.location - last)))
        last = match.range.location + match.range.length
      }
      pieces.append(ns.substring(from: last))
      for piece in pieces {
        let pair = piece.split(separator: ";", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        guard let eq = pair.firstIndex(of: "=") else { continue }
        let name = String(pair[..<eq])
        let value = String(pair[pair.index(after: eq)...])
        if value.isEmpty || piece.localizedCaseInsensitiveContains("Max-Age=0") { cookies.removeValue(forKey: name) } else { cookies[name] = value }
      }
    }
    return page
  }

  func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil)
  }
}

/// PKCE for the test's browser login (the web-app client requires S256).
struct PKCE {
  let verifier: String
  let challenge: String

  init() {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    verifier = PKCE.base64url(Data(bytes))
    challenge = PKCE.base64url(Data(SHA256.hash(data: Data(verifier.utf8))))
  }

  static func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}

/// The compose stack's admin API (admin / admin), to reset push state between runs.
enum Admin {
  static let base = ProcessInfo.processInfo.environment["KC_BASE"] ?? "http://localhost:8089"
  static let realm = base + "/realms/demo"

  static func token() -> String? {
    var request = URLRequest(url: URL(string: base + "/realms/master/protocol/openid-connect/token")!)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = Data("grant_type=password&client_id=admin-cli&username=admin&password=admin".utf8)
    return (json(request) as? [String: Any])?["access_token"] as? String
  }

  static func user(_ username: String) -> [String: Any]? {
    guard let token = token() else { return nil }
    var request = URLRequest(url: URL(string: base + "/admin/realms/demo/users?username=\(username)&exact=true")!)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    return (json(request) as? [[String: Any]])?.first
  }

  static func pushCredentials(_ username: String) -> [[String: Any]] {
    guard let token = token(), let id = user(username)?["id"] as? String else { return [] }
    var request = URLRequest(url: URL(string: base + "/admin/realms/demo/users/\(id)/credentials")!)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    return ((json(request) as? [[String: Any]]) ?? []).filter { $0["type"] as? String == "push-mfa" }
  }

  static func deletePushCredentials(_ username: String) {
    guard let token = token(), let id = user(username)?["id"] as? String else { return }
    for credential in pushCredentials(username) {
      var request = URLRequest(url: URL(string: base + "/admin/realms/demo/users/\(id)/credentials/\(credential["id"] as? String ?? "")")!)
      request.httpMethod = "DELETE"
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
      _ = json(request)
    }
  }

  static func enable(_ username: String) {
    update(username) { $0["enabled"] = true }
  }

  static func setRequiredActions(_ username: String, _ actions: [String]) {
    update(username) { $0["requiredActions"] = actions }
  }

  /// Read-modify-write: a partial PUT would wipe the profile (declarative user profile).
  private static func update(_ username: String, _ change: (inout [String: Any]) -> Void) {
    guard let token = token(), var representation = user(username), let id = representation["id"] as? String else { return }
    change(&representation)
    var request = URLRequest(url: URL(string: base + "/admin/realms/demo/users/\(id)")!)
    request.httpMethod = "PUT"
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: representation)
    _ = json(request)
  }

  private static func json(_ request: URLRequest) -> Any? {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Any?
    URLSession.shared.dataTask(with: request) { data, _, _ in
      result = data.flatMap { try? JSONSerialization.jsonObject(with: $0) }
      semaphore.signal()
    }.resume()
    semaphore.wait()
    return result
  }
}
