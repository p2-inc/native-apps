import CryptoKit
import XCTest

/// Smoke tests of the example app on an iOS simulator against the demo compose stack
/// (`KC_PORT=8089 docker compose up --wait`; `App/Config.plist` points at it). They drive the real
/// app UI: S3 (alice: password → TOTP), the Keychain restore across a relaunch, refresh, logout, the
/// software DPoP key on the simulator, and S14 (erin: brute force → access_denied). spec/06 §1
/// "Smoke UI tests", spec/10 Phase 1c.
final class DemoAppUITests: XCTestCase {
  static let aliceTotpSecret = "alice-totp-secret-20261014"
  let timeout: TimeInterval = 20

  override func setUpWithError() throws {
    continueAfterFailure = false
  }

  func testS3PasswordTotpLoginRelaunchRefreshAndLogout() throws {
    let app = XCUIApplication()
    app.launch()

    // Scenario S3, then Login tab.
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-s3PasswordTotp"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["Start login"].tap()

    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), "username challenge not shown: \(status(app))")
    XCTAssertEqual(username.value as? String, "alice", "scenario pre-fills the username")
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

    let tokenType = app.staticTexts["signedInTokenType"]
    XCTAssertTrue(tokenType.waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("Signed in as alice"), status(app))
    XCTAssertTrue(status(app).contains("token_type DPoP"), "the token endpoint binds to the DPoP key: \(status(app))")

    // DPoP key on a simulator: software key, thumbprint shown.
    app.tabBars.buttons["Diagnostics"].tap()
    let jkt = app.staticTexts["dpopJkt"]
    XCTAssertTrue(jkt.waitForExistence(timeout: timeout))
    XCTAssertTrue(wait(timeout) { !(self.label(jkt).hasSuffix("—")) }, "jkt missing: \(label(jkt))")

    // Relaunch: the Keychain CredentialsManager restores the session.
    app.terminate()
    app.launch()
    app.tabBars.buttons["Home"].tap()
    let homeTokenType = app.staticTexts["homeTokenType"]
    XCTAssertTrue(homeTokenType.waitForExistence(timeout: timeout), "credentials not restored after relaunch: \(status(app))")
    XCTAssertTrue(label(homeTokenType).contains("DPoP"), label(homeTokenType))

    tap(app, app.buttons["Refresh tokens"])
    XCTAssertTrue(wait(timeout) { self.status(app) == "Tokens refreshed." }, status(app))

    tap(app, app.buttons["Log out"])
    XCTAssertTrue(wait(timeout) { self.status(app) == "Logged out." }, status(app))
    XCTAssertTrue(app.staticTexts["notSignedIn"].waitForExistence(timeout: timeout))

    // Relaunch again: logout cleared the Keychain.
    app.terminate()
    app.launch()
    app.tabBars.buttons["Home"].tap()
    XCTAssertTrue(app.staticTexts["notSignedIn"].waitForExistence(timeout: timeout), status(app))
  }

  func testS14BruteForceEndsWithAccessDenied() throws {
    let app = XCUIApplication()
    app.launch()
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-s14BruteForce"])
    // The scenario list has grown: the "Run" section sits below the fold, so scroll to it.
    let run = app.buttons["Run S14 now (locks user erin for a minute)"]
    tap(app, run)
    // erin may still be locked from an earlier run (spec/03 §4.1: a locked account gets the same
    // phantom password challenge and countdown as an unknown one, so the scenario still ends with
    // access_denied after five attempts); the only other outcome is a transient state — wait out
    // the 60 s lock once and try again.
    if !wait(timeout, { self.status(app).contains("access_denied") }) {
      XCTAssertTrue(status(app).contains("invalid_credential") || status(app).contains("Server offers"), status(app))
      sleep(61)
      tap(app, run)
      XCTAssertTrue(wait(timeout) { self.status(app).contains("access_denied") }, status(app))
    }
    XCTAssertTrue(status(app).contains("Locked out after repeated failures"), status(app))
  }

  // MARK: - Phase 2b required actions (spec/03 §4.12–§4.14, spec/14 D1)

  /// Picks a scenario, starts the login and gets past username + password.
  private func loginThroughPassword(_ app: XCUIApplication, scenario: String, username expectedUsername: String, password: String) {
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-\(scenario)"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["Start login"].tap()
    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), "username challenge not shown: \(status(app))")
    XCTAssertEqual(username.value as? String, expectedUsername)
    app.buttons["Continue"].tap()
    let passwordField = app.secureTextFields["password"]
    XCTAssertTrue(passwordField.waitForExistence(timeout: timeout), "password challenge not shown: \(status(app))")
    passwordField.tap()
    passwordField.typeText(password)
    app.buttons["Sign in with password"].tap()
  }

  /// carol: UPDATE_PASSWORD served in-band; the same password is set again so the realm stays usable.
  /// After the first run the action is gone (until `docker compose down -v`): then the login just succeeds.
  func testCarolUpdatesPasswordInBand() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "carolUpdatePassword", username: "carol", password: "carol-password")
    let newPassword = app.secureTextFields["newPassword"]
    if newPassword.waitForExistence(timeout: timeout) {
      XCTAssertTrue(status(app).contains("update_password"), status(app))
      newPassword.tap()
      newPassword.typeText("carol-password")
      let confirm = app.secureTextFields["newPasswordConfirm"]
      confirm.tap()
      confirm.typeText("other")
      app.buttons["updatePassword"].tap()
      XCTAssertTrue(wait(timeout) { self.status(app).contains("update_password") && app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'password_mismatch'")).count > 0 }, "mismatch not reported: \(status(app))")
      confirm.tap()
      confirm.press(forDuration: 1.0)
      if app.menuItems["Select All"].waitForExistence(timeout: 2) { app.menuItems["Select All"].tap() }
      confirm.typeText("carol-password")
      app.buttons["updatePassword"].tap()
    }
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("Signed in as carol"), status(app))
  }

  /// grace: VERIFY_EMAIL served with a mailed code read from mailpit's API.
  func testGraceVerifiesEmail() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "graceVerifyEmail", username: "grace", password: "grace-password")
    let codeField = app.textFields["verifyEmailCode"]
    if codeField.waitForExistence(timeout: timeout) {
      let code = try XCTUnwrap(Mailpit.latestCode(to: "grace@example.com"), "no code in mailpit for grace")
      codeField.tap()
      codeField.typeText(code)
      app.buttons["verifyEmail"].tap()
    }
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("Signed in as grace"), status(app))
  }

  /// hank: TERMS_AND_CONDITIONS served as `terms`; declining ends the login, accepting signs in.
  func testHankAcceptsTerms() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "hankTerms", username: "hank", password: "hank-password")
    let accept = app.buttons["acceptTerms"]
    if accept.waitForExistence(timeout: timeout) {
      XCTAssertTrue(app.staticTexts["termsText"].exists)
      app.buttons["declineTerms"].tap()
      XCTAssertTrue(wait(timeout) { self.status(app).contains("access_denied") }, status(app))
      // Declined: start again and accept.
      app.buttons["Start login"].tap()
      XCTAssertTrue(app.textFields["username"].waitForExistence(timeout: timeout))
      app.buttons["Continue"].tap()
      let passwordField = app.secureTextFields["password"]
      XCTAssertTrue(passwordField.waitForExistence(timeout: timeout))
      passwordField.tap()
      passwordField.typeText("hank-password")
      app.buttons["Sign in with password"].tap()
      XCTAssertTrue(accept.waitForExistence(timeout: timeout), status(app))
      accept.tap()
    }
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("Signed in as hank"), status(app))
  }

  // MARK: - Phase 2 scenarios driven by XCUITest (spec/10 Phase 2b)

  /// S4: bob on demo-ios-otp gets the e-mail code as the only second factor; the code comes from mailpit.
  func testS4EmailOtpWithResend() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "s4EmailOtp", username: "bob", password: "bob-password")
    let otp = app.textFields["otp"]
    XCTAssertTrue(otp.waitForExistence(timeout: timeout), "otp challenge not shown: \(status(app))")
    XCTAssertTrue(app.buttons["otpResend"].exists)
    let code = try XCTUnwrap(Mailpit.latestCode(to: "bob@example.com"), "no code in mailpit for bob")
    otp.tap()
    otp.typeText(code)
    app.buttons["Verify code"].tap()
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("Signed in as bob"), status(app))
  }

  /// S5: the KeycloakNativeUI product with the "Try another way" chooser (alice: TOTP vs e-mail code).
  func testS5DefaultUIWithChooser() throws {
    let app = XCUIApplication()
    app.launch()
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-s5DefaultUI"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["startDefaultUI"].tap()
    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), status(app))
    username.tap()
    username.typeText("alice")
    app.buttons["Continue"].tap()
    let password = app.secureTextFields["password"]
    XCTAssertTrue(password.waitForExistence(timeout: timeout), status(app))
    password.tap()
    password.typeText("alice-password")
    app.buttons["Sign in"].tap()
    // The first supported entry (TOTP) is shown; switch to the e-mail code through the chooser.
    XCTAssertTrue(app.textFields["totp"].waitForExistence(timeout: timeout), status(app))
    let switchToOtp = app.buttons["switchTo-otp"]
    XCTAssertTrue(switchToOtp.waitForExistence(timeout: timeout))
    switchToOtp.tap()
    let send = app.buttons["otpSend"]
    XCTAssertTrue(send.waitForExistence(timeout: timeout), "otp screen with 'Send me a code' not shown")
    send.tap()
    let otp = app.textFields["otp"]
    XCTAssertTrue(otp.waitForExistence(timeout: timeout), "code field not shown after sending")
    let code = try XCTUnwrap(Mailpit.latestCode(to: "alice@example.com"), "no code in mailpit for alice")
    otp.tap()
    otp.typeText(code)
    app.buttons["Verify"].tap()
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Signed in as alice") }, status(app))
  }

  /// S13: same flow, but the TOTP screen is replaced through challengePresenter(for: .totp).
  func testS13CustomTotpPresenter() throws {
    let app = XCUIApplication()
    app.launch()
    app.tabBars.buttons["Scenarios"].tap()
    tap(app, app.buttons["scenario-s13CustomPresenter"])
    app.tabBars.buttons["Login"].tap()
    app.buttons["startDefaultUI"].tap()
    let username = app.textFields["username"]
    XCTAssertTrue(username.waitForExistence(timeout: timeout), status(app))
    username.tap()
    username.typeText("alice")
    app.buttons["Continue"].tap()
    let password = app.secureTextFields["password"]
    XCTAssertTrue(password.waitForExistence(timeout: timeout), status(app))
    password.tap()
    password.typeText("alice-password")
    app.buttons["Sign in"].tap()
    XCTAssertTrue(app.staticTexts["customTotpTitle"].waitForExistence(timeout: timeout), "custom presenter not used: \(status(app))")
    let custom = app.textFields["customTotp"]
    custom.tap()
    custom.typeText(TOTP.code(secret: Self.aliceTotpSecret))
    app.buttons["Go"].tap()
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Signed in as alice") }, status(app))
  }

  /// S6: password-only login on demo-ios-stepup (acr 1); Transfer is refused with 401 until the
  /// step-up asks for the TOTP only; then it succeeds with acr 2.
  func testS6StepUpForTheProtectedTransfer() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "s6StepUp", username: "alice", password: "alice-password")
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), "not signed in: \(status(app))")
    XCTAssertTrue(status(app).contains("acr 1"), status(app))
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["transfer"])
    // The resource server answered 401 and the app started the step-up: only the TOTP is asked.
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Step-up") }, status(app))
    app.tabBars.buttons["Login"].tap()
    let totp = app.textFields["totp"]
    XCTAssertTrue(totp.waitForExistence(timeout: timeout), "totp not asked on step-up: \(status(app))")
    XCTAssertFalse(app.secureTextFields["password"].exists, "the primary factor is not asked again")
    totp.tap()
    totp.typeText(TOTP.code(secret: Self.aliceTotpSecret))
    app.buttons["Verify code"].tap()
    XCTAssertTrue(wait(timeout) { self.status(app).contains("acr 2") }, status(app))
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["transfer"])
    XCTAssertTrue(wait(timeout) { self.label(app.staticTexts["resourceResult"]).contains("HTTP 200") }, label(app.staticTexts["resourceResult"]))
  }

  /// S8: the server ends the session (refresh token revoked); the next refresh reports reauthentication_required.
  func testS8RefreshAfterServerSideLogoutRequiresReauthentication() throws {
    let app = XCUIApplication()
    app.launch()
    loginThroughPassword(app, scenario: "s8RefreshReauth", username: "alice", password: "alice-password")
    let totp = app.textFields["totp"]
    XCTAssertTrue(totp.waitForExistence(timeout: timeout), status(app))
    totp.tap()
    totp.typeText(TOTP.code(secret: Self.aliceTotpSecret))
    app.buttons["Verify code"].tap()
    XCTAssertTrue(app.staticTexts["signedInTokenType"].waitForExistence(timeout: timeout), status(app))
    app.tabBars.buttons["Home"].tap()
    tap(app, app.buttons["endSession"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("Session ended on the server") }, status(app))
    tap(app, app.buttons["Refresh tokens"])
    XCTAssertTrue(wait(timeout) { self.status(app).contains("reauthentication_required") }, status(app))
    XCTAssertTrue(app.staticTexts["notSignedIn"].waitForExistence(timeout: timeout))
  }

  // MARK: -

  /// SwiftUI lists only expose the rows on screen: swipe up until the element exists, then tap it.
  private func tap(_ app: XCUIApplication, _ element: XCUIElement) {
    for _ in 0..<8 where !element.exists {
      app.swipeUp()
    }
    XCTAssertTrue(element.waitForExistence(timeout: 5), "not found after scrolling: \(element)")
    element.tap()
  }

  private func status(_ app: XCUIApplication) -> String {
    label(app.staticTexts["status"].firstMatch)
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

/// The compose stack's mailpit API (`http://localhost:8025`), for the mailed codes.
enum Mailpit {
  static let base = URL(string: ProcessInfo.processInfo.environment["MAILPIT_BASE"] ?? "http://localhost:8025")!

  /// The 4-10 digit code in the newest message to `email`, polling for a few seconds.
  static func latestCode(to email: String) -> String? {
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
      if let code = fetchCode(to: email) { return code }
      RunLoop.current.run(until: Date().addingTimeInterval(1))
    }
    return nil
  }

  private static func fetchCode(to email: String) -> String? {
    guard let list = get("/api/v1/messages?limit=50"), let messages = list["messages"] as? [[String: Any]] else { return nil }
    for message in messages {
      let recipients = (message["To"] as? [[String: Any]] ?? []).compactMap { $0["Address"] as? String }
      guard recipients.contains(where: { $0.caseInsensitiveCompare(email) == .orderedSame }), let id = message["ID"] as? String else { continue }
      guard let body = get("/api/v1/message/\(id)"), let text = body["Text"] as? String else { return nil }
      if let range = text.range(of: "code is ([0-9]{4,10})", options: .regularExpression) {
        return text[range].split(separator: " ").last.map(String.init)
      }
      return nil
    }
    return nil
  }

  private static func get(_ path: String) -> [String: Any]? {
    let semaphore = DispatchSemaphore(value: 0)
    var result: [String: Any]?
    let url = URL(string: base.absoluteString + path)!
    URLSession.shared.dataTask(with: url) { data, _, error in
      if let error { NSLog("mailpit %@: %@", url.absoluteString, String(describing: error)) }
      result = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
      semaphore.signal()
    }.resume()
    _ = semaphore.wait(timeout: .now() + 10)
    return result
  }
}

/// RFC 6238 (SHA-1, 6 digits, 30 s), the realm's OTP policy for alice.
enum TOTP {
  static func code(secret: String, at date: Date = Date()) -> String {
    var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
    let message = Data(bytes: &counter, count: 8)
    let mac = HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: Data(secret.utf8)))
    let bytes = Array(mac)
    let offset = Int(bytes[19] & 0x0f)
    let binary = (Int(bytes[offset] & 0x7f) << 24) | (Int(bytes[offset + 1]) << 16) | (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
    return String(format: "%06d", binary % 1_000_000)
  }
}
