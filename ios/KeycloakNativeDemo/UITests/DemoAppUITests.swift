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
    let run = app.buttons["Run S14 now (locks user erin for a minute)"]
    XCTAssertTrue(run.waitForExistence(timeout: timeout))
    run.tap()
    // erin may still be locked from an earlier run (the username step then re-challenges with
    // invalid_credential and the scenario stops): wait out the 60 s lock once and try again.
    if !wait(timeout, { self.status(app).contains("access_denied") }) {
      XCTAssertTrue(status(app).contains("invalid_credential") || status(app).contains("Server offers"), status(app))
      sleep(61)
      run.tap()
      XCTAssertTrue(wait(timeout) { self.status(app).contains("access_denied") }, status(app))
    }
    XCTAssertTrue(status(app).contains("Locked out after repeated failures"), status(app))
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
