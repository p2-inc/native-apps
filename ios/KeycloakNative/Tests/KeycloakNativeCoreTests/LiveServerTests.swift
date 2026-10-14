import Foundation
import Testing
@testable import KeycloakNativeCore

/// End-to-end against the demo compose stack (`KC_PORT=8089 docker compose up --wait`), enabled
/// with `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089`. Uses the real `URLSessionTransport`, a
/// software DPoP key and the software WebAuthn authenticator; this is what the iOS example app does
/// on a device, minus the platform passkey sheet.
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_BASE"] != nil))
struct LiveServerTests {
  static let base = ProcessInfo.processInfo.environment["KEYCLOAK_NATIVE_LIVE_BASE"] ?? ""
  static let issuer = URL(string: base + "/realms/demo")!
  static let aliceTotpSecret = "alice-totp-secret-20261014"

  func sdk(clientId: String, passkeys: any PasskeyPlatform = SoftwareAuthenticator(origin: Self.base)) -> KeycloakNative {
    var options = KeycloakNative.Options()
    options.secureStore = InMemorySecureStore()
    options.passkeyPlatform = passkeys
    options.dpop = .software
    options.logger = NoopLogger()
    return KeycloakNative.configure(issuer: Self.issuer, clientId: clientId, options: options)
  }

  func loginAlice(_ kc: KeycloakNative, passkey: Bool = false, authenticator: SoftwareAuthenticator? = nil) async throws -> Credentials {
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "LiveServerTests"))
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    if passkey, let challenge = step.challenges?.first(.passkey) {
      let assertion = try await kc.passkeys().assert(try #require(challenge.passkeyParams))
      step = try await flow.respond(.passkey(assertion), to: challenge)
    } else {
      step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    }
    step = try await flow.respond(.totp(TOTP.code(secret: Self.aliceTotpSecret)), to: try #require(step.challenges?.first(.totp)))
    return try #require(step.credentials)
  }

  @Test func metadataAndS3PasswordTotpLoginWithTokenLifecycle() async throws {
    let kc = sdk(clientId: "demo-ios")
    let metadata = try await kc.metadata()
    #expect(metadata.passkey?.rpId == "localhost")
    #expect(metadata.dpopSigningAlgValuesSupported.isEmpty)

    let credentials = try await loginAlice(kc)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(credentials.authSession != nil)
    // Record what Keycloak 26.8.1 does with an unsolicited DPoP proof on the token request (spec/12).
    print("LIVE: token_type=\(credentials.tokenType) dpop_bound=\(credentials.isDPoPBound)")

    let manager = kc.credentialsManager()
    try await manager.store(credentials.expiredCopy())
    let refreshed = try await manager.credentials()
    #expect(refreshed.accessToken != credentials.accessToken && refreshed.authSession == credentials.authSession)
    try await kc.tokens().revoke(token: try #require(refreshed.refreshToken))
    let gone = await #expect(throws: NativeAuthError.self) { try await kc.tokens().refresh(refreshed) }
    #expect(gone?.code == NativeAuthError.Code.invalidGrant)
  }

  @Test func s11RegisterPasskeyAfterLoginThenS1AllowListLogin() async throws {
    let authenticator = SoftwareAuthenticator(origin: Self.base)
    let kc = sdk(clientId: "demo-ios", passkeys: authenticator)
    let credentials = try await loginAlice(kc)
    let registered = try await kc.passkeys().registerNewPasskey(label: "LiveServerTests", credentials: credentials)
    #expect(registered.credentialId == authenticator.credentialIdBase64URL && registered.label == "LiveServerTests")

    let viaPasskey = try await loginAlice(kc, passkey: true)
    #expect(viaPasskey.accessTokenClaims?["preferred_username"]?.stringValue == "alice")

    // S2: discoverable login on demo-ios-passkey with the resident credential just registered.
    let kcDiscoverable = sdk(clientId: "demo-ios-passkey", passkeys: authenticator)
    let flow = kcDiscoverable.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    let passkey = try #require(step.challenges?.first(.passkey))
    #expect(passkey.passkeyParams?.discoverable == true)
    step = try await flow.respond(.passkey(try await kcDiscoverable.passkeys().assert(passkey.passkeyParams!)), to: passkey)
    guard case .challenges(let next, let context) = step else { Issue.record("expected totp"); return }
    #expect(context.username == "alice")
    step = try await flow.respond(.totp(TOTP.code(secret: Self.aliceTotpSecret)), to: try #require(next.first(.totp)))
    #expect(step.credentials != nil)

    // Wrong key → invalid_credential with a fresh challenge, then cancel.
    let wrong = sdk(clientId: "demo-ios", passkeys: SoftwareAuthenticator(origin: Self.base, wrongKey: true))
    let flow2 = wrong.authentication().startLogin(LoginParameters(scope: "openid"))
    step = try await flow2.start()
    step = try await flow2.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    let challenge = try #require(step.challenges?.first(.passkey))
    try await Task.sleep(for: .seconds(1.1))  // stay outside Keycloak's quick-login window
    step = try await flow2.respond(.passkey(try await wrong.passkeys().assert(challenge.passkeyParams!)), to: challenge)
    #expect(step.challenges?.first(.passkey)?.error?.code == "invalid_credential")
    await flow2.cancel()
  }

  @Test func daveEnrolsAPasskeyInBandOnFirstLogin() async throws {
    let authenticator = SoftwareAuthenticator(origin: Self.base)
    let kc = sdk(clientId: "demo-ios", passkeys: authenticator)
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    step = try await flow.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    guard let password = step.challenges?.first(.password) else {
      Issue.record("dave already has a passkey from a previous run; reset with docker compose down -v")
      await flow.cancel()
      return
    }
    step = try await flow.respond(.password("dave-password"), to: password)
    guard let registration = step.challenges?.first(.passkeyRegistration) else {
      await flow.cancel()
      return  // action already consumed in this container
    }
    #expect(registration.id == "native-passkey-register" && registration.required)
    let params = try #require(registration.passkeyRegistrationParams)
    let attestation = try await kc.passkeys().register(params)
    step = try await flow.respond(.passkeyRegistration(attestation, label: "Dave's phone"), to: registration)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "dave")

    let second = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    step = try await second.start()
    step = try await second.respond(.username("dave"), to: try #require(step.challenges?.first(.username)))
    let passkey = try #require(step.challenges?.first(.passkey))
    step = try await second.respond(.passkey(try await kc.passkeys().assert(passkey.passkeyParams!)), to: passkey)
    #expect(step.credentials != nil)
  }

  @Test func s14BruteForceLockEndsWithAccessDenied() async throws {
    let kc = sdk(clientId: "demo-ios")
    let flow = kc.authentication().startLogin(LoginParameters(scope: "openid"))
    var step = try await flow.start()
    step = try await flow.respond(.username("erin"), to: try #require(step.challenges?.first(.username)))
    var locked: NativeAuthError?
    for attempt in 1...6 {
      guard let password = step.challenges?.first(.password) else { break }
      do {
        step = try await flow.respond(.password("wrong-\(attempt)"), to: password)
      } catch let error as NativeAuthError {
        locked = error
        break
      }
    }
    #expect(locked?.code == NativeAuthError.Code.accessDenied)
    let state = await flow.currentState
    #expect(state == .finished)
  }
}
