# KeycloakNative (iOS SDK)

Swift package implementing the client side of the Keycloak Native Authentication Profile
(`../../spec/03-protocol-spec.md`). Products (Swift 6, strict concurrency, iOS 17+ / macOS 14+, no
dependencies):

- `KeycloakNativeCore`: metadata discovery, the challenge state machine, PKCE, DPoP proofs (Secure
  Enclave or software key; the server binds session, code and tokens to the key), the passkey bridge
  over `AuthenticationServices`, step-up / re-authentication with the post-login `auth_session`, the
  browser fallback (`WebFallback` over `ASWebAuthenticationSession`), email/SMS one-time codes, the
  in-band required actions (`updatePassword`, `verifyEmail`, `terms`, `passkeyRegistration`), token
  exchange/refresh/revoke/logout and a Keychain-backed `CredentialsManager`.
- `KeycloakNativePush`: push MFA for this device (spec/05 §5, spec/14 D9) — `kc.push()`: enrolment
  from inside the app (`enroll`, through `/native-auth/push/enroll/start` and ba-itsys'
  `/push-mfa/enroll/complete`) or mid-flow (`prepareEnrollment` for the `push_enrollment` challenge,
  then `commit`), `pendingApprovals`, `respond(to:_:)` with number match, `handleNotification`,
  `updateAPNsToken`, `rotateKey`, `lockout`, `DeviceTokenProvider` (default: the user's own
  DPoP-bound native tokens — the DPoP key is the device key, spec/03 §7.1) and a
  `UNNotificationServiceExtension` helper (`PushNotificationService.rewrite`).
- `KeycloakNativeUI`: `NativeLoginView` drives a flow with default SwiftUI screens for every
  challenge type (username, password, TOTP, OTP with resend countdown, passkey, passkey registration,
  recovery code, update password with policy hints, verify email, terms, push with number match and
  polling, push enrolment, browser fallback), `PushApprovalsView` (the pending sign-in requests with
  approve / deny / number buttons and pull-to-refresh) and a
  "Try another way" chooser; any screen is replaceable with `.challengePresenter(for:)`, the chooser
  with `.challengeChooser`. Texts come from the package's `Localizable.xcstrings` (English, German);
  `.nativeLoginStrings(bundle:)` overrides any key from the app's own bundle.

Design: `../../spec/05`, decisions: `../../spec/12-phase1b-decisions.md` and
`../../spec/13-phase2-decisions.md`.

```swift
import KeycloakNativeCore

let kc = KeycloakNative.configure(issuer: URL(string: "https://idp.example.com/realms/demo")!, clientId: "demo-ios")
let flow = kc.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: "My iPhone"))
var step = try await flow.start()
loop: while true {
  switch step {
  case .challenges(let challenges, let context):
    if let passkey = challenges.first(where: { $0.type == .passkey }), let params = passkey.passkeyParams {
      let assertion = try await kc.passkeys().assert(params)            // ASAuthorizationController
      step = try await flow.respond(.passkey(assertion), to: passkey)
    } else if let username = challenges.first(where: { $0.type == .username }) {
      step = try await flow.respond(.username("alice"), to: username)
    } // password, totp, passkeyRegistration likewise; unknown types stay in the list as .unknown
  case .authorized(let credentials):
    try await kc.credentialsManager().store(credentials)                // Keychain; post-login auth_session kept
    break loop
  }
}
let fresh = try await kc.credentialsManager().credentials()           // refreshes when expired
let passkey = try await kc.passkeys().registerNewPasskey(label: "iPhone", credentials: fresh)  // spec/03 §6

// Step-up (spec/03 §5): after a resource server answered 401 insufficient_user_authentication acr_values=2
let stepUp = try await kc.authentication().stepUp(acrValues: "2")   // uses the stored post-login auth_session
// drive `stepUp` like a login: the username step is skipped, only the missing level is asked,
// .authorized carries tokens for the same session with acr=2
let headers = try await kc.resourceRequestHeaders(for: fresh, method: "GET", url: api)  // Bearer, or DPoP + proof

// Browser fallback (spec/03 §3.4)
if case .redirectToWeb(let request) = step {
  let credentials = try await kc.webFallback().complete(request, flow: flow)   // ASWebAuthenticationSession
}

// Default UI
NativeLoginView(kc: kc, flow: kc.authentication().startLogin()) { result in /* .authorized / .cancelled / .failed */ }
  .challengePresenter(for: .totp) { ctx in MyTOTPScreen(ctx) }
```

Errors are always `NativeAuthError`; switch on `code` (`NativeAuthError.Code`): server codes
(`invalid_session`, `access_denied`, `invalid_grant`, `insufficient_authorization`,
`invalid_dpop_proof`, …) pass through, SDK codes are `network_error`, `passkey_cancelled` and
`web_fallback_cancelled` (not flow failures), `rp_id_mismatch`, `reauthentication_required`,
`credentials_not_found`, `flow_state`, `unsupported_challenge`. An `insufficient_authorization` from
the registration endpoints carries `authSession` and `maxAge`: hand it to
`authentication().continueAfterTokenChallenge(error)` for the step-up.

## Build and test

```bash
swift build
swift test          # Core: replays keycloak-native-auth/demo/transcripts/*.json through a mock transport
                    # UI: NativeLoginModel behaviour with a scripted transport, the string catalogue and overrides
```

With Xcode installed this is all that is needed (verified with Xcode 27 / Swift 6.4).

On a Mac with only the Command Line Tools (no Xcode) the toolchain has neither XCTest nor the
Testing module and its default build system fails; use

```bash
KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native
```

which adds Apple's `swift-testing` package as a test-only dependency (nothing is added to the
library). Live tests against the demo compose stack run when `KEYCLOAK_NATIVE_LIVE_BASE` is set
(e.g. `http://localhost:8089`; they also use mailpit on `:8025` and the resource server on `:8091`,
override with `KEYCLOAK_NATIVE_LIVE_MAILPIT` / `KEYCLOAK_NATIVE_LIVE_RESOURCE`), see
`Tests/KeycloakNativeCoreTests/LiveServerTests.swift` and `LivePushTests.swift` (push: the test is
both the native client and the "phone"; the realm's `web-app` browser login is driven with a
cookie-keeping `URLSession`).

## Push MFA in an app (spec/14 D9)

```swift
let push = kc.push()                                   // device token = the stored native login (DPoP-bound)
try await push.enroll(deviceLabel: UIDevice.current.name, pushProviderType: "apns", pushProviderId: apnsTokenHex)
let pending = try await push.pendingApprovals()        // also on foreground / pull-to-refresh: APNs may be late
try await push.respond(to: pending[0], .approve(userVerification: "42"))   // number match
try await push.updateAPNsToken(deviceToken)            // from didRegisterForRemoteNotificationsWithDeviceToken
try await push.rotateKey()                             // new DPoP key; the stored tokens are dropped, sign in again
try await push.lockout()                               // panic button: ba-itsys disables the account
```

The enrolment, the device JWTs, the confirm token and the APNs token are masked by the `Redactor`
before anything reaches a log. Key rotation rotates the SDK's DPoP key (the push credential and the
token binding share it), so a new login follows. `DeviceTokenProvider` is the extension point for a
stock ba-itsys install that wants `client_credentials` on a device client (no such provider ships:
it would need a secret the app cannot hold).

## Not in this phase (marked extension points, no stubs)

`select` answers (no server-side authenticator emits them), completion-handler / Combine variants
of the async API, a `client_credentials` `DeviceTokenProvider`.
