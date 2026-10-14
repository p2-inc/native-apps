# KeycloakNative (iOS SDK)

Swift package implementing the client side of the Keycloak Native Authentication Profile
(`../../spec/03-protocol-spec.md`). Product `KeycloakNativeCore` (Swift 6, strict concurrency,
iOS 17+ / macOS 14+, no dependencies): metadata discovery, the challenge state machine, PKCE, DPoP
proofs (Secure Enclave or software key), the passkey bridge over `AuthenticationServices`, token
exchange/refresh/revoke/logout and a Keychain-backed `CredentialsManager`. Design: `../../spec/05`,
decisions: `../../spec/12-phase1b-decisions.md`.

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
```

Errors are always `NativeAuthError`; switch on `code` (`NativeAuthError.Code`): server codes
(`invalid_session`, `access_denied`, `invalid_grant`, `insufficient_authorization`, …) pass through,
SDK codes are `network_error`, `passkey_cancelled` (not a flow failure), `rp_id_mismatch`,
`reauthentication_required`, `flow_state`, `unsupported_challenge`.

## Build and test

```bash
swift build
swift test          # replays keycloak-native-auth/demo/transcripts/*.json through a mock transport
```

On a Mac with only the Command Line Tools (no Xcode) the toolchain has neither XCTest nor the
Testing module and its default build system fails; use

```bash
KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native
```

which adds Apple's `swift-testing` package as a test-only dependency (nothing is added to the
library). Live tests against the demo compose stack run when `KEYCLOAK_NATIVE_LIVE_BASE` is set
(e.g. `http://localhost:8089`), see `Tests/KeycloakNativeCoreTests/LiveServerTests.swift`.

## Not in this phase (marked extension points, no stubs)

`stepUp` / `continueAfterTokenChallenge` (the server rejects the post-login `auth_session` until
step-up exists), `redirect_to_web` + `WebFallback` (surfaced as an error with the body), `otp`,
`push`, `recovery_code`, `select` answers, `KeycloakNativeUI`, `KeycloakNativePush`.
