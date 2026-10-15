# 05 — iOS SDK Plan (`KeycloakNative`)

Swift Package, Swift 6 (strict concurrency), minimum **iOS 17** (passkeys need 16.6+; 17 simplifies `AuthorizationController` and `SwiftUI` APIs). Core also declares **macOS 14** (it is built and tested there, 12); visionOS can be added later since no UIKit is required in Core.

**Status (Phase 2b, 14):** `KeycloakNativeCore` and `KeycloakNativeUI` exist at `ios/KeycloakNative/` (step-up, `WebFallback`, OTP, recovery codes, the in-band required actions, the default screens with a string catalogue and `.nativeLoginStrings(bundle:)`, and the UI product's own tests included); `KeycloakNativePush` does not yet. Deviations from the API sketched below are listed in 12 D4, 13 D5 and 14 (e.g. `stepUp` is `async`, `WebFallback.complete(_:flow:)` takes the flow, `NativeLoginView(kc:flow:onResult:)`).

## 1. Package products

| Product | Depends on | Purpose |
|---------|-----------|---------|
| `KeycloakNativeCore` | Foundation, CryptoKit, Security, AuthenticationServices | Protocol client, challenge state machine, PKCE, DPoP, JWT utils, Keychain-backed `CredentialsManager`, passkey platform bridge, typed errors. **No UI.** |
| `KeycloakNativeUI` | Core, SwiftUI | Default screens for every challenge type + a `NativeLoginView` that drives the whole flow. All replaceable. |
| `KeycloakNativePush` | Core, UserNotifications | Push-MFA device: Secure Enclave key, enrolment, APNs token sync, confirm-token handling, pending/approve/deny, number-match, lockout, key rotation. Optional `KeycloakNativePushUI` approval sheet lives in `KeycloakNativeUI`. |

Zero third-party dependencies. (Auth0.swift also has none; JWT/JWK/base64url are small enough to implement and audit.)

## 2. Public API (Core)

Modelled on Auth0.swift's factory + protocol style, with a challenge-driven state machine instead of per-factor entry points.

```swift
import KeycloakNative

// Configuration
let kc = KeycloakNative.configure(
    issuer: URL(string: "https://idp.example.com/realms/demo")!,
    clientId: "demo-ios",
    options: .init(dpop: .secureEnclave, redirectToWebCallback: URL(string: "demoapp://auth/callback")!)
)

// Start a login (or step-up)
let flow = kc.authentication().startLogin(scope: "openid profile offline_access", acrValues: nil)
var step = try await flow.start()

// Drive the state machine
loop: while true {
    switch step {
    case .challenges(let challenges, let context):
        // pick one (or let the UI layer do it)
        guard let passkey = challenges.first(where: { $0.type == .passkey }) else { … }
        let assertion = try await kc.passkeys().assert(passkey.passkeyParams!)   // ASAuthorization under the hood
        step = try await flow.respond(.passkey(assertion), to: passkey)
    case .authorized(let credentials):
        try kc.credentialsManager().store(credentials)
        break loop
    case .redirectToWeb(let request):
        let credentials = try await kc.webFallback().complete(request)             // ASWebAuthenticationSession + PKCE + token exchange
        break loop
    }
}
```

### 2.1 Types

```swift
public enum FlowStep: Sendable {
    case challenges([Challenge], FlowContext)
    case authorized(Credentials)
    case redirectToWeb(RedirectToWebRequest)
}

public struct Challenge: Sendable, Identifiable {
    public let id: String                 // challenge_id
    public let type: ChallengeType        // .username, .password, .passkey, .passkeyRegistration, .totp, .otp, .push, .recoveryCode, .select, .unknown(String)
    public let label: String?
    public let required: Bool
    public let error: ChallengeError?     // previous attempt failed
    public let retry: RetryInfo?
    public let rawParams: [String: JSONValue]
    // typed accessors
    public var passkeyParams: PasskeyAssertionParams?
    public var passkeyRegistrationParams: PasskeyRegistrationParams?
    public var otpParams: OTPParams?
    public var pushParams: PushParams?
    …
}

public enum ChallengeAnswer: Sendable {
    case username(String)
    case password(String)
    case passkey(PasskeyAssertion)                    // from kc.passkeys().assert(_)
    case passkeyRegistration(PasskeyAttestation, label: String?)
    case totp(String, credentialId: String? = nil)
    case otp(String)
    case otpResend
    case push(PushPollAction)                         // .poll | .cancel
    case recoveryCode(String)
    case select(challengeId: String)
    case cancel
}

public protocol LoginFlow: Sendable {
    func start() async throws -> FlowStep
    func respond(_ answer: ChallengeAnswer, to challenge: Challenge) async throws -> FlowStep
    var authSession: String? { get }     // exposed so apps can persist/inspect; Core persists it automatically
}
```

Completion-handler and Combine variants are generated from the async API (as Auth0.swift does) so UIKit apps are not forced into async/await.

### 2.2 Clients (all protocol-typed, obtained from `kc`)

| Client | Methods |
|--------|---------|
| `Authentication` | `startLogin(...)`, `stepUp(acrValues:maxAge:)`, `continueAfterTokenChallenge(_ error:)` (handles `insufficient_authorization` from refresh), `metadata()` |
| `Passkeys` | `assert(_ params:) async throws -> PasskeyAssertion`, `register(_ params:) -> PasskeyAttestation`, `registerNewPasskey(label:)` (authenticated, uses §6 endpoints), supports `preferImmediatelyAvailableCredentials` and autofill (`performAutoFillAssistedRequests`) |
| `CredentialsManager` | `store`, `credentials()` (auto-refresh; surfaces `.reauthenticationRequired(flow)` when refresh returns a challenge), `clear`, `enableBiometrics(title:)`, `hasValid` |
| `WebFallback` | `complete(_ request:)` runs `ASWebAuthenticationSession` with PAR `request_uri`, PKCE from the original flow, exchanges the code |
| `Tokens` | `exchange(code:)`, `refresh`, `revoke`, `logout` (RP-initiated), all DPoP-aware |
| `Push` (in KeycloakNativePush) | see §5 |

### 2.3 Error model

```swift
public struct NativeAuthError: Error, Sendable {
    public let code: String              // stable: "invalid_session", "access_denied", "network_error", "passkey_cancelled", "invalid_dpop_proof", …
    public let statusCode: Int?
    public let description: String?
    public let authSessionStillValid: Bool
    public let isNetworkError: Bool
    public let isRetryable: Bool
    public let underlying: Error?
}
```
Rule (borrowed from Auth0 docs): apps switch on `code`, never on messages. All codes are listed in a `NativeAuthError.Code` namespace and in the SDK docs.

## 3. Internals

### 3.1 Challenge transport
- `ChallengeEndpointClient`: builds `application/x-www-form-urlencoded` bodies, attaches `DPoP` proof when configured, parses 200/403/400, tolerates 400 for `insufficient_authorization`, maps unknown challenge types to `.unknown`.
- `AuthSessionStore`: in-memory during a flow; persisted to Keychain (per issuer+client) on success so `stepUp` and `continueAfterTokenChallenge` work across launches.
- `PKCE`: 32-byte verifier, S256 challenge, per flow.
- `DPoP`: `DPoPKey` protocol with `SecureEnclaveDPoPKey` (ES256, `kSecAttrTokenIDSecureEnclave`) and `SoftwareDPoPKey` (CryptoKit P256, for simulators). Proof builder handles `htm/htu/iat/jti/ath/nonce` and retries once on `use_dpop_nonce`.
- JOSE utilities: base64url, compact JWS sign/verify (ES256/RS256), JWK thumbprint (RFC 7638), JWKS fetch+cache with `kid` rotation handling.

### 3.2 Passkey bridge
- Wraps `ASAuthorizationPlatformPublicKeyCredentialProvider` (relying party = `rp_id` from params; the SDK asserts it matches the host unless `allowRpIdMismatch` is set for testing).
- Maps `PasskeyAssertionParams.allowCredentials` → `allowedCredentials`; `user_verification` → `userVerificationPreference`.
- Returns `PasskeyAssertion(credentialId, clientDataJSON, authenticatorData, signature, userHandle)` as base64url strings — exactly the §4.3 wire fields.
- Cancellation (`ASAuthorizationError.canceled`) → `code = "passkey_cancelled"`, not a failure of the flow (the app can offer another challenge).
- Registration mirrors this with `createCredentialRegistrationRequest`.

### 3.3 Logging
- `KeycloakNative.logger` protocol; default `os.Logger` with **automatic redaction** of `auth_session`, codes, tokens, passwords, OTPs (regex on form keys + JSON keys). Debug mode prints request/response shapes with values masked.

## 4. UI layer (`KeycloakNativeUI`) and customisation model

Goal: an app can use the whole default experience in one line, or replace any single screen, or ignore the UI product entirely.

```swift
// 1. Whole flow, default screens
NativeLoginView(flow: kc.authentication().startLogin()) { result in … }
    .nativeLoginTheme(.init(accent: .indigo, logo: Image("logo")))

// 2. Replace one challenge screen
NativeLoginView(flow: …) { result in … }
    .challengePresenter(for: .totp) { ctx in
        MyTOTPScreen(onSubmit: { code in ctx.submit(.totp(code)) }, error: ctx.challenge.error)
    }

// 3. Full control: use Core only and render your own screens from FlowStep
```

- `ChallengePresenter` = `(ChallengePresentationContext) -> some View`. The context exposes the `Challenge`, `FlowContext`, `submit(_:)`, `switchTo(challenge:)`, `cancel()`, `isSubmitting`.
- The `.challenges([...])` step with several alternatives is rendered by a `ChallengeChooser` (also replaceable). Default behaviour: auto-select passkey when available and the device supports it; show other options under "Try another way".
- Provided default screens: Username, Password, PasskeyPrompt (shows a button that triggers the platform sheet, with autofill variant), PasskeyRegistration, TOTP (6-digit field with paste/autofill of `oneTimeCode`), OTP (with resend countdown and masked destination), PushWait (spinner + number-match digit + "cancel"), RecoveryCode, RedirectToWeb (explains fallback), ErrorScreen.
- Localisation: `Localizable.xcstrings` in the package; apps override by supplying their own `Bundle` via `.nativeLoginStrings(bundle:)`.
- Accessibility: all defaults pass VoiceOver + Dynamic Type; `oneTimeCode` text content type for SMS autofill.

## 5. Push module (`KeycloakNativePush`)

```swift
let push = kc.push()

// Enrolment from inside the app (user already logged in natively)
try await push.enroll(deviceLabel: UIDevice.current.name, accessTokenProvider: kc.credentialsManager())
// or from a QR / deep link
try await push.enroll(enrollmentURL: url, …)

// APNs
push.updateAPNsToken(deviceToken)                       // call from didRegisterForRemoteNotificationsWithDeviceToken; syncs via PUT /device/push-provider when changed

// Notification handling
let pending = try await push.handleNotification(userInfo)   // verifies confirmToken, fetches /login/pending → [PendingApproval]
try await push.respond(to: pending[0], action: .approve(userVerification: "42"))

// Other
try await push.pendingApprovals()      // poll on app foreground (push may be delayed/dropped)
try await push.rotateKey()
try await push.lockout()               // panic button
push.isEnrolled, push.credential       // local state
```

Design notes
- **Keys:** one Secure Enclave ES256 key per enrolment; `credentialId` random 16 bytes base64url; `deviceId` UUID persisted in Keychain (survives reinstall is *not* desired → store with `ThisDeviceOnly`).
- **Device access token:** ba-itsys obtains a DPoP-bound token with `client_credentials` on `push-device-client`. A secret in a public app is weak; see 08 Q6 for the recommended replacement (token exchange from the user's native token, or a secret-less client with DPoP + attestation). The SDK abstracts this behind `DeviceTokenProvider` so the strategy can change without touching callers.
- **Notification type:** send both an alert push (so the user is prompted) and include `confirmToken` in the payload; the SDK also exposes a `UNNotificationServiceExtension` helper to fetch `/login/pending` and rewrite the notification body to "Approve sign-in to *Demo Web* from Chrome on macOS?" before display. Time-sensitive interruption level.
- **Number match UX:** the three numbers from `userVerification.numbers` are shown as buttons; the browser shows one; mismatch → `403` → show error, allow one retry, then deny.
- **Deny by default on expiry**: if the user ignores the prompt the SDK does nothing (server expires it); if the user explicitly dismisses, send `deny`.
- **Background polling** via `BGAppRefreshTask` is optional and off by default.

## 6. Credentials & storage

- Keychain items keyed by issuer + clientId; accessibility `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; optional `SecAccessControl` with `biometryCurrentSet` for "require Face ID to use stored credentials".
- Stored: access token, refresh token, id token, expiry, scope, `auth_session`, DPoP key reference (not the key), push credential metadata.
- Refresh: serialised with an actor to avoid concurrent refreshes; `insufficient_authorization` → `CredentialsManagerError.reauthenticationRequired(LoginFlow)` carrying a ready-to-run flow with the returned `auth_session`.

## 7. Testing

- Unit tests (Swift Testing) with a `MockTransport` replaying the recorded transcripts in `keycloak-native-auth/demo/transcripts/` (the **same fixtures** the Keycloak integration tests produce → contract tests both sides, 12 D1); live tests against the compose stack behind `KEYCLOAK_NATIVE_LIVE_BASE`.
- Passkey bridge tested on device via the example app; in CI, inject a `PasskeyPlatform` protocol mock.
- DPoP/JWS vectors from RFC 9449 and RFC 7515 appendices.
- UI tests (XCUITest) for the default screens against a local Keycloak started by `docker compose` in CI (self-hosted macOS runner or Keycloak in a Linux job exposed via tunnel — decide in Phase 1).

## 8. Distribution & docs

- SwiftPM via GitHub releases; semantic versioning; `Package.swift` exposes the three products.
- DocC catalogue with articles: Getting started, Passkeys setup (Associated Domains, RP ID), Customising screens, Push MFA setup (APNs, entitlements, notification service extension), Step-up, Migrating from ASWebAuthenticationSession, Error codes reference.
- An `EXAMPLES.md` in the Auth0 style (callback / async / Combine for each operation).
