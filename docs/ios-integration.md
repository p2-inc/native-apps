# Integrating the iOS SDK

[Index](README.md) · [Protocol](protocol-and-flows.md) · [Sample](sample-app.md) · [Android integration](android-integration.md)

## Installation and configuration

The [package manifest](../Package.swift) (at the repository root; sources under `ios/KeycloakNative/`) requires Swift tools 6.0 / Swift language mode 6, iOS 17+ or macOS 14+. Library products have no third-party package dependencies; platform frameworks include AuthenticationServices, CryptoKit, Security and SwiftUI. Repository verification uses Xcode 27 / Swift 6.4; the sample XcodeGen file's `xcodeVersion:16.0` is project metadata, not evidence that Xcode 16 was tested.

Because the manifest is at the repository root, SwiftPM can consume the repository by URL: in Xcode add the package by the repository URL, `https://github.com/p2-inc/native-apps` (or the local checkout's root folder) and link `KeycloakNativeCore`. Add `KeycloakNativeUI` for SwiftUI screens; it depends on Core and Push. Add `KeycloakNativePush` for explicit device enrollment/approval operations. The package identity is the repository name, `native-apps`:

```swift
.package(url: "https://github.com/p2-inc/native-apps", exact: "0.3.0")   // or .package(path: "<path to the checkout root>")
```

and `.product(name: "KeycloakNativeCore", package: "native-apps")` in target dependencies (see the [sample manifest](../ios/KeycloakNativeDemo/Package.swift)). Releases are tags on this repository (see [Releases](../CONTRIBUTING.md#releases)). Before 1.0 any release may change the API, so pin with `exact:` (or `.upToNextMinor(from:)` once you accept patch updates); `from:` would also pull in later breaking `0.x` releases. SwiftPM resolves only plain semantic-version tags (`0.1.0`, not `ios-0.1.0`), so the SDKs and the server share one version line.

Configure a public Keycloak client using the [server setup](README.md#practical-quick-start). Use the **issuer URL including `/realms/<realm>`**, not the challenge endpoint; client ID is separate. PKCE S256 must be required on the client. Register a callback such as `demoapp://auth/callback` for browser fallback; native success itself does not redirect. Use HTTPS outside the local demo. Keep one SDK instance per issuer/client so credentials, DPoP key, metadata cache and refresh coordination remain consistent.

```swift
import Foundation
import KeycloakNativeCore

let kc = KeycloakNative.configure(
  issuer: URL(string: "https://idp.example.com/realms/demo")!,
  clientId: "demo-native"
)
```

[Options](../ios/KeycloakNative/Sources/KeycloakNativeCore/KeycloakNative.swift) defaults: `.dpop = .automatic`, `.allowRpIdMismatch = false`, Keychain service `io.phasetwo.keycloak.native`, metadata cache TTL 300 s, non-ephemeral system-browser preference. Options also accept transport, secure-store, logger, flow observer, passkey platform, web presenter, Keychain access group, presentation anchor, and browser ephemeral preference. Set them **before** `configure`. Use `InMemorySecureStore` only in tests/previews. Automatic DPoP uses Secure Enclave when available/creation succeeds and software P-256 otherwise; `.secureEnclave` explicitly requires that key type. Keep the key available for the life of bound credentials and push enrollment.

## Minimal working SwiftUI integration

This view uses the real public UI product and explicitly persists successful credentials. Create a new flow for each login attempt; pass an **unstarted** flow to `NativeLoginView`, which starts it on appearance. Keep the view alive while a result is being persisted. The application decides navigation after `signedIn` changes.

```swift
import SwiftUI
import KeycloakNativeCore
import KeycloakNativeUI

@MainActor
struct LoginScreen: View {
  let kc: KeycloakNative
  @State private var flow: NativeLoginFlow?
  @State private var signedIn = false
  @State private var message: String?

  var body: some View {
    VStack {
      if signedIn {
        Text("Signed in")
      } else if let flow {
        NativeLoginView(kc: kc, flow: flow) { result in
          switch result {
          case .authorized(let credentials):
            Task { @MainActor in
              do {
                try await kc.credentialsManager().store(credentials)
                signedIn = true
                self.flow = nil
              } catch {
                message = error.localizedDescription
                self.flow = nil
              }
            }
          case .cancelled:
            self.flow = nil
          case .failed(let error):
            message = error.code
            self.flow = nil
          }
        }
      } else {
        Button("Sign in") {
          message = nil
          flow = kc.authentication().startLogin(
            LoginParameters(scope: "openid profile", deviceName: "Example iPhone")
          )
        }
      }
      if let message { Text(message) }
    }
  }
}
```

Default UI handles all implemented challenge types, alternatives, descriptor errors, resend timing, passkey ceremonies, push polling/enrollment and the browser-fallback prompt. It returns `NativeLoginResult.authorized`, `.cancelled`, or `.failed`. It does not store credentials or own your application session/navigation. See [NativeLoginView](../ios/KeycloakNative/Sources/KeycloakNativeUI/NativeLoginView.swift) and [NativeLoginModel](../ios/KeycloakNative/Sources/KeycloakNativeUI/NativeLoginModel.swift).

## Driving custom native screens

Core exposes async APIs; it has no completion-handler or Combine login facade. `NativeLoginFlow` and `CredentialsManager` are actors, `KeycloakNative` is Sendable, and UI models/presentation contexts are `@MainActor`. Update your view model on the main actor, await network calls and serialize submissions; actor isolation alone does not replace a UI submission guard during suspended requests. Custom `FlowObserver` implementations must be Sendable and marshal UI writes to the main actor.

```swift
let flow = kc.authentication().startLogin(
  LoginParameters(scope: "openid profile", deviceName: "Example iPhone")
)
let firstStep = try await flow.start()
```

`startLogin` creates a fresh PKCE pair but sends nothing until `start()`. Retain `flow` and the latest `FlowStep` in your application model:

| `FlowStep` | Application responsibility |
| --- | --- |
| `.challenges([Challenge], FlowContext)` | Render supported choices in server order; collect one response and replace the entire step with its result. Descriptor error is inline feedback, not a thrown terminal error. |
| `.authorized(Credentials)` | Code exchange already succeeded. Explicitly store credentials, clear credential input fields and transition to signed-in UI. |
| `.redirectToWeb(RedirectToWebRequest)` | Offer system browser, keeping original flow/PKCE; call `try await kc.webFallback().complete(request, flow: flow)` and persist its returned credentials. If browser use is unacceptable, end the attempt. |

For example, after a username screen collected `enteredUsername` and selected its returned `Challenge`:

```swift
let nextStep = try await flow.respond(.username(enteredUsername), to: challenge)
```

Do not manufacture challenge IDs, select challenges from an old set, loop over all alternatives, or call `start()` twice on one flow. Use `await flow.pendingChallenges`, `authSession`, `expiresIn`, `currentState` for state inspection; keep the session value private. States are `idle` → `awaitingAnswer` → `finished`. The SDK retains continuation state and validates pending type/ID and answer type before sending. Store an app-generated stable device ID in app configuration if you choose to supply `LoginParameters.deviceId`; SDK does not generate it automatically.

| Challenge / typed params | Submit via `flow.respond(_:to:)` |
| --- | --- |
| `.username` / `usernameParams` | `.username(input)` |
| `.password` / `passwordParams` | `.password(input)` |
| `.totp` / `totpParams` | `.totp(input, credentialId: selectedId)` (ID optional) |
| `.otp` / `otpParams` | `.otp(input)` or `.otpResend`; use `sent`/`resendWait()` to render controls |
| `.recoveryCode` / `recoveryCodeParams` | `.recoveryCode(input)`; warn from `shouldWarn` |
| `.passkey` / `passkeyParams` | `let assertion = try await kc.passkeys().assert(params)` then `.passkey(assertion)` |
| `.passkeyRegistration` / `passkeyRegistrationParams` | `let attestation = try await kc.passkeys().register(params)` then `.passkeyRegistration(attestation, label: label)` |
| `.updatePassword` / `updatePasswordParams` | `.updatePassword(input, confirm: confirmation)`; policy hints do not replace server validation |
| `.verifyEmail` / `verifyEmailParams` | `.verifyEmail(code: input)` or `.verifyEmailResend` |
| `.terms` / `termsParams` | `.terms(accepted: decision)` |
| `.push` / `pushParams` | `.pushResend`, then `.pushPoll` at `pollInterval` while pending; display number-match number |
| `.pushEnrollment` / `pushEnrollmentParams` | Prepare enrollment with Push module, respond with `prepared.answer`, commit locally only after server accepts |
| `.pin` / `pinParams` (PIN extension) | `.pin(input)`; show `length` slots. `invalid_credential` carries `retry.remaining`; `credential_locked` (`challenge.isLocked`) means the PIN must be reset on the web or by an administrator, so offer cancel or another alternative, not a retry |
| `.pinSetup` / `pinSetupParams` (PIN extension) | `.pinSetup(pin: input, confirm: confirmation)`; `isWellFormed(_:)` pre-checks the length; errors `pin_mismatch`, `invalid_format`, `weak_pin` |
| any required action with `isSkippable` | `.skip(challenge.type)` declines it for this login ("Not now"); the default passkey-registration screen shows the button |
| extension or otherwise unmodeled answer | `.custom(type: challenge.type, fields: [FormField("name", "value")])`, sent through the normal pipeline (DPoP, nonce retry, `auth_session` rotation, code exchange) |

Extra request fields (spec/03 §2.3), e.g. a device or risk signal from another SDK: `LoginParameters.additionalParameters` go on the initial request, `continuationParameters` on every continuation, and `flow.respond(_:to:additionalFields:)` adds fields to one request. Use the reserved `x_` prefix; names the protocol or the answer already uses are refused with `invalid_parameter`. `x_*` values are masked in logs and the flow log; other `custom` field values are masked only when their name is in `Redactor.sensitiveKeys`.

`Challenge` has `id`, `type`, `label`, `required`, `error`, `retry`, typed views, raw `params` and raw descriptor. [ChallengeModels](../ios/KeycloakNative/Sources/KeycloakNativeCore/Challenge/ChallengeModels.swift) defines these and form encoding. Unknown types remain `.unknown(String)`. Choose another supported alternative or surface unsupported-method/update guidance. `.select` is recognized but unsupported. Core does not manufacture a fallback PAR for these cases.

To replace one default screen use `.challengePresenter(for: .totp) { context in … }`. Your view receives `ChallengePresentationContext` with current challenge/set/context, `isSubmitting`, `submit`, `switchTo`, passkey/enrollment helpers and `cancel`. To replace alternatives UI use `.challengeChooser`; localization uses `.nativeLoginStrings(bundle:)` and existing English/German string catalog keys. See the sample's [CustomTOTPScreen](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Views/LoginView.swift).

### Password managers

Password AutoFill (iCloud Keychain and third-party managers such as 1Password or Bitwarden) needs two things: the app associated with the site, and fields that say what they hold.

- **Association.** Add an Associated Domains `webcredentials:<domain>` entry for the domain where users' passwords are saved (usually the Keycloak host) and serve `apple-app-site-association` there, the same entry passkeys need (see [sample setup](sample-app.md)). Without it the keyboard can still offer passwords, but not matched to your site, and saved passwords land under the app instead of the domain.
- **Content types.** The default screens set them: `.username` on the username field, `.password` on the password field, `.newPassword` on both update-password fields, `.oneTimeCode` on TOTP, OTP and email-code fields. Custom screens must do the same.
- **Two-step login.** Keycloak asks for the username and the password on separate screens, and password managers pair a password with a username field on the same screen. The default password and update-password screens therefore repeat the username (`FlowContext.username`) in a read-only `.username` field; without it the "Save password?" prompt stores a password with no account, or does not appear. Custom password screens should do the same.
- **Saved-password sheet.** `kc.pickSavedPassword()` shows the system sheet of passwords saved for the associated domains and returns the pick; answer `.username(saved.username)`, then the following `password` challenge with `.password(saved.password)`. The default username and password screens offer it as "Use a saved password" (turn off with `NativeLoginView(offerSavedPasswords: false)`). Closing the sheet is `saved_password_cancelled` and leaves the flow as it was; nothing saved is `saved_password_unavailable`.

Saving needs no code on iOS: the system offers it when a screen with filled `.username` and `.password` fields goes away after a successful submit.

## Tokens and application sessions

```swift
let manager = kc.credentialsManager()
let restored = try await manager.stored()
let credentials = try await manager.credentials(minTTL: 60)
let apiURL = URL(string: "https://api.example.com/me")!
let headers = try await kc.resourceRequestHeaders(
  for: credentials, method: "GET", url: apiURL
)
```

`stored()` returns optional possibly expired credentials. `hasValid(minTTL:)` only checks expiry, not server validity. `credentials(minTTL:)` refreshes when access expiry is within 30 s + requested TTL, serializes concurrent refreshes and persists result. Calls with no credentials throw `credentials_not_found`; direct `Tokens.refresh` does not persist. Access/refresh/ID tokens and post-login session live in `Credentials`; expiry is derived from token response lifetimes. `accessTokenClaims`/`idTokenClaims` are unverified display conveniences.

We recommend enabling DPoP on the server so these tokens are bound to the device key; see [security](security.md#recommended-dpop-for-every-client-refresh-tokens-stay-native) for what that asks of your APIs. Set returned resource headers on your request, preserving exact method/URL for DPoP. Core does not perform resource requests, validate server authorization results, parse every resource server's step-up policy, schedule background refresh or automatically retry business operations.

```swift
let elevatedFlow = try await kc.authentication().stepUp(acrValues: "2")
let elevatedFirstStep = try await elevatedFlow.start()
```

Drive it like a login; store its authorized credentials and retry the protected operation yourself. For a registration `insufficient_authorization` carrying `authSession`/`maxAge`, use `try kc.authentication().continueAfterTokenChallenge(error)` then `await flow.start()`. A plain refresh `invalid_grant` clears stored credentials and maps to `reauthentication_required`; start fresh if no session is provided. The current server never injects a challenge into standard token refresh, although SDK parsing supports one.

For post-login passkey enrollment:

```swift
let credentials = try await kc.credentialsManager().credentials()
let registered = try await kc.passkeys().registerNewPasskey(
  label: "iPhone", credentials: credentials
)
```

Stale authentication needs step-up and a fresh registration attempt; the SDK does not automatically replay registration after the new login. [Passkey setup](sample-app.md#real-passkeys) is required even though the package compiles on a Mac/simulator.

### Biometry-protected credentials

To keep tokens device-only and readable only after Face ID / Touch ID, give the credentials their own store; the DPoP key reference and push enrolment stay in the default store, which the SDK reads on every signed request without user interaction:

```swift
import LocalAuthentication

let context = LAContext()
context.localizedReason = "Unlock your account"
context.touchIDAuthenticationAllowableReuseDuration = 60   // one prompt covers reads for a minute

var options = KeycloakNative.Options()
options.credentialsStore = KeychainStore(
  service: "com.example.app.credentials",
  accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
  accessControl: .biometryCurrentSet,
  authenticationContext: { context })
```

Every `CredentialsManager` read (including the one before a refresh) then needs user authentication; returning the same evaluated `LAContext` avoids a prompt per read. A cancelled or failed authentication surfaces as `keychain_authentication_failed`; `.biometryCurrentSet` items become unreadable when the enrolled biometry changes, so treat that like signed-out credentials and log in again. Writes replace the item (an update of a protected item would itself need authentication). Any other `SecureStore` implementation can be passed the same way.

## Push integration

Import `KeycloakNativePush`; use the same SDK instance/key as the stored native login:

```swift
import KeycloakNativePush

let push = kc.push()
let enrollment = try await push.enroll(deviceLabel: "iPhone")
let pending = try await push.pendingApprovals()
```

Default provider `none` works by fetching approvals. After explicit user approval, call `push.respond(to: approval, .approve(userVerification: chosenNumber))`; use `.deny` for rejection. Never approve on receipt of a notification. Fetch on foreground/pull-to-refresh because delivery may be delayed. `PushApprovalsView(push:)` provides default context/number-match UI.

For APNs request notification permission/register through the application delegate, enroll with `pushProviderType:"apns"`, `pushProviderId:<hex-token>`, and call `try await push.updateAPNsToken(deviceToken)` on changes. `handleNotification` parses a hint and `pendingApproval(for:)` resolves server state; it does not independently verify realm JWT signatures. The [service helper](../ios/KeycloakNative/Sources/KeycloakNativePush/PushNotificationService.swift) can rewrite notification content, but this repository does not ship an installed notification service extension target.

During a `.pushEnrollment` challenge, use `prepareEnrollment(for:deviceLabel:)`, then `flow.respond(prepared.answer,to:challenge)`. If response accepts the action (next step is not its error rechallenge), call `try push.commit(prepared)`. Preparation alone does not persist a valid enrollment. Push state is scoped by issuer/client, like credentials, not separately by user; account switching needs an explicit policy for forgetting/re-enrolling it.

`rotateKey()` registers a fresh key using current proof, then commits it and clears old bound credentials: sign in again. `forgetEnrollment()` only deletes local state; it does not remove the server credential. `lockout()` disables the server user until administrator intervention. Default `NativeDeviceTokenProvider` obtains stored user credentials and requires DPoP binding; a protocol for custom token providers exists, but no secret-based `client_credentials` implementation ships.

## Errors, retries, logout and cancellation

Catch `NativeAuthError` and switch on stable `code`, not display descriptions. It includes `statusCode`, `errorDescription`, optional session/details/max-age. Distinguish inline descriptor errors from thrown HTTP/transport/state errors:

- `invalid_session`, `access_denied`, `invalid_client`, `server_error` finish the Core flow; a new attempt needs a new flow. `invalid_request` can preserve it and update continuation session.
- `network_error` leaves the last local pending state, but server may already have advanced. Offer deliberate retry or restart; there is no general automatic safe replay. A failed token exchange cannot be retried through the finished flow.
- `passkey_cancelled` leaves challenges available; the user can pick another way. `web_fallback_cancelled` follows a terminal native handoff and requires starting again.
- `rp_id_mismatch` requires deployment/configuration correction. Do not ship `allowRpIdMismatch=true` as a workaround.
- `await flow.cancel()` is a best-effort server cancellation of pending native state. Canceling a Swift `Task`/dismissing a custom view is not an explicit server cancel; invoke it when your UI abandons login. There is no in-progress restoration API across process termination.

`await manager.logout()` attempts server logout using stored refresh token and clears local credentials regardless of network result. It does not remove browser SSO, passkeys, push enrollment or DPoP keys, and cannot guarantee server invalidation while offline. For explicit revocation use `try await kc.tokens().revoke(token: refreshToken)` and manage local state separately. Do not equate a successful local restore, credential clear or logout button with universal server token revocation. See [security](security.md).
