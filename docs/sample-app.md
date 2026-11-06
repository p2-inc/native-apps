# Running and understanding the sample app

[Index](README.md) · [iOS integration](ios-integration.md) · [Protocol examples](flow-examples.md)

## Build and launch

Run the server [quick start](README.md#practical-quick-start) on **8089**. From `ios/KeycloakNativeDemo`:

```bash
swift build
xcodebuild -list -project KeycloakNativeDemo.xcodeproj
xcrun simctl list devices available
xcodebuild -project KeycloakNativeDemo.xcodeproj -scheme KeycloakNativeDemo \
  -destination 'generic/platform=iOS Simulator' CODE_SIGN_IDENTITY="-" build-for-testing
```

Open the committed `KeycloakNativeDemo.xcodeproj` in Xcode, choose application scheme **KeycloakNativeDemo**, select a simulator, and Run. Package-library schemes are not executables. The generated project is committed; XcodeGen is needed only when regenerating from [project.yml](../ios/KeycloakNativeDemo/project.yml): `xcodegen generate` in that directory. Keep simulator ad hoc signing; disabling signing can cause Keychain `-34018`.

[Config.plist](../ios/KeycloakNativeDemo/App/Config.plist) supplies `Issuer=http://localhost:8089/realms/demo`, `ClientId=demo-ios`, `PasskeyClientId=demo-ios-passkey`, `StepUpClientId=demo-ios-stepup`, `OtpClientId=demo-ios-otp`, `ResourceServer=http://localhost:8091`, `AllowRpIdMismatch=false`, `DeviceName=KeycloakNativeDemo`. [DemoConfig](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/DemoConfig.swift) loads these from the app bundle and has matching fallback defaults. There is no settings UI. On a physical device, `localhost` is that device; use a reachable correctly configured HTTPS server/issuer.

Begin with S3 (alice/password/TOTP; current code from the walkthrough), or bob/password on a regular flow to skip second factor. Home's claims/token type/expiry and a successful `/token` exchange in Diagnostics confirm SDK completion. A `.challenges` username/context value alone does not mean authentication succeeded.

## Implementation map

| File | Role |
| --- | --- |
| [KeycloakNativeDemoApp.swift](../ios/KeycloakNativeDemo/App/KeycloakNativeDemoApp.swift) | `@main`, application delegate wiring, model creation and root view |
| [AppDelegate.swift](../ios/KeycloakNativeDemo/App/AppDelegate.swift) | Notification permission/APNs callbacks and tapped notification forwarding |
| [RootView.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Views/RootView.swift) | Environment model, tab navigation and startup restoration; approvals refresh is handled separately by its view |
| [DemoModel.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/DemoModel.swift) | `@MainActor @Observable`; owns SDK instances keyed by client ID, active flow/step, input fields, credentials, status, enrollment and diagnostics |
| [Scenario.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Scenario.swift) | Scenario title/help, selected client role and prefilled username |
| [LoginView.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Views/LoginView.swift) | Challenge-type switch, native fields/buttons, OTP resend countdown, push poll task; also default UI and custom TOTP presenter |
| [HomeView.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Views/HomeView.swift) | Claims, passkey enrollment, protected transfer, refresh/logout, push controls and approvals navigation |
| [DiagnosticsView.swift](../ios/KeycloakNativeDemo/Sources/KeycloakNativeDemoApp/Views/DiagnosticsView.swift) | Metadata/key thumbprint and redacted request/response log; copy/clear controls |

`DemoModel.startLogin()` makes a flow and awaits `start()`. `apply` stores the returned `FlowStep`; LoginView renders all offered challenge sections, collects input, and calls `answer(_:to:)`. Server execution order controls the screens; the app does not independently choose which factors must succeed. `run` owns a busy flag and catches errors; passkey cancellation preserves choices, terminal invalid-session/access-denied clears pending UI. Push screen's task polls by challenge `cid` at the supplied interval. UI actions launch async `Task`s; model changes stay on the main actor. S5/S13 instead pass an unstarted flow to `NativeLoginView`, with S13 replacing only TOTP via `challengePresenter`.

On authorized, `apply` sets in-memory credentials, clears flow and launches a task to store credentials. Restore at launch reads only the **standard client's** credentials and can display expired ones until an explicit refresh. Switching scenarios changes the active SDK/client. Step-up/error recovery retains a new flow for Login tab; after successful step-up the user retries Transfer or Register passkey manually. Browser fallback retains the original flow for its PKCE verifier and offers Open browser. Native flow state is not restored across process restarts.

## Walkthrough scenarios

| Scenario | Client/flow and actions |
| --- | --- |
| S1, S3 | `demo-ios` / `native`: username → passkey or password → configured second factor. S1 needs a previously registered passkey; S3 works from fresh export. |
| S2 | `demo-ios-passkey` / `native-passkey-first`: discoverable passkey or username/password branch, then conditional TOTP |
| S4 | `demo-ios-otp` / `native-otp`: bob gets email code automatically; alice chooses TOTP or requests code. Inbox `http://localhost:8025`. |
| S5, S13 | Same OTP client using default SDK UI; S13 substitutes the TOTP screen |
| S6 | `demo-ios-stepup` / `native-step-up`: initial ACR 1, Home → Transfer → Login TOTP → retry Transfer with ACR 2 |
| S7 | frank/password → `UPDATE_PROFILE` unsupported natively → system browser login/profile completion → callback/token exchange |
| S8 | Home “End session on the server” revokes refresh token but keeps local copy; “Refresh tokens” then demonstrates `reauthentication_required` |
| S9, S10, S12 | Standard client: enroll on Home → approve browser/native sign-in from Sign-in requests → token/provider/key/lockout maintenance |
| S11 | After login, Home → Register passkey; stale auth triggers reauthentication on Login, then retry registration |
| S14 | erin; automatic deliberate wrong-password sequence until Keycloak lockout; uses `demo-ios`, not your production account |
| Dave | `native-passkey-register` required action after password → native platform registration → tokens |
| Carol, Grace, Hank | Password → native password update / email code verification / terms acceptance → tokens (declining terms fails) |
| Ivy | Password → TOTP or recovery code; last recovery code triggers browser-only code generation |
| Judy | Password → native push enrollment using same DPoP key → tokens; later login asks for push |

All usernames above use `<username>-password` initially. Consumed actions, codes and enrolled devices persist in the demo database. Resetting with `docker compose down -v` **deletes** that database; use it only for a disposable demo. SMS client and alternative-factor client have protocol/tests but no dedicated sample scenario/client-config key. Their server layouts and setup are documented in [flow examples](flow-examples.md).

## Real passkeys

The package can compile without an Apple team, but functioning platform passkeys need deployment setup. The export's localhost policy does not supply an associated real domain.

1. Expose Keycloak at a stable HTTPS domain you control, e.g. `idp.example.com`, through a configured reverse proxy/tunnel. Configure Keycloak's public hostname/proxy handling so metadata and WebAuthn origin use the actual HTTPS origin. The existing [passkey setup notes](../ios/KeycloakNativeDemo/README.md#2-real-passkeys-s1-s2-s11-dave-https-host--associated-domains) include a proxy example; verify generated endpoint URLs rather than assuming tunnel headers are accepted.
2. Serve `https://idp.example.com/.well-known/apple-app-site-association` as JSON containing `{"webcredentials":{"apps":["<TEAMID>.io.phasetwo.keycloak.nativedemo"]}}`. Keycloak does not serve this file; the proxy/host must.
3. In realm WebAuthn **Passwordless** policy set RP ID `idp.example.com`. Keep UV/resident key/algorithms consistent with the app's platform. Keycloak must accept the platform's `client_data_json.origin`: use its public base origin or deliberately configured extra origin.
4. Set app `Issuer=https://idp.example.com/realms/demo`, `AllowRpIdMismatch=false`, and [entitlements](../ios/KeycloakNativeDemo/App/KeycloakNativeDemo.entitlements) to `webcredentials:idp.example.com` (development-only `?mode=developer` is described in the existing notes). Sign with the appropriate team/profile; use a device or suitable simulator signed into iCloud Keychain. RP mismatch override does not bypass Apple's association rules.
5. S3 → S11 Register passkey → S1 identified login → S2 discoverable login. Dave demonstrates mid-flow registration on a fresh realm. Exercise platform cancellation and alternative password login as well.

## Push and browser setup

For simulator push, enroll alice on Home with provider `none`, then start a browser account login at `http://localhost:8089/realms/demo/account`. Approve from Home → Sign-in requests. S10's native requester shows a number; choose it in the approvals view and let Login poll. This can demonstrate both sides on the same sample installation using previously stored credentials; new app integrations must deliberately preserve a usable approving session.

Real APNs requires Apple signing/push capability, APNs token, and server `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_KEY`, matching `APNS_TOPIC` and correct sandbox/production environment. The checked-in app entitlements/project do not configure an `aps-environment` entitlement or notification service extension target; those are additional app provisioning work, not supplied end-to-end delivery. “Simulate APNs token” only updates a fake token; it does not prove delivery. Key rotation clears credentials; lockout disables the account. Review [Push SDK](ios-integration.md#push-integration) before exercising maintenance.

For S7 register `demoapp://auth/callback` on the client (export already does). `ASWebAuthenticationSession` uses its callback scheme and returned state; the checked-in Info.plist does not declare a URL type. This SDK path is handled by the system session callback, not a general app deep-link router. An app implementing separate deep-link routing must configure that independently. The native session is gone after handoff; browser cancellation requires a new attempt.

## Android demo

[android/demo](../android/demo/README.md) is the Android counterpart, with Login, Home, Push and Diagnostics tabs on the SDK's default Compose screens. From the emulator the compose stack is `http://10.0.2.2:8080`. Real FCM delivery needs a Firebase project, its `google-services.json` and the server override `keycloak-native-auth/demo/docker-compose.fcm.yml` with the service account. Real passkeys need an HTTPS RP ID that serves `assetlinks.json`, and the app's `android:apk-key-hash:` origin in the Passwordless policy. Its README has the steps.

## Sample shortcuts to replace

Development HTTP/`NSAllowsLocalNetworking`, admin credentials, seeded passwords/TOTP/recovery codes and permissive dev hostname settings are local conveniences. Demo OTP reuse is enabled for repeatable tests. Password/OTP inputs live in model strings; clear them promptly in a production app. `apply` stores asynchronously with `try?`, hiding persistence errors; production code should await storage and handle failure before treating restoration as reliable. Scenario switching drops `flow` without canceling server state, restore only covers one client, and credentials/enrollment are not scoped separately by user. Provide deliberate account switching, cancellation, navigation, refresh and error policies.

Home's forced-expiry refresh helper is for demonstration. Claims are explicitly unverified display values. Logout clears local tokens and attempts server logout but leaves push enrollment, key and browser cookies. Diagnostics can expose identifying metadata even after secret masking; do not make copied logs a production token/account export mechanism.
