# 17 — Android SDK plan (`keycloak-native-android`)

**Date:** 23 October 2026
**Status:** plan; nothing implemented. Replaces the one-line "Phase 5 — Android" of 08 and 10.
**Builds on:** 03 (the protocol, unchanged), 05 (the iOS SDK, the reference implementation), 15 (`skip`, `custom`, `x_*`), 16 (Keycloak 26.4–26.8).

The protocol is platform-neutral and the iOS SDK proves the client shape, so the Android SDK is a **port of the iOS SDK's state machine onto Android's platform APIs**, verified against the **same transcripts**. This document fixes what differs on Android, what the server and the spec still lack, and the order of work.

## 1. Readiness

| Area | State | Gap |
|---|---|---|
| Wire protocol (03 §1–§6, §8) | frozen v1.0-rc + additive 15 | none for the login flow |
| Conformance fixtures | `keycloak-native-auth/demo/transcripts/*.json`: plain JSON (method, path, headers, form, body), masked secrets | none; a Kotlin harness reads them as the Swift one does |
| Passkeys (server) | `native-passkey` / `native-passkey-register` verify through Keycloak's `WebAuthnCredentialProvider`, which applies the Passwordless policy's extra origins; **`AndroidOriginIT`**: a passkey with origin `android:apk-key-hash:<…>` registers and signs in once that origin is an extra origin, and is refused without it (§6 A1, done) | operator setup only: extra origins + `assetlinks.json` |
| Push MFA (server) | ba-itsys ships an `fcm` sender (URL and service-account `token_uri` configurable) | not installed or tested in the demo; no FCM transcript; 03 §7 examples say `ios` / `apns` only |
| Push device API (03 §7) | draft | `deviceType: "android"`, `pushProviderType: "fcm"`, `pushProviderId` = FCM registration token to be written down |
| iOS on hardware | simulator only | a device pass (passkeys, Secure Enclave, real APNs) is still open; see §7 |

## 2. Modules

Gradle (Kotlin DSL), Kotlin 2.x, coroutines. Group `io.phasetwo.keycloak.native`, artifacts on Maven Central once distribution is decided (same question as SwiftPM tags, 15).

| Module | Kind | Depends on | Content |
|---|---|---|---|
| `core` | **Kotlin/JVM** (no Android) | kotlinx-coroutines, kotlinx-serialization-json | metadata, the challenge state machine (`NativeLoginFlow`), `ChallengeAnswer` incl. `skip` / `custom`, extra fields, PKCE, DPoP proof building over a `DPoPKey` interface, `Tokens`, `CredentialsManager` over a `SecureStore` interface, `Transport` interface + `HttpURLConnection` default, redaction, typed errors with the iOS codes |
| `android` | Android library | `core`, `androidx.credentials`, `androidx.browser` | `CredentialManagerPasskeyPlatform`, `KeystoreDPoPKey` (StrongBox when available), `KeystoreSecureStore`, `AuthTabWebPresenter` / Custom Tabs fallback |
| `push` | Android library | `core`, `android`, Firebase Messaging | enrolment (in-app and mid-flow), approvals with number match, FCM token sync, key rotation, lockout |
| `ui` | Android library | `core`, `push`, Jetpack Compose | `NativeLoginScreen` and one default composable per challenge type, chooser, per-type overrides, string resources (en, de) |
| `demo` | Android app | all | the iOS demo's scenarios (06) where the platform allows |

`core` is plain JVM so the transcript replay, the state machine and DPoP/PKCE run as ordinary JUnit tests on any JDK: no emulator, no Android SDK. It mirrors `KeycloakNativeCore` type for type (Swift enum ↔ Kotlin sealed interface) so a fix in one SDK maps to the other.

## 3. Platform mapping

| Concern | iOS (05) | Android |
|---|---|---|
| Passkey assertion / registration | `ASAuthorizationPlatformPublicKeyCredentialProvider` | Credential Manager: `GetPublicKeyCredentialOption(requestJson)` / `CreatePublicKeyCredentialRequest(requestJson)`; the SDK converts 03 §4.3/§4.4 snake_case `params` to WebAuthn JSON (`PublicKeyCredentialRequestOptionsJSON` / `…CreationOptionsJSON`, camelCase, base64url) and the `authenticationResponseJson` / `registrationResponseJson` back to the 03 form fields |
| App ↔ RP-ID association | Associated Domains `webcredentials:` + AASA | Digital Asset Links `https://<rp_id>/.well-known/assetlinks.json` with `delegate_permission/common.get_login_creds` for the app's package and signing-cert fingerprint |
| `client_data_json.origin` | `https://<rp_id>` | `android:apk-key-hash:<base64url SHA-256 of the signing cert>`: must be in the Passwordless policy's **extra origins** (one per signing key: debug, upload, Play App Signing) |
| DPoP / device key | Secure Enclave, software fallback | Android Keystore EC P-256 (`setIsStrongBoxBacked(true)`, fallback without StrongBox on `StrongBoxUnavailableException`); `SHA256withECDSA` gives DER, the proof needs raw `R‖S` (64 bytes) |
| Secure storage | Keychain, optional `SecAccessControl` (`KeychainStore(accessControl:)`, `Options.credentialsStore`) | Keystore AES-GCM key wrapping a small file/DataStore; optional `setUserAuthenticationRequired` + `BiometricPrompt` with a `CryptoObject`, the analogue of `KeychainStore(accessControl:)` (Jetpack `EncryptedSharedPreferences` is deprecated and not used) |
| Browser fallback (03 §3.4) | `ASWebAuthenticationSession` | Auth Tab (`androidx.browser` `AuthTabIntent`) where the browser supports it, else Custom Tabs + a redirect activity for the registered `redirect_uri` (App Link `https` preferred over a custom scheme) |
| Push | APNs, notification service extension | FCM data message → `FirebaseMessagingService`; the confirm token is verified and resolved locally as on iOS; `deviceType: "android"`, `pushProviderType: "fcm"` |
| Async API | `async`/`await`, actors | `suspend` functions, `Mutex` for the serialised refresh; `Flow` only where a stream is natural (approvals) |
| UI | SwiftUI, string catalogue | Compose, `strings.xml` (en, de), `CompositionLocal` for strings/theme and per-type overrides |

## 4. Public API sketch (core)

```kotlin
val kc = KeycloakNative.configure(
  issuer = "https://idp.example.com/realms/demo",
  clientId = "demo-android",
  options = KeycloakNative.Options(platform = AndroidPlatform(context)),
)
val flow = kc.authentication().startLogin(LoginParameters(scope = "openid profile"))
var step = flow.start()
while (true) {
  step = when (step) {
    is FlowStep.Challenges -> flow.respond(answerFor(step.challenges.first()), step.challenges.first())
    is FlowStep.Authorized -> break
    is FlowStep.RedirectToWeb -> kc.webFallback().complete(step.request, flow)
  }
}
```

`ChallengeAnswer` is a sealed interface with the iOS cases (`Username`, `Password`, `Totp`, `Passkey`, `PasskeyRegistration`, `Otp`, `OtpResend`, `UpdatePassword`, `VerifyEmail`, `VerifyEmailResend`, `Terms`, `RecoveryCode`, `PushResend`, `PushPoll`, `PushEnrollment`, `PushEnrollmentCheck`, `Skip`, `Custom`). Error codes are the iOS `NativeAuthError.Code` strings, so apps and support docs share one list.

## 5. Testing

- **`core` (JVM):** a Kotlin port of the Swift `Harness` / `MockTransport` reads `../keycloak-native-auth/demo/transcripts/*.json` directly (no copy) and applies the same matching rules: same method and path, same form-field set, values equal except `***` and the per-run fields (`code_challenge`, `device_id`, `nonce`). Every Swift replay test has a Kotlin twin with the same name; a transcript re-recorded on the server fails both SDKs the same way.
- **`android`:** Robolectric for the JSON conversion of passkey options/responses; instrumentation tests on an emulator for Keystore and Credential Manager (emulator API 34+ with a Google account for passkeys).
- **Live tests:** the iOS `LiveServerTests` against the compose stack, ported to an instrumentation suite (`10.0.2.2` from the emulator).
- **CI:** an `android` job on `ubuntu-latest` (Android SDK preinstalled): `./gradlew :core:test` (transcript replay) on every PR, `assembleDebug` of the libraries and the demo; emulator jobs later.

## 6. Order of work

**A. Server and spec (before or alongside the SDK; no Android tooling needed)**
1. ✅ `AndroidOriginIT`: a passkey registered and used with origin `android:apk-key-hash:<test hash>` in the policy's extra origins; refused without it. Found on the way: a realm update applies the Passwordless policy only when it carries `webAuthnPolicyPasswordlessRpEntityName` and then rebuilds the whole policy from the request, so an update with only `webAuthnPolicyPasswordlessExtraOrigins` returns `204` and changes nothing (the admin console always sends the whole policy; scripts and Terraform must too). To do: the operator setup in `docs/`.
2. Spec 03 §7: the `android` / `fcm` values; §4.3/§4.4: the Android origin and Digital Asset Links next to the iOS rule. Additive.
3. Demo + IT for the `fcm` sender with a fake FCM endpoint and a fake service account whose `token_uri` points at the sink (as `ApnsSink`); record the push transcripts for `fcm`.

**B. `core` (JVM; buildable here with a JDK)**
4. Gradle skeleton under `android/`, `core` module, the transcript harness.
5. Port the state machine, answers, metadata, PKCE, DPoP proofs (software key in tests), tokens, credentials, redaction; Kotlin twins of the Swift replay suites until all pass.

**C. `android`, then `push`, then `ui`, then `demo`** (need the Android SDK and, for passkeys and push, a device or emulator with Google Play services).

## 7. Open questions

- **Distribution:** private for now, under the repository's ELv2 license and its version line (`0.0.x` pre-releases, README "Releases"). The demo app depends on the library modules as Gradle project dependencies, so nothing is published for our own testing. Testers outside the repository get the artifacts from GitHub Packages (the org's private Maven repository; each consumer needs a GitHub token with `read:packages`). Maven Central, like a public SwiftPM release, waits for the public-distribution decision, and needs the sources the Central rules require to be published with the binaries.
- **Repository layout:** `android/` next to `ios/` in this repository (one version line, shared transcripts) is assumed; a separate repository would need the transcripts published as an artifact.
- **Minimum API level:** passkeys through Credential Manager need Google Play services; `minSdk 28` is assumed and to be confirmed against target customers' fleets.
- **iOS device pass first?** Nothing seen on the simulator suggests a wire change, but a real-device surprise (passkey transports, Secure Enclave key behaviour, APNs) would be cheaper to absorb before a second SDK depends on the same contract. Recommended: run the iOS hardware checklist (10, Phase 1c) before Android step C.
