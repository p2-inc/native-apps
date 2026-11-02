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
| Push MFA (server) | ba-itsys' `fcm` sender is installed with the push extension and tested against a fake FCM (`FcmPushIT`, §6 A3) | real delivery needs a Firebase project and a device |
| Push device API (03 §7) | draft; the `android` / `fcm` values and the FCM message shape are written down (§6 A2) | none |
| iOS on hardware | simulator only | a device pass (passkeys, Secure Enclave, real APNs) is still open; see §7 |

## 2. Modules

Gradle (Kotlin DSL), Kotlin 2.x, coroutines. Maven group `io.phasetwo.keycloak.nativeauth` (artifacts `keycloak-native-<module>`), Kotlin packages `io.phasetwo.keycloak.nativeauth.sdk.*`: `native` is a reserved word in Java, so it cannot be a package name that Java callers import. Distribution: see §7.

| Module | Kind | Depends on | Content |
|---|---|---|---|
| `core` | **Kotlin/JVM** (no Android) | kotlinx-coroutines, kotlinx-serialization-json | metadata, the challenge state machine (`NativeLoginFlow`), `ChallengeAnswer` incl. `skip` / `custom`, extra fields, PKCE, DPoP proof building over a `DPoPKey` interface, `Tokens`, `CredentialsManager` over a `SecureStore` interface, `Transport` interface + `HttpURLConnection` default, redaction, typed errors with the iOS codes |
| `android` | Android library | `core`, `androidx.credentials`, `androidx.browser` | `CredentialManagerPasskeyPlatform`, `KeystoreDPoPKey` (StrongBox when available), `KeystoreSecureStore`, `AuthTabWebPresenter` / Custom Tabs fallback |
| `push` | Android library | `core`, `android`, Firebase Messaging | enrolment (in-app and mid-flow), approvals with number match, FCM token sync, key rotation, lockout |
| `ui` | Android library | `core`, `push`, Jetpack Compose | `NativeLoginScreen` and one default composable per challenge type, chooser, per-type overrides, string resources (en, de) |
| `demo` | Android app | all | the iOS demo's scenarios (06) where the platform allows |

`core` is plain JVM so the transcript replay, the state machine and DPoP/PKCE run as ordinary JUnit tests on any JDK: no emulator, no Android SDK. It mirrors `KeycloakNativeCore` type for type (Swift enum ↔ Kotlin sealed class, actor ↔ `Mutex` or short locks, `async` ↔ `suspend`) so a fix in one SDK maps to the other.

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
  issuer = URI("https://idp.example.com/realms/demo"),
  clientId = "demo-android",
  // The android module will offer one call that fills in its platform pieces.
  options = KeycloakNative.Options(secureStore = …, hardwareKeys = …, passkeyPlatform = …, webPresenter = …),
)
val flow = kc.authentication().startLogin(LoginParameters(scope = "openid profile"))
var step = flow.start()
while (step is FlowStep.Challenges) {
  val challenge = step.challenges.first()
  step = flow.respond(answerFor(challenge), challenge)
}
val credentials = when (step) {
  is FlowStep.Authorized -> step.credentials
  is FlowStep.RedirectToWeb -> kc.webFallback().complete(step.request, flow)
  is FlowStep.Challenges -> error("unreachable")
}
kc.credentialsManager().store(credentials)
```

`ChallengeAnswer` is a sealed class with the iOS cases (`Username`, `Password`, `Totp`, `Passkey`, `PasskeyRegistration`, `Otp`, `OtpResend`, `UpdatePassword`, `VerifyEmail`, `VerifyEmailResend`, `Terms`, `RecoveryCode`, `PushResend`, `PushPoll`, `PushEnrollment`, `PushEnrollmentCheck`, `Skip`, `Custom`). Error codes are the iOS `NativeAuthError.Code` strings, so apps and support docs share one list.

## 5. Testing

- **`core` (JVM):** a Kotlin port of the Swift `Harness` / `MockTransport` reads `../keycloak-native-auth/demo/transcripts/*.json` directly (no copy) and applies the same matching rules: same method and path, same form-field set, values equal except `***` and the per-run fields (`code_challenge`, `device_id`, `nonce`). Every Swift replay test has a Kotlin twin with the same name; a transcript re-recorded on the server fails both SDKs the same way.
- **`android`:** Robolectric for the JSON conversion of passkey options/responses; instrumentation tests on an emulator for Keystore and Credential Manager (emulator API 34+ with a Google account for passkeys).
- **Live tests:** the iOS `LiveServerTests` against the compose stack, ported to an instrumentation suite (`10.0.2.2` from the emulator).
- **CI:** an `android` job on `ubuntu-latest` (Android SDK preinstalled): `./gradlew :core:test` (transcript replay) on every PR, `assembleDebug` of the libraries and the demo; emulator jobs later.

## 6. Order of work

**A. Server and spec (before or alongside the SDK; no Android tooling needed)**
1. ✅ `AndroidOriginIT`: a passkey registered and used with origin `android:apk-key-hash:<test hash>` in the policy's extra origins; refused without it. Found on the way: a realm update applies the Passwordless policy only when it carries `webAuthnPolicyPasswordlessRpEntityName` and then rebuilds the whole policy from the request, so an update with only `webAuthnPolicyPasswordlessExtraOrigins` returns `204` and changes nothing (the admin console always sends the whole policy; scripts and Terraform must too). The operator setup is in `keycloak-native-auth/README.md` (Passwordless policy row) and `docs/development-and-troubleshooting.md`.
2. ✅ Spec 03 §7: the `android` / `fcm` values, the FCM message shape (`notification` + `data.token`; data reaches a backgrounded app only on tap, so the client also reads `/login/pending` on resume) and `onNewToken`; §4.3/§4.4: the Android origin and Digital Asset Links next to the iOS rule. Additive.
3. ✅ `FcmPushIT` with `FcmSink`, a fake FCM whose service account's `token_uri` and send URL point at the sink (as `ApnsSink`): enrolment as `android` / `fcm`, the RS256 JWT-bearer token grant, the HTTP v1 message (`notification` + `data.token`), approval with number match, and a refreshed registration token; transcripts recorded. Configuration names confirmed: `--spi-push-notification-sender--fcm--google-fcm-url` and `GOOGLE_APPLICATION_CREDENTIALS` (README).

**B. `core` (JVM; buildable here with a JDK)**
4. ✅ Gradle skeleton under `android/` (wrapper 9.8.2, Kotlin 2.4, JDK 21 toolchain, Java 17 bytecode for Android), `core` module with the transport types and the redactor, the transcript harness (`Transcript`, `MockTransport` with the iOS matching rules). Its tests replay every committed transcript as recorded and check the matching rules reject what the iOS harness rejects; CI job `android-core`.
5. ✅ The state machine, answers, metadata, PKCE, DPoP proofs, tokens, `CredentialsManager`, passkey models and the §6 registration client, `WebFallback`, the flow observer and an `HttpURLConnection` transport, ported from `KeycloakNativeCore`. Kotlin twins of the Swift unit and replay suites pass (`TranscriptReplay`, `Phase2Replay`, `Phase2bReplay`, `ProtocolAdditionsReplay`, parsing, JOSE/DPoP, credentials, redaction); a single changed request field fails 40 of them. Where the platforms differ: `SecureStore` functions suspend (a Keystore store may wait for `BiometricPrompt`); hardware keys plug in through `HardwareDPoPKeys` (`DPoPMode.HARDWARE` / `AUTOMATIC`), the analogue of the Secure Enclave key; without a configured `PasskeyPlatform` passkeys fail with `passkey_unavailable`. Left for later modules: the push replay suite (`Phase3ReplayTests`, needs `push`) and the live-server tests (an instrumentation suite, §5).

**C. `android`, then `push`, then `ui`, then `demo`** (need the Android SDK and, for passkeys and push, a device or emulator with Google Play services).

## 7. Open questions

- **Distribution:** private for now, under Apache-2.0 like the iOS SDK (README "License") and on the repository's version line (`0.x` pre-releases, README "Releases"). No Maven server: the demo app depends on the library modules as Gradle project dependencies, and each release attaches a zip of a file-based Maven repository (`./gradlew publishAllPublicationsToReleaseRepository` into a build directory: the `.jar` / `.aar` files with their POMs) to the GitHub release. A tester unzips it and adds `maven { url = uri("<unzipped folder>") }` to `settings.gradle.kts`; unlike bare `.aar` files in `libs/`, the POMs bring the transitive dependencies (AndroidX Credentials, Browser, Firebase Messaging, coroutines) along. GitHub Packages or Maven Central replace the zip when distribution goes wider; the Gradle publication stays the same.
- **Repository layout:** `android/` next to `ios/` in this repository (one version line, shared transcripts) is assumed; a separate repository would need the transcripts published as an artifact.
- **Minimum API level:** passkeys through Credential Manager need Google Play services; `minSdk 28` is assumed and to be confirmed against target customers' fleets.
- **Push credentials are per Keycloak deployment, not per realm or app.** The ba-itsys senders read their APNs key and the FCM service account from server configuration (`--spi-push-notification-sender--…`, `GOOGLE_APPLICATION_CREDENTIALS`), so one Keycloak sends every push with one APNs key and one Firebase project. That is fine for a customer's own deployment, but on a shared hosted cluster each customer's app has its own APNs topic and Firebase project, so a sender would need to take its credentials from the realm or the client. That is a change to the sender (or our own sender beside ba-itsys') before hosted customers can use push.
- **iOS device pass first?** Nothing seen on the simulator suggests a wire change, but a real-device surprise (passkey transports, Secure Enclave key behaviour, APNs) would be cheaper to absorb before a second SDK depends on the same contract. Recommended: run the iOS hardware checklist (10, Phase 1c) before Android step C.
