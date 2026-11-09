# 18 — Flutter plugin plan (`keycloak_native`)

**Date:** 9 November 2026
**Status:** plan, with phase A (the first vertical slice) implemented in `flutter/keycloak_native`. Phases B–E are open.
**Builds on:** 03 (the protocol, unchanged), 05 and 17 (the iOS and Android SDKs, which this plugin wraps), 15 (`skip`, `custom`, `x_*`).

A Flutter app gets native authentication through a **plugin that wraps the two native SDKs** over platform channels. It is not a third implementation of the protocol in Dart. The state machine, PKCE, DPoP, token exchange and refresh, the secure stores, passkey ceremonies, the browser fallback and push stay in `KeycloakNativeCore` (iOS) and `core` + `android` (Android), which already replay the server's transcripts. Dart gets the challenge loop as typed classes and Flutter widgets in place of the SwiftUI and Compose screens, with every default screen replaceable per challenge type, as in the native UI layers. A React Native module follows the same shape (spec/19); where a choice here is arbitrary it is made so the two stay alike.

## 1. Why a wrapper

| | Wrap the native SDKs (chosen) | Pure-Dart protocol client |
|---|---|---|
| Protocol fixes | once per platform SDK, already replayed against transcripts | a third implementation to keep in step |
| Hardware keys, Keychain / Keystore | the SDKs' own (`SecureEnclaveDPoPKey`, `KeystoreDPoPKeys`, `KeychainStore`, `KeystoreSecureStore`) | needs plugins for each, and non-exportable keys cannot sign from Dart without a native call per proof anyway |
| Passkeys, browser, push | the SDKs' bridges (`ASAuthorization…`, Credential Manager, `ASWebAuthenticationSession`, Auth Tab, APNs, FCM) | the same native calls through other plugins, glued in Dart |
| Secrets in the Dart heap | only what the app needs: access and ID token | refresh token, `auth_session`, DPoP material |
| Cost | a bridge per platform and a channel interface | none of the above, but all of the left column again |

## 2. Package layout

`flutter/keycloak_native/` in this repository (one version line and one set of transcripts with the server and the SDKs).

| Path | Content |
|---|---|
| `pubspec.yaml` | plugin `keycloak_native`, platforms `android` (`io.phasetwo.keycloak.nativeauth.flutter.KeycloakNativePlugin`) and `ios` (`KeycloakNativePlugin`); Apache-2.0 (`LICENSE`, a copy of the repository's) |
| `pigeons/messages.dart` | the channel interface (§4); `dart run pigeon --input pigeons/messages.dart` writes the three generated files, which are committed |
| `lib/keycloak_native.dart` | the public library; everything else is under `lib/src/` |
| `lib/src/client.dart` | `KeycloakNative.configure`, `KeycloakNativeOptions`, `Authentication`, `CredentialsManager`, `WebFallback` |
| `lib/src/flow.dart` | `LoginParameters`, `NativeLoginFlow`, `FlowStep` (`ChallengesStep`, `AuthorizedStep`, `RedirectToWebStep`) |
| `lib/src/challenges.dart`, `answers.dart` | `ChallengeType`, the sealed `Challenge` hierarchy, the sealed `ChallengeAnswer` hierarchy, `FlowContext`, `RedirectToWebRequest` |
| `lib/src/credentials.dart`, `errors.dart` | `Credentials` (no refresh token), `NativeAuthException` and `NativeAuthErrorCode` (the SDKs' codes) |
| `lib/src/mapping.dart` | messages ↔ model, internal |
| `lib/src/ui/` | `NativeLoginController` (the twin of the native `NativeLoginModel`), `NativeLoginView`, the default screens, `NativeLoginStrings` |
| `android/` | `KeycloakNativePlugin.kt` (FlutterPlugin + ActivityAware + the host API) and the generated `Messages.g.kt` |
| `ios/keycloak_native/` | a Swift package (`Package.swift`, Flutter's Swift Package Manager integration) with `KeycloakNativePlugin.swift` and the generated `Messages.g.swift` |
| `example/` | an app with one client of the demo realm: sign in through `NativeLoginView`, show claims, refresh, log out |
| `test/` | model mapping, transcript replay through a fake host API, widget tests (§7) |

## 3. Native dependencies

| Platform | Plugin depends on | Inside this repository | Outside (pub.dev) |
|---|---|---|---|
| Android | `io.phasetwo.keycloak.nativeauth:keycloak-native-android` (brings `keycloak-native-core`) | the example's `settings.gradle.kts` includes `../../../../android` as a Gradle composite build and substitutes both modules with its projects, so a change in the SDK is picked up without publishing | Maven Central, at the plugin's version (the artifacts are about to be published there) |
| iOS | product `KeycloakNativeCore` of the root `Package.swift` | the plugin's `Package.swift` sees the repository four directories up (resolving the symlink Flutter reaches it through) and uses it as a local path package | the same manifest falls back to `.package(url: "https://github.com/p2-inc/native-apps.git", exact: <version>)` |

Consequences:

- The composite build loads the Android SDK's Gradle plugins, so the example (and the plugin's `buildscript`) use the SDK's versions: AGP 9.5.0, Kotlin 2.4.21, Gradle 9.8.2, `compileSdk 37`. `minSdk` is 28, the SDK's. An app with a lower `minSdk` must raise it.
- iOS needs 17.0 (the SDK's floor) and Swift Package Manager, Flutter's default. There is no podspec, because the SDK has none; an app that turned SPM off cannot use the plugin (§10).
- `UI`, `Push` (iOS) and `ui`, `push` (Android) are not dependencies: Flutter widgets replace the native screens, and push comes in phase D with its own optional dependency.

## 4. The channel (Pigeon)

Pigeon 29 generates Dart, Kotlin (`suspend` host methods on `Dispatchers.Main`) and Swift (`async throws`). The interface is in `pigeons/messages.dart`; its shape:

- **Handles, not objects.** `configure` returns an instance handle, `startLogin` / `stepUp` a flow handle; the bridges keep the native `KeycloakNative`, `NativeLoginFlow` and `RedirectToWebRequest` objects in tables keyed by handle. `disposeFlow` drops a flow (Dart's `NativeLoginFlow.dispose`). Several instances can coexist (one per issuer and client).
- **Challenges go out parsed, params as JSON text.** `ChallengeMessage` carries the descriptor's fields (`id`, `type` wire string, `label`, `required`, `error`, `retry`, `skippable`) and `paramsJson`. The Dart sealed classes read their typed fields from it, the same getters as the native `…Params` types. The native side does not re-model params per type, so a new param needs no bridge change.
- **Answers come in typed.** `AnswerMessage` has an `AnswerKind` (one per native `ChallengeAnswer` case that carries only strings: `username`, `password`, `totp`, `otp`, `otpResend`, `updatePassword`, `verifyEmail`, `verifyEmailResend`, `terms`, `recoveryCode`, `pushResend`, `pushPoll`, `pushEnrollmentCheck`, `skip`, `custom`) and its values. Each bridge builds the native `ChallengeAnswer`, so form fields, reserved-name checks and redaction stay native. `respond` names the challenge by id and type; the bridge picks it from the flow's `pendingChallenges`.
- **What never crosses.** The refresh token, the post-login `auth_session`, the PKCE verifier, DPoP keys and proofs other than the headers of `resourceRequestHeaders`. `CredentialsMessage` has the access and ID token, type, scope, expiries and `hasRefreshToken`, plus a `handle` naming the native `Credentials` a flow produced; `storeCredentials(handle)` stores those in the native store. Stored credentials come back with an empty handle.
- **Errors.** A native `NativeAuthError` becomes a `PlatformException` with its `code`, its description and `details` (`statusCode`, `isNetworkError`, `isRetryable`, `retryAfter`, `maxAge`, the body as JSON); Dart turns it into `NativeAuthException`. Codes are the SDKs' list (`NativeAuthErrorCode`).

## 5. Challenge types

| Type (spec/03) | Dart class | Answers from Dart | Native side | Default widget | Phase |
|---|---|---|---|---|---|
| `username` | `UsernameChallenge` (`allowEmail`, `hint`) | `username` | `ChallengeAnswer.username` | `UsernameScreen` | A ✅ |
| `password` | `PasswordChallenge` (`usernameKnown`) | `password` | `.password` | `PasswordScreen` (read-only username for autofill, `TextInput.finishAutofillContext`) | A ✅ |
| `totp` | `TotpChallenge` (`digits`, `period`, `credentials`) | `totp(code, credentialId:)` | `.totp` | `TotpScreen` with an authenticator picker | A ✅ |
| `otp` | `OtpChallenge` | `otp`, `otpResend` | `.otp`, `.otpResend` | resend countdown screen | B |
| `recovery_code` | `RecoveryCodeChallenge` | `recoveryCode` | `.recoveryCode` | screen with the low-codes warning | B |
| `update_password` | `UpdatePasswordChallenge` (`policy`) | `updatePassword(…, confirm:)` | `.updatePassword` | screen with policy hints (`hints` comes to Dart in B) | B |
| `verify_email` | `VerifyEmailChallenge` | `verifyEmail`, `verifyEmailResend` | `.verifyEmail…` | like `otp` | B |
| `terms` | `TermsChallenge` | `terms(accepted:)` | `.terms` | text or link, accept / decline | B |
| `passkey` | `PasskeyChallenge` | none: `usePasskey(flow, challenge)` host call | `kc.passkeys().assert` + `respond(.passkey)` natively, with the window / activity of §6 | "Continue with passkey" | C |
| `passkey_registration` | `PasskeyRegistrationChallenge` | none: `registerPasskey(flow, challenge, label)`; `skip` | `kc.passkeys().register` + `respond(.passkeyRegistration)` | with "Not now" when skippable | C |
| `push` | `PushChallenge` | `pushResend`, `pushPoll` | `.pushResend`, `.pushPoll` | number match, polling at `pollInterval` | B (no native push needed) |
| `push_enrollment` | `PushEnrollmentChallenge` | `pushEnrollmentCheck`; the enrolment itself is a host call | `push().prepareEnrollment` + `respond` + `commit` | enrol screen | D |
| `select`, unknown | `UnknownChallenge` | `custom(type, fields)` | `.custom` | "update required" | — |
| any skippable required action | — | `skip(type)` | `.skip` | "Not now" | A (model), B (widgets) |

`RedirectToWebStep` (spec/03 §3.4) is phase A: `kc.webFallback.complete(flow)` runs the SDK's `WebFallback` with the request the bridge kept for that flow; `RedirectToWebScreen` explains why and opens the browser.

In phase A `NativeLoginView` shows the default screen for `username`, `password` and `totp` and the "update required" screen otherwise; an app can pass `presenters` for any other type (the widget test does so for `terms`). The controller's `answerableChallengeTypes` decides which alternatives it offers and which entry it shows first; passkey types join it in phase C.

## 6. Window and activity anchors

| Need | iOS | Android |
|---|---|---|
| Passkey and saved-password sheets | `KeycloakNative.Options.presentationAnchor` defaults to the key window, which is Flutter's; phase C adds an override only if a multi-window app needs one | `CredentialManagerPasskeyPlatform(context) { currentActivity }` and the saved-password twin; the plugin tracks the activity through `ActivityAware` (attach, detach, config changes) |
| Browser fallback | `ASWebAuthenticationSession` through the same anchor; `ephemeralWebSession` maps to `prefersEphemeralWebBrowserSession` | `AuthTabWebPresenter` must be created while its activity is being created (it registers an activity result launcher), so the plugin creates two (normal and ephemeral) in `onAttachedToActivity`, which Flutter calls from the activity's creation. That needs a `ComponentActivity`: the app's `MainActivity` extends `FlutterFragmentActivity`, not `FlutterActivity`. Without one, the fallback fails with `web_fallback_failed` naming the fix. The app also declares `NativeAuthRedirectActivity` with its `redirect_uri` (Custom Tab fallback), as a native app does |
| Push (phase D) | the app forwards the APNs token and notification taps (`Push.handleNotification`) from its `AppDelegate`; the plugin adds a Dart stream for pending approvals | the app's `FirebaseMessagingService` forwards to the `push` module (`onNewFcmToken`, `handle(RemoteMessage)`); the plugin does not register its own service, so it does not clash with `firebase_messaging` |

## 7. Testing

- **Dart model (`test/model_mapping_test.dart`):** every wire type maps to its class, typed params read from JSON, answers map to their `AnswerKind` and values, credentials keep their handle and never print a token, a bridge `PlatformException` becomes a `NativeAuthException`.
- **Transcript replay (`test/transcript_replay_test.dart`):** `TranscriptHostApi` implements the generated `KeycloakNativeHostApi` from a transcript in `keycloak-native-auth/demo/transcripts` (read in place; `KEYCLOAK_NATIVE_TRANSCRIPTS` overrides). Each `start` / `respond` builds the form the native SDK would send (the initial §2.1 fields from the `LoginParametersMessage`, then `auth_session` + `challenge_type` + `challenge_id` + the answer's fields, which mirror `ChallengeAnswer.formFields`) and compares it with the next recorded request by the native suites' rules (same field set, same values except `***` and the per-run `code_challenge`, `device_id`, `nonce`); it answers with the recorded response as the bridges would encode it. Scenarios: the happy path, a wrong password with its descriptor error and `retry.remaining`, alternatives, `redirect_to_web`, declining terms (`access_denied`), the controller end to end, and a sweep that maps every descriptor of every transcript to its typed class and reads every getter. A server change to a descriptor or a request field fails here as it fails the native replays.
- **Widgets (`test/native_login_view_test.dart`):** the default screens over the same fake: username → password → TOTP to `NativeLoginAuthorized`, switching to an alternative, an app presenter for a type without a default screen.
- **Bridges:** the Kotlin and Swift bridges are thin and compile in CI with the example app. Phase E adds JVM tests for the Kotlin answer mapping (it is plain Kotlin apart from the generated types) and a Swift test target, and an integration test (`integration_test/`) against the compose stack on an emulator and a simulator, the analogue of the SDKs' live-server suites.
- **CI:** a `flutter` job: `flutter analyze`, `flutter test`, `flutter build apk --debug` of the example (which compiles the Android SDK through the composite build). Not a required check yet. An iOS build of the example (`flutter build ios --simulator --no-codesign`) can join the macOS job.

## 8. Distribution

- **pub.dev** as `keycloak_native`, Apache-2.0, on the repository's version line (`0.x` before 1.0). The release workflow gains a `dart pub publish` step once the Android artifacts are on Maven Central; the plugin's Gradle file names the SDK version, and the iOS manifest the tag.
- **Android:** apps need `mavenCentral()` (Flutter's default). The SDK's AARs require `compileSdk 37` and `minSdk 28`.
- **iOS:** Swift Package Manager resolves `https://github.com/p2-inc/native-apps.git` at the tag; the repository's root manifest is already consumable by URL.
- **In this repository** the example never uses published artifacts (§3), so the plugin and the SDKs change in one PR.

## 9. Order of work

**A. First vertical slice** (this PR)
1. ✅ Plugin scaffold (`flutter create --template=plugin`, Kotlin + Swift), Apache-2.0 `LICENSE`, the Android package `io.phasetwo.keycloak.nativeauth.flutter`.
2. ✅ Pigeon interface: configure, start login, step-up, start, respond, cancel, dispose, browser fallback, store / stored / current (refreshing) credentials, `hasValid`, logout, clear, resource request headers, `jkt`, metadata.
3. ✅ Dart API and model: `KeycloakNative`, `Authentication`, `NativeLoginFlow`, sealed `FlowStep`, `Challenge` (every spec/03 type, typed getters) and `ChallengeAnswer`, `Credentials`, `NativeAuthException`.
4. ✅ Android bridge over `KeycloakNative` with `KeystoreSecureStore`, `KeystoreDPoPKeys`, the Credential Manager platforms and `AuthTabWebPresenter` through the current activity; iOS bridge over `KeycloakNative` with the SDK's default Keychain store, Secure Enclave keys and browser.
5. ✅ `NativeLoginController` + `NativeLoginView` with default `username`, `password`, `totp`, `redirect_to_web`, "update required" screens, the "Try another way" chooser, `presenters`, `chooser`, `header`, `NativeLoginStrings`.
6. ✅ Example app on the demo realm (`demo-native`, `demoapp://auth/callback`; debug builds allow plain HTTP to `10.0.2.2` / `localhost`).
7. ✅ Tests of §7 (model, replay, widgets).

**B. The rest of the in-band screens:** `otp`, `recovery_code`, `update_password` (with the SDKs' policy hints as a host call or a Dart port), `verify_email`, `terms`, `push` (polling, number match), "Not now" for skippable required actions; German strings and a localization delegate in place of `NativeLoginStrings`; a flow observer stream for a diagnostics screen.

**C. Passkeys and saved passwords:** host calls `usePasskey`, `registerPasskey`, `pickSavedPassword`, `savePassword` that run the native ceremony and answer the challenge natively, returning the next step; `autoSelectPasskey`; passkey registration after login through `kc.passkeys()`; the AASA / `assetlinks.json` setup in the example.

**D. Push:** enrolment in-app and mid-flow (`push_enrollment`), pending approvals with approve / deny and number match, key rotation, lockout; APNs and FCM token forwarding from the app (§6); an optional dependency on the native `push` module so apps without Firebase do not pull it.

**E. Hardening and release:** JVM and Swift tests of the bridges, an `integration_test` suite against the compose stack, the CI job as a required check, `dart pub publish` in the release workflow, a `docs/flutter-integration.md` guide next to the iOS and Android ones, and a device pass (passkeys, Keystore / Secure Enclave, browser on both).

## 10. Open questions

- **CocoaPods.** The iOS SDK ships only as a Swift package, so the plugin has no podspec and needs Flutter's Swift Package Manager integration (the default in current Flutter). Supporting apps that turned it off means publishing a podspec for `KeycloakNativeCore` as well. Worth it only if integrators ask.
- **`FlutterFragmentActivity`.** The Android browser fallback needs a `ComponentActivity`. Apps on `FlutterActivity` get `web_fallback_failed`. The alternative is a small transparent activity owned by the plugin that hosts the Auth Tab launcher; it costs an extra activity hop but lifts the requirement.
- **How much of the token reaches Dart.** The access and ID token do, because apps call APIs with them; the refresh token does not. Apps that send DPoP-bound tokens must use `resourceRequestHeaders`, a channel round trip per request. A Dart HTTP client wrapper (`package:http` `BaseClient`) that adds the headers would make that convenient.
- **Strings.** `NativeLoginStrings` is a plain class with English defaults. The native SDKs ship English and German; Flutter apps usually localize with `intl` / ARB files and a `LocalizationsDelegate`. Phase B picks one.
- **Shared screens with React Native.** Both wrappers send the same messages; if spec/19 lands on the same handle-and-JSON-params channel shape, the message definitions could be shared (the RN side would generate from the same schema), and the bridges' native code could become a common internal module in each SDK.
