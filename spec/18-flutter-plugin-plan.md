# 18 — Flutter plugin plan (`keycloak_native`)

**Date:** 9 November 2026
**Status:** phases A–D implemented in `flutter/keycloak_native` (every challenge type and required action, passkeys, saved passwords, push enrollment and approvals, the browser fallback, the flow log); phase E (release hardening) is partly done. The open questions of the first draft are decided in §10.
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
| `lib/src/client.dart` | `KeycloakNative.configure`, `KeycloakNativeOptions`, `Authentication` (login, step-up, `continueAfterTokenChallenge`), `CredentialsManager`, `WebFallback`, `Passkeys`, saved passwords, the `flowLog` stream |
| `lib/src/push.dart` | `Push` (enrollment, approvals, provider updates, key rotation, lockout), `PendingApproval`, `PushApprovalAction`, `PushProviderRegistration` |
| `lib/src/flow.dart` | `LoginParameters`, `NativeLoginFlow`, `FlowStep` (`ChallengesStep`, `AuthorizedStep`, `RedirectToWebStep`) |
| `lib/src/challenges.dart`, `answers.dart` | `ChallengeType`, the sealed `Challenge` hierarchy, the sealed `ChallengeAnswer` hierarchy, `FlowContext`, `RedirectToWebRequest` |
| `lib/src/credentials.dart`, `errors.dart` | `Credentials` (no refresh token), `NativeAuthException` and `NativeAuthErrorCode` (the SDKs' codes) |
| `lib/src/mapping.dart` | messages ↔ model, internal |
| `lib/src/ui/` | `NativeLoginController` (the twin of the native `NativeLoginModel`), `NativeLoginView`, a default screen per challenge type, `PushApprovalsController` + `PushApprovalsView`, `NativeLoginStrings` (English) and `NativeLoginStringsDe` |
| `android/` | `KeycloakNativePlugin.kt` (FlutterPlugin + ActivityAware + the host API) and the generated `Messages.g.kt` |
| `ios/keycloak_native/` | a Swift package (`Package.swift`, Flutter's Swift Package Manager integration) with `KeycloakNativePlugin.swift` and the generated `Messages.g.swift` |
| `example/` | an app on the demo realm's four native clients: sign in through `NativeLoginView`, claims, refresh, step-up, passkey registration, push enrollment and the approvals list, the flow log, log out; `integration_test/` signs in against the running compose stack |
| `test/` | model mapping, transcript replay through a fake host API, widget tests of every default screen, the flow log (§7) |

## 3. Native dependencies

| Platform | Plugin depends on | Inside this repository | Outside (pub.dev) |
|---|---|---|---|
| Android | `io.phasetwo.keycloak.nativeauth:keycloak-native-android` (brings `keycloak-native-core`) | the example's `settings.gradle.kts` includes `../../../../android` as a Gradle composite build and substitutes both modules with its projects, so a change in the SDK is picked up without publishing | Maven Central, at the plugin's version (the release workflow publishes the SDK there from 0.3.0) |
| iOS | products `KeycloakNativeCore` and `KeycloakNativePush` of the root `Package.swift` | the plugin's `Package.swift` sees the repository four directories up (resolving the symlink Flutter reaches it through) and uses it as a local path package | the same manifest falls back to `.package(url: "https://github.com/p2-inc/native-apps.git", exact: <version>)` |

Consequences:

- The composite build loads the Android SDK's Gradle plugins, so the example (and the plugin's `buildscript`) use the SDK's versions: AGP 9.5.0, Kotlin 2.4.21, Gradle 9.8.2, `compileSdk 37`. `minSdk` is 28, the SDK's. An app with a lower `minSdk` must raise it.
- iOS needs 17.0 (the SDK's floor) and Swift Package Manager, Flutter's default. There is no podspec, because the SDK has none; an app that turned SPM off cannot use the plugin (§10).
- `KeycloakNativeUI` (iOS) and `ui`, `push` (Android) are not dependencies: Flutter widgets replace the native screens, and the push protocol is `KeycloakNativePush` on iOS and `Push` in `core` on Android. Neither registers with APNs or FCM: the app obtains the token (for instance with `firebase_messaging`) and passes a `PushProviderRegistration`, so the plugin pulls in no Firebase and does not clash with an app's own messaging setup.
- **Kotlin metadata.** The Android SDK is compiled with Kotlin 2.4, and Kotlin reads class metadata at most one minor version ahead of itself, so the app's Kotlin Gradle plugin must be 2.3 or newer. Flutter 3.47's app template pins Kotlin 2.4.0 (`org.jetbrains.kotlin.android` in `settings.gradle.kts`), which reads the SDK as is; apps created with older templates (Kotlin 2.1 or 2.2) fail with an "incompatible version of Kotlin" metadata error until they raise it. This is the same constraint the React Native module meets; a change to the SDK's build to emit older metadata is a separate decision (and PR) for the Android SDK, not something the plugin works around. Not reproduced here with an old-template app: the in-repo example builds the SDK in the same Gradle build, which forces one Kotlin version.

## 4. The channel (Pigeon)

Pigeon 29 generates Dart, Kotlin (`suspend` host methods on `Dispatchers.Main`) and Swift (`async throws`). The interface is in `pigeons/messages.dart`; its shape:

- **Handles, not objects.** `configure` returns an instance handle, `startLogin` / `stepUp` a flow handle; the bridges keep the native `KeycloakNative`, `NativeLoginFlow` and `RedirectToWebRequest` objects in tables keyed by handle. `disposeFlow` drops a flow (Dart's `NativeLoginFlow.dispose`). Several instances can coexist (one per issuer and client).
- **Challenges go out parsed, params as JSON text.** `ChallengeMessage` carries the descriptor's fields (`id`, `type` wire string, `label`, `required`, `error`, `retry`, `skippable`) and `paramsJson`. The Dart sealed classes read their typed fields from it, the same getters as the native `…Params` types. The native side does not re-model params per type, so a new param needs no bridge change.
- **Answers come in typed.** `AnswerMessage` has an `AnswerKind` (one per native `ChallengeAnswer` case that carries only strings: `username`, `password`, `totp`, `otp`, `otpResend`, `updatePassword`, `verifyEmail`, `verifyEmailResend`, `terms`, `recoveryCode`, `pushResend`, `pushPoll`, `pushEnrollmentCheck`, `skip`, `custom`) and its values. Each bridge builds the native `ChallengeAnswer`, so form fields, reserved-name checks and redaction stay native. `respond` names the challenge by id and type; the bridge picks it from the flow's `pendingChallenges`.
- **What never crosses.** The refresh token, the post-login `auth_session`, the PKCE verifier, DPoP keys and proofs other than the headers of `resourceRequestHeaders`. `CredentialsMessage` has the access and ID token, type, scope, expiries and `hasRefreshToken`, plus a `handle` naming the native `Credentials` a flow produced; `storeCredentials(handle)` stores those in the native store. Stored credentials come back with an empty handle.
- **Ceremonies are host calls that answer natively.** `usePasskey`, `registerPasskey` and `enrollPush` take the flow and challenge handles, run the platform ceremony (Credential Manager / `ASAuthorization`, the device JWT signed by the DPoP key) and send the answer from the native side, returning the next step; the WebAuthn material and the device key never reach Dart. The enrollment is kept once the server moved on from the challenge, as the native UI models do.
- **Token challenges stay native.** When `credentials`, `resourceRequestHeaders` or `registerNewPasskey` fail with an error that carries an `auth_session` (`reauthentication_required`, `insufficient_authorization`), the bridge keeps that error per instance and `continueAfterTokenChallenge` starts the step-up flow from it.
- **The flow log goes the other way.** `KeycloakNativeFlutterApi.onFlowLog` (a Pigeon `@FlutterApi`) delivers the SDK's already-redacted entries when `observeFlow` is set; Dart routes them by instance handle to `KeycloakNative.flowLog`.
- **Errors.** A native `NativeAuthError` becomes a `PlatformException` with its `code`, its description and `details` (`statusCode`, `isNetworkError`, `isRetryable`, `retryAfter`, `maxAge`, the body as JSON); Dart turns it into `NativeAuthException`. Codes are the SDKs' list (`NativeAuthErrorCode`).

## 5. Challenge types

| Type (spec/03) | Dart class | Answers from Dart | Native side | Default widget | Phase |
|---|---|---|---|---|---|
| `username` | `UsernameChallenge` (`allowEmail`, `hint`) | `username` | `ChallengeAnswer.username` | `UsernameScreen` with "Use a saved password" | A ✅ |
| `password` | `PasswordChallenge` (`usernameKnown`) | `password` | `.password` | `PasswordScreen` (read-only username for autofill, `TextInput.finishAutofillContext`, "Use a saved password") | A ✅ |
| `totp` | `TotpChallenge` (`digits`, `period`, `credentials`) | `totp(code, credentialId:)` | `.totp` | `TotpScreen` with an authenticator picker | A ✅ |
| `otp` | `OtpChallenge` | `otp`, `otpResend` | `.otp`, `.otpResend` | `OtpScreen`: "Send me a code" while `sent` is false, resend with the server's cooldown | B ✅ |
| `recovery_code` | `RecoveryCodeChallenge` | `recoveryCode` | `.recoveryCode` | `RecoveryCodeScreen` with the remaining count and the low-codes warning | B ✅ |
| `update_password` | `UpdatePasswordChallenge` (`policy`) | `updatePassword(…, confirm:)` | `.updatePassword` | `UpdatePasswordScreen` with the policy hints (`NativeLoginStrings.passwordPolicyHints`, a Dart port of the SDKs' `hints`) | B ✅ |
| `verify_email` | `VerifyEmailChallenge` | `verifyEmail`, `verifyEmailResend` | `.verifyEmail…` | `VerifyEmailScreen`, like `otp` | B ✅ |
| `terms` | `TermsChallenge` | `terms(accepted:)` | `.terms` | `TermsScreen`: text, the link (opened through an app callback, else shown), accept / decline | B ✅ |
| `passkey` | `PasskeyChallenge` | none: `NativeLoginFlow.usePasskey(challenge)` | `kc.passkeys().assert` + `respond(.passkey)` natively, with the window / activity of §6 | `PasskeyScreen`; `autoSelectPasskey` | C ✅ |
| `passkey_registration` | `PasskeyRegistrationChallenge` | none: `NativeLoginFlow.registerPasskey(challenge, label:)`; `skip` | `kc.passkeys().register` + `respond(.passkeyRegistration)` | `PasskeyRegistrationScreen` with "Not now" when skippable | C ✅ |
| `push` | `PushChallenge` | `pushResend`, `pushPoll` | `.pushResend`, `.pushPoll` | `PushScreen`: send on demand, the number for number match, polling at `pollInterval`, "Check now" | B ✅ |
| `push_enrollment` | `PushEnrollmentChallenge` | `pushEnrollmentCheck`; the enrollment itself is `NativeLoginFlow.enrollPush` | `push().prepareEnrollment` + `respond` + `commit` | `PushEnrollmentScreen` (device name; the view's `pushRegistration`) | D ✅ |
| `select`, unknown | `UnknownChallenge` | `custom(type, fields)` | `.custom` | "update required" | — |
| any skippable required action | — | `skip(type)` | `.skip` | "Not now" | B ✅ |

`RedirectToWebStep` (spec/03 §3.4) is phase A: `kc.webFallback.complete(flow)` runs the SDK's `WebFallback` with the request the bridge kept for that flow; `RedirectToWebScreen` explains why and opens the browser.

`NativeLoginView` has a default screen for every type above; `presenters` replaces any of them, and an app can add a screen for an extension type it answers with `custom`. The controller mirrors the native `NativeLoginModel`: the entry it shows is the one that failed, else the type shown before, else the first in server order; passkey, saved-password and browser cancellations keep the set; a picked saved password answers the username and then the password; a typed password is offered to the password manager after success (`offerToSavePassword`; Android only, iOS AutoFill offers it on its own). Outside a flow, `PushApprovalsView` lists the pending approvals with the number-match buttons or a PIN field, keeps the card after a wrong number, and drops expired requests.

## 6. Window and activity anchors

| Need | iOS | Android |
|---|---|---|
| Passkey and saved-password sheets | `KeycloakNative.Options.presentationAnchor` is left at its default, the key window, which is Flutter's (verified on the simulator); an override is added only if a multi-window app needs one | `CredentialManagerPasskeyPlatform(context) { currentActivity }` and the saved-password twin; the plugin tracks the activity through `ActivityAware` (attach, detach, config changes) |
| Browser fallback | `ASWebAuthenticationSession` through the same anchor; `ephemeralWebSession` maps to `prefersEphemeralWebBrowserSession` | `AuthTabWebPresenter` must be created while its activity is being created (it registers an activity result launcher), so the plugin creates two (normal and ephemeral) in `onAttachedToActivity`, which Flutter calls from the activity's creation. That needs a `ComponentActivity`: the app's `MainActivity` extends `FlutterFragmentActivity`, not `FlutterActivity`. Without one, the fallback fails with `web_fallback_failed` naming the fix. The app also declares `NativeAuthRedirectActivity` with its `redirect_uri` (Custom Tab fallback), as a native app does |
| Push | the app gets the APNs token and notification payloads from its messaging plugin and passes them in: `PushProviderRegistration('apns', hexToken)` to `enroll` / `enrollPush` / `updatePushProvider`, the payload's strings to `kc.push.handleMessage`, which returns the `cid` to focus in `PushApprovalsView` | the same with FCM: `PushProviderRegistration('fcm', token)`, `onNewToken` → `updatePushProvider`, `RemoteMessage.data` → `handleMessage`; the plugin registers no `FirebaseMessagingService`, so it does not clash with `firebase_messaging` |

## 7. Testing

- **Dart model (`test/model_mapping_test.dart`):** every wire type maps to its class, typed params read from JSON, answers map to their `AnswerKind` and values, credentials keep their handle and never print a token, a bridge `PlatformException` becomes a `NativeAuthException`.
- **Transcript replay (`test/transcript_replay_test.dart`):** `TranscriptHostApi` implements the generated `KeycloakNativeHostApi` from a transcript in `keycloak-native-auth/demo/transcripts` (read in place; `KEYCLOAK_NATIVE_TRANSCRIPTS` overrides). Each `start` / `respond` builds the form the native SDK would send (the initial §2.1 fields from the `LoginParametersMessage`, then `auth_session` + `challenge_type` + `challenge_id` + the answer's fields, which mirror `ChallengeAnswer.formFields`) and compares it with the next recorded request by the native suites' rules (same field set, same values except `***` and the per-run `code_challenge`, `device_id`, `nonce`); it answers with the recorded response as the bridges would encode it. Scenarios: the happy path, a wrong password with its descriptor error and `retry.remaining`, alternatives, `redirect_to_web`, declining terms (`access_denied`), the controller end to end, and a sweep that maps every descriptor of every transcript to its typed class and reads every getter. A server change to a descriptor or a request field fails here as it fails the native replays.
- **Widgets (`test/native_login_view_test.dart`, `test/default_screens_test.dart`):** every default screen over the same fake and the transcript that exercises it: username → password → TOTP, alternatives, an app presenter; `otp` sent on request, `recovery_code` with a wrong code, `update_password` through `missing_credential` / `password_mismatch` / `invalid_password`, `verify_email` with `resend_too_soon`, `terms`, `push_enrollment` with a failed first attempt, a discoverable `passkey` (tapped and with `autoSelectPasskey`), `passkey_registration` created and declined, `push` sent and polled, saved passwords picked and offered, German strings, and `PushApprovalsView` with a wrong and then the right number. The ceremonies (`usePasskey`, `registerPasskey`, `enrollPush`) are checked for routing and field names; the recorded WebAuthn material and device JWT stand in for the platform's. The flow log has its own test over the Pigeon channel.
- **Live (`example/integration_test/live_login_test.dart`):** the example app with the real plugin and native SDK against `docker compose up` in `keycloak-native-auth/demo`: alice with username, password and TOTP, refresh, in-app push enrollment (`none`), the approvals list and forgetting the enrollment; bob on `demo-native-otp` with the email code read from mailpit. Run with `flutter test integration_test -d <device>`; it is not in CI, which has no compose stack in the Flutter job.
- **Bridges:** the Kotlin and Swift bridges are thin and compile in CI with the example app; the live test exercises them end to end. JVM and Swift unit tests of the answer mapping are still open (phase E).
- **CI:** a `flutter` job: `flutter analyze`, `flutter test`, `flutter build apk --debug` of the example (which compiles the Android SDK through the composite build). Not a required check yet. A `flutter-ios` job builds the example for the simulator on macOS (`flutter build ios --simulator --debug --no-codesign`), which compiles the iOS SDK through the local Swift package.

## 8. Distribution

- **pub.dev** as `keycloak_native`, Apache-2.0, on the repository's version line (`0.x` before 1.0). The release workflow gains a `dart pub publish` step once the package name is settled (§10); the Android artifacts go to Maven Central from 0.3.0; the plugin's Gradle file names the SDK version, and the iOS manifest the tag.
- **Android:** apps need `mavenCentral()` (Flutter's default). The SDK's AARs require `compileSdk 37` and `minSdk 28`.
- **iOS:** Swift Package Manager resolves `https://github.com/p2-inc/native-apps.git` at the tag; the repository's root manifest is already consumable by URL.
- **In this repository** the example never uses published artifacts (§3), so the plugin and the SDKs change in one PR.

## 9. Order of work

**A. First vertical slice**
1. ✅ Plugin scaffold (`flutter create --template=plugin`, Kotlin + Swift), Apache-2.0 `LICENSE`, the Android package `io.phasetwo.keycloak.nativeauth.flutter`.
2. ✅ Pigeon interface: configure, start login, step-up, start, respond, cancel, dispose, browser fallback, store / stored / current (refreshing) credentials, `hasValid`, logout, clear, resource request headers, `jkt`, metadata.
3. ✅ Dart API and model: `KeycloakNative`, `Authentication`, `NativeLoginFlow`, sealed `FlowStep`, `Challenge` (every spec/03 type, typed getters) and `ChallengeAnswer`, `Credentials`, `NativeAuthException`.
4. ✅ Android bridge over `KeycloakNative` with `KeystoreSecureStore`, `KeystoreDPoPKeys`, the Credential Manager platforms and `AuthTabWebPresenter` through the current activity; iOS bridge over `KeycloakNative` with the SDK's default Keychain store, Secure Enclave keys and browser.
5. ✅ `NativeLoginController` + `NativeLoginView` with default `username`, `password`, `totp`, `redirect_to_web`, "update required" screens, the "Try another way" chooser, `presenters`, `chooser`, `header`, `NativeLoginStrings`.
6. ✅ Example app on the demo realm (`demo-native`, `demoapp://auth/callback`; debug builds allow plain HTTP to `10.0.2.2` / `localhost`).
7. ✅ Tests of §7 (model, replay, widgets).

**B. The rest of the in-band screens**
8. ✅ Default screens for `otp`, `recovery_code`, `update_password` (policy hints ported to Dart), `verify_email`, `terms`, `push` (send, number match, polling), "Not now" for skippable required actions; a ticking `Countdown` for resend cooldowns that stops at zero.
9. ✅ German strings (`NativeLoginStringsDe`, the native catalogues' translations) picked by the app's locale (§10).
10. ✅ The flow log: `KeycloakNativeOptions.observeFlow`, `KeycloakNative.flowLog`, a Pigeon `@FlutterApi` from both bridges; the example's diagnostics page.

**C. Passkeys and saved passwords**
11. ✅ `NativeLoginFlow.usePasskey` and `registerPasskey` (native ceremony and answer), `autoSelectPasskey`, `Passkeys.registerNewPasskey` after login, `KeycloakNative.pickSavedPassword` / `savePassword`, "Use a saved password" and the save offer in the controller.
12. ✅ `Authentication.continueAfterTokenChallenge` with the token challenge kept natively (§4).
13. Open: the AASA and `assetlinks.json` setup for the example, which needs an HTTPS RP ID (a tunnel) and the app's signing identity; until then passkeys are verified by the replay tests and on the native demo apps.

**D. Push**
14. ✅ `Push` in Dart over `KeycloakNativePush` / core `Push`: in-app enrollment, mid-flow enrollment (`NativeLoginFlow.enrollPush`, `PushEnrollmentScreen`, the view's `pushRegistration`), pending approvals, approve / deny with number match or PIN, `handleMessage`, provider updates, key rotation, lockout, forgetting the enrollment; `PushApprovalsView`.
15. ✅ No Firebase in the plugin: the app hands in its FCM or APNs token (§3, §6). The example enrolls as `none` and reads its approvals.

**E. Hardening and release**
16. ✅ An `integration_test` suite against the compose stack (§7), run on the iOS simulator.
17. ✅ A CI job that builds the example for the iOS simulator.
18. Open: JVM and Swift unit tests of the bridges; the Flutter jobs as required checks (a repository setting); `dart pub publish` in the release workflow once the package name is settled (§10); a `docs/flutter-integration.md` guide next to the iOS and Android ones; a device pass (passkeys with an HTTPS RP ID, Keystore / Secure Enclave keys, the browser, real FCM and APNs delivery) and the live suite on an Android emulator.

## 10. Decisions and open questions

Decided (9 November 2026):

- **Swift Package Manager only, no podspec.** The iOS SDK ships only as a Swift package and Flutter integrates plugins through SPM by default; a podspec would need one for `KeycloakNativeCore` and `KeycloakNativePush` as well. Apps that turned SPM off cannot use the plugin; revisit only if integrators ask.
- **`FlutterFragmentActivity` stays a requirement on Android.** The browser fallback's Auth Tab launcher must be registered while a `ComponentActivity` is created. A plugin-owned transparent activity would lift the requirement at the cost of an extra activity hop and its own lifecycle edge cases; switching an app's `MainActivity` base class is one line, and the failure names the fix (`web_fallback_failed`). The same activity serves Credential Manager.
- **Only the access and ID token reach Dart.** Apps call APIs with the access token; DPoP-bound tokens need `CredentialsManager.resourceRequestHeaders` (one channel call per request). The plugin adds no HTTP client dependency; wrapping `package:http`'s `BaseClient` around `resourceRequestHeaders` is a few lines in the app (README).
- **Strings are a Dart class, English and German.** `NativeLoginStrings.of(context)` picks German for a `de` locale, English otherwise; apps subclass it to reword or add languages. No ARB files or `LocalizationsDelegate`, so the package needs no code generation and no `flutter_localizations` dependency, and apps with their own `intl` setup map their messages onto the getters.
- **No push messaging in the plugin.** See §3: the app owns APNs and FCM registration and hands in tokens and payloads.
- **Terms links open through the app.** `TermsScreen.openUrl` takes the app's launcher (e.g. `url_launcher`); without one the URL is shown as selectable text. The plugin does not depend on `url_launcher`.

Open, for the product owner:

- **The package name and publisher on pub.dev.** `keycloak_native` is a working name; publishing needs a verified publisher (phasetwo.io) and possibly a prefixed name (`phasetwo_keycloak_native`) to avoid implying an official Keycloak package. The Android package `io.phasetwo.keycloak.nativeauth.flutter` and the iOS module name follow whatever is chosen.
- **Minimum versions.** The plugin inherits iOS 17, Android API 28 and Kotlin 2.3+ (§3) from the SDKs. Whether those floors are acceptable for the Flutter audience is a product call; lowering them is SDK work, not plugin work.
- **Shared screens with React Native.** Both wrappers send the same messages; if spec/19 lands on the same handle-and-JSON-params channel shape, the message definitions could be shared and the bridges' native code could become a common internal module in each SDK.
