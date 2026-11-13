# 19 — React Native module plan (`react-native/keycloak-native-react-native`)

**Date:** 9 November 2026
**Status:** implemented through §10 step 8 (every challenge type, passkeys, saved passwords, push enrollment and approvals, the Expo config plugin). Publication (step 9) waits on the `phasetwo` npm organization and the SDK release that includes the compatibility changes (§8). Replaces "React Native wrapper" in ROADMAP "Later".
**Builds on:** 03 (the protocol, unchanged), 05 and 17 (the iOS and Android SDKs, which this module wraps), 15 (`skip`, `custom`, `x_*`).

A React Native app gets native authentication by **wrapping the two native SDK cores**, not by reimplementing the protocol in JavaScript. The SDKs already own everything that must stay on the device's secure side (Keychain and Keystore storage, non-exportable DPoP keys, passkey ceremonies, push device keys) and are verified against the server's transcripts; a JavaScript protocol client would duplicate that and move secrets into the JS heap. The module is a New Architecture TurboModule with a Codegen TypeScript spec. JavaScript gets the challenge loop as a typed discriminated union per challenge type, and React components replace the SwiftUI and Compose UI layers, with every default screen replaceable per challenge type as on iOS and Android.

## 1. Readiness

| Area | State | Gap |
|---|---|---|
| iOS SDK (`KeycloakNativeCore`, `KeycloakNativePush`) | Swift package at the repository root, async/await, iOS 17+ | consumed by the module through React Native's `spm_dependency` (§8) |
| Android SDK (`core`, `android`) | on Maven Central from 0.3.0, coroutines, minSdk 28, built against SDK 37 | usable from Kotlin 2.2 apps on compileSdk 36 once the compatibility change (§8) is merged |
| Conformance fixtures | `keycloak-native-auth/demo/transcripts/*.json` | none: the TypeScript tests read them in place (§9) |
| Server | unchanged | none: the module adds no protocol |
| React Native | 0.84 or later (New Architecture only; §8 "Floor"); the example runs 0.88; Codegen, `create-react-native-library` 0.64 scaffold | none |

## 2. Package layout

npm package `@p2-inc/keycloak-native-react-native` (§11), Apache-2.0 like the SDKs, in `react-native/keycloak-native-react-native/`:

| Path | Content |
|---|---|
| `src/NativeKeycloakNative.ts` | the Codegen spec (§4) |
| `src/model.ts` | the typed model: `Challenge` union, params per type, `FlowStep`, `ChallengeAnswer`, `Credentials`, the push types, `NativeAuthError` with the SDKs' codes |
| `src/KeycloakNative.ts` | the client API: `KeycloakNative` (with `push`), `NativeLoginFlow` (§5) |
| `src/ui/` | `LoginController` (the twin of the native `NativeLoginModel`s), `NativeLoginScreen`, the default screens for every type, `ChallengePresentationProps`, the chooser, `PushApprovalsController` / `PushApprovalsScreen`, English and German strings |
| `src/__tests__/` | Jest: model and transcript drift sweep, replays, controller flows for every screen, rendering, the config plugin (§9) |
| `ios/` | `KeycloakNativeModule.mm` (ObjC++, conforms to the generated protocol) forwarding to `KeycloakNativeBridge.swift`; `BridgeJSON.swift` |
| `android/` | `KeycloakNativeModule.kt` (extends the generated spec), `BridgeJson.kt`, `KeycloakNativeActivity.kt`, the package |
| `app.plugin.js`, `plugin/` | the Expo config plugin (§3) |
| `KeycloakNativeReactNative.podspec` | the pod, with `spm_dependency` on `KeycloakNativeCore` and `KeycloakNativePush` (§8) |
| `example/` | React Native app against the compose stack (login, step-up, passkey registration, push enrollment and approvals), with the composite build of `../../android` and the local Swift package |

The Flutter plugin (spec/18) is planned in parallel; the shapes here (one instance per issuer + client, `startLogin` / `start` / `respond(answer, challenge)`, answers named like the native cases, results `authorized` / `cancelled` / `failed`) are the native SDKs' shapes, so both wrappers stay symmetric with each other through them.

## 3. Decisions

- **The native side owns the flow.** `NativeLoginFlow` (with its PKCE verifier, DPoP signer and pending set), the full `Credentials` and the platform pieces live in the native module; JavaScript holds an instance id and a flow id. JavaScript keeps a mirror of the pending set to refuse stale or foreign challenges before they reach the bridge; the native flow validates again. Credentials of a released flow stay available to `credentialsManager.store` (the last few), so `release()` before `store()` is not an error.
- **JSON strings across the bridge.** Challenge `params` are open-ended JSON (spec/03 §10), so the native side forwards each descriptor and the `context` exactly as the server sent them (`Challenge.raw`, `FlowContext.raw`) and `src/model.ts` builds the typed views. Codegen object types would force a closed schema on an extensible protocol; one `string` per structured value keeps the spec stable as challenge types are added. Answers go the other way as `{kind, ...}` objects that the native side turns into `ChallengeAnswer`. Optional string arguments are passed as empty strings, which keeps the Codegen signatures free of nullable parameters.
- **What never crosses.** The refresh token and the post-login `auth_session` stay native: JavaScript gets `hasRefreshToken`, refreshes with `credentials(minTtl)`, and starts a step-up that reads the stored session natively. The DPoP private key never leaves the Secure Enclave or Keystore; JavaScript asks for `resourceRequestHeaders(method, url)` per request, and push device JWTs are signed natively. The access and ID tokens do cross, because apps send them with `fetch`. Passwords and codes cross as strings, as with any React Native login form; so does a password picked from the saved-password sheet, because the next step answers it.
- **Ceremonies run natively in one call.** `flow.usePasskey(challenge)` runs `kc.passkeys().assert(params)` and `flow.respond(.passkey(assertion), challenge)` in one promise; `flow.registerPasskey(challenge, label)` and `flow.enrollPush(challenge, deviceLabel, registration)` likewise (the enrollment is stored once the server accepted it). WebAuthn material and device JWTs never take a round trip through JavaScript.
- **Saved passwords.** `kc.pickSavedPassword()` shows the system sheet on both platforms. Saving after a login goes through Credential Manager on Android (`kc.savePassword`, which the controller calls once the flow is authorized with the password the user typed, never one that was rejected or picked); on iOS AutoFill offers to save from the screen's fields, so `savePassword` resolves without doing anything.
- **Push without a second notification stack.** React Native apps already own their notifications (`@react-native-firebase/messaging`, `expo-notifications`, `react-native-notifications`); a second `FirebaseMessagingService` or `UNUserNotificationCenter` delegate would fight them. The app passes the provider token to `push.enroll` / `push.updateProvider` (or to the screen's `pushRegistration`) and forwards message data to `push.handleMessage`, which runs the SDK's `handleMessage` / `handleNotification`. The module therefore needs **no event emitter**: nothing originates natively that JavaScript does not already receive from its notification library.
- **Threading.** Android: one `CoroutineScope(SupervisorJob() + Dispatchers.Default)` per module, cancelled in `invalidate()`; each promise settles exactly once; the SDK switches to the main thread where a platform API needs it. iOS: one `Task` per call; the instance and flow registries are actors; no lock is held across an `await`. A JavaScript promise cannot be cancelled; `flow.cancel()` is the explicit server cancel, as in the native SDKs.
- **Expo: a config plugin, not the Expo Modules API.** The module stays a TurboModule; Expo runs TurboModules in development builds and EAS (not in Expo Go). `app.plugin.js` does the native setup the module cannot do at runtime: `KeycloakNativeActivity.register(this)` in `MainActivity.onCreate`, the `NativeAuthRedirectActivity` intent filter for the `redirectUri`, floors for `android.minSdkVersion` (28), `android.compileSdkVersion` (36) and `android.kotlinVersion` (2.2) in `gradle.properties`, the iOS 17 deployment target (Podfile properties and the Xcode project), and `webcredentials:` Associated Domains entries. Its transforms are unit-tested; an Expo example app in CI is not planned.

## 4. TurboModule spec

`src/NativeKeycloakNative.ts`, module name `KeycloakNative`. Every method returns a promise except `releaseFlow`; errors reject with the SDK's `NativeAuthError` code as the promise's `code` and `statusCode`, `isNetworkError`, `isRetryable`, `retryAfter` in `userInfo`.

| Method | iOS (`KeycloakNativeCore`, `KeycloakNativePush`) | Android (`io.phasetwo.keycloak.nativeauth.sdk`) |
|---|---|---|
| `configure(instanceId, config)` | `KeycloakNative.configure(issuer:clientId:options:)` with `dpop`, `allowRpIdMismatch`, `ephemeralWebSession`, `metadataCacheTTL`, `keychainService`, `keychainAccessGroup` | `KeycloakNative.configure` with `KeystoreSecureStore(namespace)`, `KeystoreDPoPKeys`, `CredentialManagerPasskeyPlatform` / `…SavedPasswordPlatform` (current activity), the Auth Tab presenter (§7) |
| `createFlow(instanceId, parameters, stepUp)` | `authentication().startLogin(_:)` / `stepUp(_:)` | `authentication().startLogin(…)` / `stepUp(…)` |
| `start(flowId)`, `respond(flowId, challengeId, challengeType, answer, additionalFields)` | `flow.start()`, `flow.respond(_:to:additionalFields:)` on the pending challenge with that id and type | `flow.start()`, `flow.respond(answer, challenge, additionalFields)` |
| `respondWithPasskey`, `respondWithPasskeyRegistration`, `respondWithPushEnrollment` | `passkeys().assert` / `register`, `push().prepareEnrollment` + `commit`, then `flow.respond` | same |
| `cancel(flowId)`, `releaseFlow(flowId)` | `flow.cancel()`; drop the handle | same |
| `completeWebFallback(flowId)` | `webFallback().complete(request, flow:)` | `webFallback().complete(request, flow)` |
| `storeCredentials(flowId)` | `credentialsManager().store(_:)` with the flow's credentials | same |
| `credentials`, `storedCredentials`, `hasValidCredentials`, `logout`, `clearCredentials` | `CredentialsManager` | `CredentialsManager` |
| `resourceRequestHeaders(instanceId, method, url)` | `resourceRequestHeaders(for:method:url:)` with `credentials()` | same |
| `metadata`, `dpopKeyThumbprint` | `metadata(forceRefresh:).raw`, `dpopKeyThumbprint()` | same |
| `pickSavedPassword`, `savePassword`, `registerNewPasskey` | `pickSavedPassword()`, nothing (AutoFill), `passkeys().registerNewPasskey` | `pickSavedPassword()`, `savePassword`, `passkeys().registerNewPasskey` |
| `pushEnrollment`, `pushEnroll`, `pushForgetEnrollment`, `pushPendingApprovals`, `pushRespond`, `pushHandleMessage`, `pushUpdateProvider`, `pushRotateKey`, `pushLockout` | `push()` (`enrollment`, `enroll`, `forgetEnrollment`, `pendingApprovals`, `respond(cid:)`, `handleNotification`, `updatePushProvider`, `rotateKey`, `lockout`) | `push()` (same names, `handleMessage`) |

JSON shapes (the TypeScript readers are the reference):

```ts
// NativeFlowStep, from start / respond / respondWith…
{ kind: 'challenges', challenges: [/* descriptors as received */], context: {/* as received */}, expiresIn?: number }
{ kind: 'authorized', credentials: NativeCredentials }
{ kind: 'redirectToWeb', request: {/* the redirect_to_web body as received */} }

// NativeCredentials: epoch milliseconds; null for "never" (offline tokens)
{ accessToken, tokenType: 'Bearer' | 'DPoP', idToken, scope, expiresAt, refreshExpiresAt, issuedAt, hasRefreshToken, isDPoPBound }

// ChallengeAnswer, to respond: the native case names
{ kind: 'username', username } | { kind: 'password', password } | { kind: 'totp', code, credentialId? } | { kind: 'otp', code } | { kind: 'otpResend' }
| { kind: 'recoveryCode', code } | { kind: 'updatePassword', password, confirm } | { kind: 'verifyEmail', code } | { kind: 'verifyEmailResend' }
| { kind: 'terms', accepted } | { kind: 'pushResend' } | { kind: 'pushPoll' } | { kind: 'pushEnrollmentCheck' } | { kind: 'skip' } | { kind: 'custom', fields }

// Push: the enrollment (instants in epoch milliseconds), the pending approvals as the server sent them, a message payload
{ credentialId, deviceId, userId, username, deviceLabel, pushProviderType, pushProviderId, deviceApiBase, keyThumbprint, enrolledAt }
[ { cid, userId, username, clientId, clientName, createdAt, expiresAt, userVerification: { type, numbers } } ]
{ cid, credentialId, expiresAt }
```

## 5. TypeScript API

```ts
const kc = KeycloakNative.configure({ issuer: 'https://idp.example.com/realms/demo', clientId: 'demo-native' });
const flow = await kc.authentication.startLogin({ scope: 'openid profile', deviceName: 'Pixel' });
let step = await flow.start();
while (step.kind === 'challenges') {
  const challenge = step.supportedChallenges[0];
  step = challenge.type === 'passkey'
    ? await flow.usePasskey(challenge)
    : await flow.respond(answerFor(challenge), challenge);   // answer first, as in the native SDKs
}
const credentials = step.kind === 'authorized' ? step.credentials : await kc.webFallback.complete(step.request, flow);
await kc.credentialsManager.store(credentials);
flow.release();
const headers = await kc.resourceRequestHeaders('GET', 'https://api.example.com/me');
```

`Challenge` narrows on `type` (`'username' | 'password' | 'totp' | 'otp' | 'recovery_code' | 'passkey' | 'passkey_registration' | 'push' | 'push_enrollment' | 'update_password' | 'verify_email' | 'terms' | 'select' | 'unknown'`), so `challenge.type === 'totp'` makes `challenge.params.digits` a number. Every challenge also carries `wireType`, `label`, `required`, `error`, `retry`, `skippable`, `supported`, `requiredAction`, `rawParams` and `raw`. Instants are epoch milliseconds (`millisUntil` replaces `resendWait()`).

The UI layer mirrors the native ones: `<NativeLoginScreen kc flow onResult presenters chooser header strings autoSelectPasskey offerSavedPasswords offerToSavePassword pushRegistration />` drives an unstarted flow and reports `{kind: 'authorized', credentials} | {kind: 'cancelled'} | {kind: 'failed', error}`; it does not store credentials or navigate. `presenters={{ totp: MyTotpScreen }}` replaces one screen; a presenter receives `ChallengePresentationProps<'totp'>` (`challenge`, `challenges`, `alternatives`, `flowContext`, `isSubmitting`, `isStepUp`, `offersSavedPasswords`, `strings`, `submit(answer)`, `usePasskey()`, `registerPasskey(label)`, `enrollPush(deviceLabel)`, `useSavedPassword()`, `switchTo(other)`, `cancel()`). `LoginController` is the state machine behind it, usable without the default component. `<PushApprovalsScreen kc focus onResponded />` lists the pending approvals with number match or PIN, on `PushApprovalsController`. Strings come in English and German, picked from the device locale (`stringsForLocale`), and any of them can be replaced.

## 6. Challenge types

| Type | TS params | Answers | Native work | Default screen |
|---|---|---|---|---|
| `username` | `allowEmail`, `hint` | `username` | saved-password sheet (optional) | ✅ with "Use a saved password" |
| `password` | `usernameKnown` | `password` | saved-password sheet; save prompt after login (Android) | ✅ read-only username for password managers |
| `totp` | `digits`, `period`, `algorithm`, `credentials` | `totp` (+ `credentialId`) | none | ✅ authenticator picker, `oneTimeCode` |
| `otp` | `channel`, `destinationMasked`, `digits`, `ttl`, `sent`, `resendAllowedAt` | `otp`, `otpResend` | none | ✅ send first when `sent: false`, resend countdown |
| `recovery_code` | `remaining`, `warningThreshold`, `shouldWarn` | `recoveryCode` | none | ✅ remaining count, low warning |
| `update_password` | `username`, `policy`, `hints` | `updatePassword`, `skip` | save prompt after login (Android) | ✅ policy hints, mismatch check |
| `verify_email` | `emailMasked`, `digits`, `sent`, … | `verifyEmail`, `verifyEmailResend`, `skip` | none | ✅ send / resend countdown |
| `terms` | `text`, `url`, `version` | `terms` | none | ✅ scrollable text, link, accept / decline |
| `passkey` | `PasskeyAssertionParams` | `flow.usePasskey` | `kc.passkeys().assert` (ASAuthorization / Credential Manager) | ✅ `autoSelectPasskey` runs it immediately |
| `passkey_registration` | `PasskeyRegistrationParams` | `flow.registerPasskey(label)`, `skip` | `kc.passkeys().register` | ✅ offer ("Not now") or requirement |
| `push` | `PushParams` (number match, poll interval) | `pushResend`, `pushPoll` | none (polling from JS on `pollInterval`) | ✅ number, waiting state, polling |
| `push_enrollment` | `PushEnrollmentParams` | `flow.enrollPush(deviceLabel, registration)`, `pushEnrollmentCheck` | `push.prepareEnrollment` + `commit` | ✅ device name |
| `select`, `unknown` | raw params | `custom` | none | "Update required" screen |
| `redirectToWeb` step | `RedirectToWebRequest` | — | `webFallback().complete` | ✅ explains the required action |

## 7. Platform anchors

- **iOS.** `ASAuthorizationController` (passkeys, saved passwords) and `ASWebAuthenticationSession` (browser fallback) present over `Options.presentationAnchor`, whose default is the key window, which is the React Native root window. Passkeys and the saved-password sheet need the app's Associated Domains `webcredentials:<rp_id>` entitlement and the server's AASA, as for the Swift SDK (the config plugin writes the entitlement).
- **Android.** Credential Manager needs the activity on screen: the platforms get `reactContext.currentActivity` through their `() -> Activity?` constructors. `AuthTabWebPresenter` must register its activity result launcher before the activity starts, which a lazily created TurboModule cannot do, so the app calls `KeycloakNativeActivity.register(this)` in `MainActivity.onCreate` (two presenters, normal and ephemeral; dropped on destroy) and declares `NativeAuthRedirectActivity` for its `redirect_uri` as for the SDK. Without the call the browser fallback fails with `web_fallback_failed` and a message naming the fix. The Expo config plugin writes both. Passkeys need `assetlinks.json` for the RP ID, as for the SDK.
- **Push.** See §3: the token and the messages come from the app's notification library; approvals, rotation and lockout wrap `Push` (`KeycloakNativePush` / the `core` push package). `deviceType` in the device JWT is the platform's (`ios`, `android`).

## 8. Distribution

- **npm.** `@p2-inc/keycloak-native-react-native` on the repository's version line, published from the release tag once the SDKs it pins are public. `package.json` names the SDK release it wraps (`keycloakNativeSdkVersion`), read by the podspec and the Gradle file, so one bump moves both platforms. npm versions cannot carry `-SNAPSHOT`; the development version is `0.3.0-dev`. Peer dependencies: `react-native` 0.84 or later and `react` 19.2 or later (the floor below); `@expo/config-plugins` 56 or later (Expo SDK 56, the first on React Native 0.84 or later) is an optional peer for the plugin.
- **Floor: React Native 0.84.** Chosen as the oldest release the module is verified to compile and run on, with no unpatched advisories in the range.
  - *Evidence.* A fresh 0.84.1 app (template from `@react-native-community/cli` 20.1.3; React 19.2.3, AGP 8.12, compileSdk 36, Kotlin raised from 2.1.20 to 2.2.20, minSdk raised to 28, iOS 17) with the module installed from `npm pack` built for Android (`assembleDebug`) and iOS (`pod install`, `xcodebuild` for the simulator), and alice signed in with username, password and TOTP through the default screens on an Android 16 emulator and the iOS simulator against the compose stack, then built DPoP resource headers, refreshed and logged out. `scripts/floor-build.sh` reproduces the build (§9). It needs the SDK changes of the compatibility pull request: before them, the build fails on Kotlin metadata (2.4 against 2.1/2.2) and on the AAR's minimum compileSdk (37 against 36).
  - *Why not older.* 0.83 and earlier ship a `spm_dependency` that only takes remote package URLs, so the module cannot be built from a checkout or in CI before an SDK tag exists, and none was verified; Expo SDK 55 is on 0.83. Releases before 0.81 also default to compileSdk 35, below what the SDK's AndroidX dependencies need.
  - *Advisories considered* (GitHub advisory database for npm, NVD keyword searches for React Native and Hermes, 10 November 2026): `react-native` has one advisory, GHSA-7f53-fmmv-mfjv (CVE-2020-1920, ReDoS), fixed in 0.64.1. `react` and `hermes-engine` have none newer than 2022, all fixed long before 0.84. CVE-2025-11953 (GHSA-399j-vxmf-hjvr, critical: command injection through the Metro development server of `@react-native-community/cli`) affects the CLI before 18.0.1, 19.1.2 and 20.0.0; it is a development dependency of the app, and the 0.84 template uses 20.1.0, which is fixed. `npm audit` of the 0.84.1 template reports only low and moderate findings in development tooling (`deepmerge`, `fast-xml-parser`, `minimatch` through the CLI, Jest and typescript-eslint), none in runtime packages. Nothing in the range warranted a higher floor.
- **iOS: SPM through the pod, not a second pod.** React Native still links native modules with CocoaPods. Three ways to bring in the Swift SDK: (a) React Native's `spm_dependency` in the podspec, which adds the Swift package to the pod's target in the Pods project; (b) publish `KeycloakNativeCore` as its own pod; (c) vendor the Swift sources into this pod. **Implemented: (a).** The SDK keeps one distribution channel (the Swift package iOS apps already use, from this repository by tag), the pod builds the same sources the Swift tests verify, and React Native supports local package paths, so inside the repository the podspec points at the repository root and the module and the SDK change together. (b) would add a second release artifact on a channel whose central trunk is winding down to read-only, and (c) duplicates the sources. Costs of (a): React Native prints a static-linking warning for pods with Swift packages and builds such pods into the shared products directory to avoid duplicate module maps (the example builds and runs with static linking; `USE_FRAMEWORKS=dynamic` is the documented fallback if an app hits linker errors); the package resolves on every `pod install`. `KEYCLOAK_NATIVE_SPM_REMOTE=1` forces the remote package inside the repository to test what npm users get; `KEYCLOAK_NATIVE_SPM_PATH` points an installed copy at a local checkout (the floor build). When React Native links modules through SPM natively, the podspec drops out and nothing else changes.
- **Android: Maven Central artifacts, composite build in the repository.** The module depends on `io.phasetwo.keycloak.nativeauth:keycloak-native-android:<keycloakNativeSdkVersion>` (with `core` transitively), which apps resolve from Maven Central. The example's `settings.gradle` includes `../../../../android` as a composite build and substitutes `keycloak-native-core` and `keycloak-native-android` with its projects, so in-repo work never waits on a publication. Pins this forces on the example (documented there): the SDK's AGP 9.5.0 and Kotlin 2.4.21 (a composite build loads both builds' plugins into one Gradle run, and AGP refuses two versions), and Gradle 9.6.1, the one line that is new enough for AGP 9.5 and still embeds a Kotlin that React Native 0.88's Gradle plugin can read.
- **Consumer requirements (Android).** minSdk 28, compileSdk 36 and **Kotlin 2.2 or later** (React Native 0.87's and 0.88's default; apps on 0.84 to 0.86, whose template has Kotlin 2.1.20, set `kotlinVersion` to a 2.2 release and give the Kotlin Gradle plugin classpath entry that version). The SDK libraries compile at Kotlin language and API level 2.2, declare `kotlin-stdlib` 2.2.20 and use kotlinx.serialization 1.11 (built with Kotlin 2.3), so a 2.2 compiler reads all of them; before that change they carried Kotlin 2.4 metadata, which stock React Native apps could not read. The libraries also declare compileSdk 36 as their consumers' minimum (AGP 9 would otherwise record their own 37, which AGP 8 apps cannot compile with). Both changes are a separate pull request on the SDK ("Android SDK: usable from apps on Kotlin 2.2 and compileSdk 36", docs/android-integration.md "Kotlin version"); they must be in the SDK release the module pins.

## 9. Testing

- **TypeScript (Jest, every PR), 138 tests.** `model.test.ts`: the typed views per type, defaults, unknown types, errors, credentials; and a **drift sweep** over every recorded transcript: every challenge set parses, every type is known, and every descriptor, context and params field is one the model reads, so a field the server adds or renames fails the build until the model and its allow-list follow. `replay.test.ts`: the TypeScript API driven through `TranscriptNative`, a mock native module that replays a transcript, checks each request the TypeScript layer causes against the recording with the Swift and Kotlin harnesses' matching rules (same field set; values equal except `***` and the per-run `code_challenge`, `device_id`, `nonce`; ceremony fields only present) and hands back the recorded responses in the native JSON shapes, including the push device API. `flows.test.ts`: the controller through every default-screen path against recordings: email code sent on request and resend, recovery codes, `update_password` retries and the save prompt, `verify_email`, declined `terms`, a skipped passkey offer, passkey registration and an automatic discoverable passkey, a closed passkey prompt, push with number match approved through `PushApprovalsController` after a wrong number, a refused then accepted mid-flow push enrollment, in-app enrollment, saved passwords. `screens.test.tsx` renders every default screen (countdowns, polling, hints, skip), the string catalogues and the approvals screen; `NativeLoginScreen.test.tsx` and `LoginController.test.ts` cover the screen and controller basics; `plugin.test.ts` the config plugin's transforms on Expo's and React Native's templates.
- **Floor build.** `scripts/floor-build.sh [android|ios|all] [work-dir]` creates a fresh app from the floor release's template (`RN_VERSION`, default 0.84.1), installs the module from `npm pack`, applies the documented setup (minSdk 28, Kotlin 2.2.20, the browser-fallback registration, iOS 17), publishes the checkout's Android SDK to a local Maven repository (or takes `KEYCLOAK_NATIVE_MAVEN_REPO`) and points the pod at the checkout's Swift package, then runs `assembleDebug` and `pod install` plus `xcodebuild` for the simulator. It is meant for a CI job.
- **Native bridges.** Both compile in the example builds: `assembleDebug` (the Kotlin bridge against the SDK through the composite build) and `xcodebuild` for the simulator (the Swift bridge against the local package through `spm_dependency`). The Kotlin bridge also compiles against SDK artifacts on React Native 0.88's own plugin versions (AGP 9.2.1, Kotlin 2.2.0) once the SDK is built at language level 2.2.
- **End to end.** The example app ran against the compose stack on the iOS simulator (iPhone 17 Pro, driven by an XCUITest) and on an Android 16 emulator (driven over adb and uiautomator): alice signed in with username, password and TOTP through the default screens, got DPoP-bound tokens, built resource headers, refreshed and logged out. Neither driver is committed; next is the same as a Maestro flow for both platforms in CI.
- **CI.** The `react-native` job: typecheck, lint, Jest, and the example's `assembleDebug` through the composite build. An iOS job (`pod install` and `xcodebuild` on a macOS runner) follows once the job's runtime is acceptable; it is the slowest of the repository's jobs.

## 10. Order of work

1. ✅ Plan (this document).
2. ✅ Scaffold (`create-react-native-library` 0.64, TurboModule, Kotlin + Objective-C++ with the Swift bridge behind it, vanilla example, Jest, ESLint), Apache-2.0, `spm_dependency` and the composite build.
3. ✅ First slice: `configure`, `startLogin` / `stepUp`, `start` / `respond`, browser fallback, credentials, `resourceRequestHeaders`, `metadata`, `jkt`; default screens for `username`, `password`, `totp`; the example app.
4. ✅ Tests: transcript drift sweep, replays, controller and rendering tests.
5. ✅ Example builds on Android (`assembleDebug`) and iOS (`pod install`, `xcodebuild` for the simulator); the CI job; the username, password and TOTP login on the iOS simulator and the Android emulator against the compose stack.
6. ✅ Default screens for `otp`, `recovery_code`, `update_password`, `verify_email`, `terms`, `push` (number match, polling on `pollInterval`, resend countdowns) and the chooser titles of the native layers; English and German strings.
7. ✅ Native ceremonies: passkey assertion and registration (in a flow and from inside the app), the saved-password sheet and save prompt; the Expo config plugin.
8. ✅ Push: enrollment mid-flow and in-app, approvals with number match and PIN, provider token updates, message handling, key rotation, lockout, `PushApprovalsScreen`.
9. Publication: npm under the `phasetwo` organization with the SDKs' release, a CI job building the floor (`scripts/floor-build.sh`), an iOS CI job, Maestro end-to-end flows for both platforms, and the module listed in the docs' reading guide (done: docs/react-native-integration.md).

## 11. Open questions

Decided while building (kept here for the record):

- **Kotlin metadata level of the Android SDK.** Decided: the SDK builds at language and API level 2.2 and accepts compileSdk 36 (§8). Apps need Kotlin 2.2 or later.
- **iOS anchor for multi-window apps.** Decided: the key window, which is React Native's root window. An option to name another anchor is added when an iPad multi-scene app asks for it.
- **Expo support level.** Decided: the config plugin, unit-tested; no Expo example app in CI.
- **Minimum React Native version.** Decided: 0.84 (§8 "Floor"), the oldest release the module is verified to build and run on; `peerDependencies` say `>=0.84.0`.
- **Native events.** Decided: none (§3, push).

- **Package name.** Decided by the product owner: `@p2-inc/keycloak-native-react-native`, under the `p2-inc` npm organization with Phase Two's other npm package (`@p2-inc/js-sdk`). 0.3.0 was published as `@phasetwo.io/keycloak-native-react-native`, which is deprecated in favor of this name. The package lives in `react-native/keycloak-native-react-native/`; the pod is `KeycloakNativeReactNative`.
- **Refresh token in JavaScript.** Decided by the product owner: it stays native-only, and there is no export API. JavaScript runs third-party npm code in one context, the usual persistence (AsyncStorage) is plain text, logging and developer tools capture what passes through JavaScript, over-the-air updates can replace the JavaScript after review, and a refresh token outlives every access token. Apps that must hand a session to a web view or a backend use their own token exchange on the server. docs/react-native-integration.md "Tokens and DPoP" explains this to integrators and recommends DPoP binding.
