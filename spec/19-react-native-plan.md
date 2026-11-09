# 19 — React Native module plan (`react-native/keycloak-native`)

**Date:** 9 November 2026
**Status:** plan, with the first vertical slice implemented (§10 steps 1–4). Replaces "React Native wrapper" in ROADMAP "Later".
**Builds on:** 03 (the protocol, unchanged), 05 and 17 (the iOS and Android SDKs, which this module wraps), 15 (`skip`, `custom`, `x_*`).

A React Native app gets native authentication by **wrapping the two native SDK cores**, not by reimplementing the protocol in JavaScript. The SDKs already own everything that must stay on the device's secure side (Keychain and Keystore storage, non-exportable DPoP keys, passkey ceremonies, push device keys) and are verified against the server's transcripts; a JavaScript protocol client would duplicate that and move secrets into the JS heap. The module is a New Architecture TurboModule with a Codegen TypeScript spec. JavaScript gets the challenge loop as a typed discriminated union per challenge type, and React components replace the SwiftUI and Compose UI layers, with every default screen replaceable per challenge type as on iOS and Android.

## 1. Readiness

| Area | State | Gap |
|---|---|---|
| iOS SDK (`KeycloakNativeCore`, `KeycloakNativePush`) | Swift package at the repository root, async/await, iOS 17+ | consumed by the module through React Native's `spm_dependency` (§8) |
| Android SDK (`core`, `android`, `push`) | Gradle build in `android/`, coroutines, minSdk 28, compileSdk 37 | Maven Central publication in progress; in-repo builds use a composite build (§8) |
| Conformance fixtures | `keycloak-native-auth/demo/transcripts/*.json` | none: the TypeScript tests read them in place (§9) |
| Server | unchanged | none: the module adds no protocol |
| React Native | 0.88 (New Architecture only), Codegen, `create-react-native-library` 0.64 scaffold | none |

## 2. Package layout

npm package `@phasetwo/react-native-keycloak-native` (name to confirm, §11), Apache-2.0 like the SDKs, in `react-native/keycloak-native/`:

| Path | Content |
|---|---|
| `src/NativeKeycloakNative.ts` | the Codegen spec (§4) |
| `src/model.ts` | the typed challenge model: `Challenge` union, params per type, `FlowStep`, `ChallengeAnswer`, `Credentials`, `NativeAuthError` with the SDKs' codes |
| `src/KeycloakNative.ts` | the client API: `KeycloakNative`, `NativeLoginFlow` (§5) |
| `src/ui/` | `LoginController` (the twin of the native `NativeLoginModel`s, plain TypeScript), `NativeLoginScreen`, the default screens, `ChallengePresentationProps`, the chooser, English strings |
| `src/__tests__/` | Jest: model, transcript replay through a mock native module, controller, rendering (§9) |
| `ios/` | `KeycloakNativeModule.mm` (ObjC++, conforms to the generated protocol) forwarding to `KeycloakNativeBridge.swift`; `BridgeJSON.swift` |
| `android/` | `KeycloakNativeModule.kt` (extends the generated spec), `BridgeJson.kt`, `KeycloakNativeActivity.kt`, the package |
| `ReactNativeKeycloakNative.podspec` | the pod, with `spm_dependency` on `KeycloakNativeCore` (§8) |
| `example/` | React Native app against the compose stack (`demo-native`), with the composite build of `../../android` and the local Swift package |

The Flutter plugin (spec/18) is planned in parallel; the shapes here (one instance per issuer + client, `startLogin` / `start` / `respond(answer, challenge)`, answers named like the native cases, results `authorized` / `cancelled` / `failed`) are the native SDKs' shapes, so both wrappers stay symmetric with each other through them.

## 3. Decisions

- **The native side owns the flow.** `NativeLoginFlow` (with its PKCE verifier, DPoP signer and pending set), the full `Credentials` and the platform pieces live in the native module; JavaScript holds an instance id and a flow id. JavaScript keeps a mirror of the pending set to refuse stale or foreign challenges before they reach the bridge; the native flow validates again.
- **JSON strings across the bridge.** Challenge `params` are open-ended JSON (spec/03 §10), so the native side forwards each descriptor and the `context` exactly as the server sent them (`Challenge.raw`, `FlowContext.raw`) and `src/model.ts` builds the typed views. Codegen object types would force a closed schema on an extensible protocol; one `string` per structured value keeps the spec stable as challenge types are added. Answers go the other way as `{kind, ...}` objects that the native side turns into `ChallengeAnswer`.
- **What never crosses.** The refresh token and the post-login `auth_session` stay native: JavaScript gets `hasRefreshToken`, refreshes with `credentials(minTtl)`, and starts a step-up that reads the stored session natively. The DPoP private key never leaves the Secure Enclave or Keystore; JavaScript asks for `resourceRequestHeaders(method, url)` per request. The access and ID tokens do cross, because apps send them with `fetch`. Passwords and codes cross as strings, as with any React Native login form.
- **Ceremonies run natively in one call.** Passkey assertion and registration, the saved-password sheet and push enrollment will be answers that the native side completes itself (`{kind: 'passkey'}` runs `kc.passkeys().assert(params)` and `flow.respond(.passkey(assertion), challenge)` in one promise), so WebAuthn material never takes a round trip through JavaScript.
- **Threading.** Android: one `CoroutineScope(SupervisorJob() + Dispatchers.Default)` per module, cancelled in `invalidate()`; each promise settles exactly once; the SDK switches to the main thread where a platform API needs it. iOS: one `Task` per call; the instance and flow registries are actors; no lock is held across an `await`. A JavaScript promise cannot be cancelled; `flow.cancel()` is the explicit server cancel, as in the native SDKs.
- **Expo.** The module stays a TurboModule; the Expo Modules API would be a second implementation with no gain, since Expo runs TurboModules in development builds and EAS (not in Expo Go). What Expo users need is a **config plugin** (`app.plugin.js` in the same package) for the native setup the module cannot do itself: `KeycloakNativeActivity.register(this)` in `MainActivity.onCreate`, the `NativeAuthRedirectActivity` intent filter for the `redirect_uri`, `minSdkVersion 28`, the iOS 17 deployment target and the Associated Domains entitlement. Recommended for phase 3 (§10).

## 4. TurboModule spec

`src/NativeKeycloakNative.ts`, module name `KeycloakNative`. Every method returns a promise except `releaseFlow`; errors reject with the SDK's `NativeAuthError` code as the promise's `code` and `statusCode`, `isNetworkError`, `isRetryable`, `retryAfter` in `userInfo`.

| Method | iOS (`KeycloakNativeCore`) | Android (`io.phasetwo.keycloak.nativeauth.sdk`) |
|---|---|---|
| `configure(instanceId, config)` | `KeycloakNative.configure(issuer:clientId:options:)` with `dpop`, `allowRpIdMismatch`, `ephemeralWebSession`, `metadataCacheTTL`, `keychainService`, `keychainAccessGroup` | `KeycloakNative.configure` with `KeystoreSecureStore(namespace)`, `KeystoreDPoPKeys`, `CredentialManagerPasskeyPlatform` / `…SavedPasswordPlatform` (current activity), the Auth Tab presenter (§7) |
| `createFlow(instanceId, parameters, stepUp)` | `authentication().startLogin(_:)` / `stepUp(_:)` | `authentication().startLogin(…)` / `stepUp(…)` |
| `start(flowId)`, `respond(flowId, challengeId, challengeType, answer, additionalFields)` | `flow.start()`, `flow.respond(_:to:additionalFields:)` on the pending challenge with that id and type | `flow.start()`, `flow.respond(answer, challenge, additionalFields)` |
| `cancel(flowId)`, `releaseFlow(flowId)` | `flow.cancel()`; drop the handle | same |
| `completeWebFallback(flowId)` | `webFallback().complete(request, flow:)` | `webFallback().complete(request, flow)` |
| `storeCredentials(flowId)` | `credentialsManager().store(_:)` with the flow's credentials | same |
| `credentials`, `storedCredentials`, `hasValidCredentials`, `logout`, `clearCredentials` | `CredentialsManager` | `CredentialsManager` |
| `resourceRequestHeaders(instanceId, method, url)` | `resourceRequestHeaders(for:method:url:)` with `credentials()` | same |
| `metadata`, `dpopKeyThumbprint` | `metadata(forceRefresh:).raw`, `dpopKeyThumbprint()` | same |

JSON shapes (the TypeScript readers are the reference):

```ts
// NativeFlowStep, from start / respond
{ kind: 'challenges', challenges: [/* descriptors as received */], context: {/* as received */}, expiresIn?: number }
{ kind: 'authorized', credentials: NativeCredentials }
{ kind: 'redirectToWeb', request: {/* the redirect_to_web body as received */} }

// NativeCredentials: epoch milliseconds; null for "never" (offline tokens)
{ accessToken, tokenType: 'Bearer' | 'DPoP', idToken, scope, expiresAt, refreshExpiresAt, issuedAt, hasRefreshToken, isDPoPBound }

// ChallengeAnswer, to respond: the native case names
{ kind: 'username', username } | { kind: 'password', password } | { kind: 'totp', code, credentialId? } | { kind: 'otp', code } | { kind: 'otpResend' }
| { kind: 'recoveryCode', code } | { kind: 'updatePassword', password, confirm } | { kind: 'verifyEmail', code } | { kind: 'verifyEmailResend' }
| { kind: 'terms', accepted } | { kind: 'pushResend' } | { kind: 'pushPoll' } | { kind: 'pushEnrollmentCheck' } | { kind: 'skip' } | { kind: 'custom', fields }
```

Later phases add `usePasskey`, `registerPasskey`, `pickSavedPassword` / `savePassword` and the push methods (§10), and a Codegen `EventEmitter` for push approvals and FCM / APNs token changes.

## 5. TypeScript API

```ts
const kc = KeycloakNative.configure({ issuer: 'https://idp.example.com/realms/demo', clientId: 'demo-native' });
const flow = await kc.authentication.startLogin({ scope: 'openid profile', deviceName: 'Pixel' });
let step = await flow.start();
while (step.kind === 'challenges') {
  const challenge = step.supportedChallenges[0];
  step = await flow.respond(answerFor(challenge), challenge);   // answer first, as in the native SDKs
}
const credentials = step.kind === 'authorized' ? step.credentials : await kc.webFallback.complete(step.request, flow);
await kc.credentialsManager.store(credentials);
const headers = await kc.resourceRequestHeaders('GET', 'https://api.example.com/me');
```

`Challenge` narrows on `type` (`'username' | 'password' | 'totp' | 'otp' | 'recovery_code' | 'passkey' | 'passkey_registration' | 'push' | 'push_enrollment' | 'update_password' | 'verify_email' | 'terms' | 'select' | 'unknown'`), so `challenge.type === 'totp'` makes `challenge.params.digits` a number. Every challenge also carries `wireType`, `label`, `required`, `error`, `retry`, `skippable`, `supported`, `requiredAction`, `rawParams` and `raw`. Instants are epoch milliseconds (`millisUntil` replaces `resendWait()`).

The UI layer mirrors the native ones: `<NativeLoginScreen kc flow onResult presenters chooser header strings />` drives an unstarted flow and reports `{kind: 'authorized', credentials} | {kind: 'cancelled'} | {kind: 'failed', error}`; it does not store credentials or navigate. `presenters={{ totp: MyTotpScreen }}` replaces one screen; a presenter receives `ChallengePresentationProps<'totp'>` (`challenge`, `challenges`, `alternatives`, `flowContext`, `isSubmitting`, `isStepUp`, `strings`, `submit(answer)`, `switchTo(other)`, `cancel()`, later `usePasskey()`, `registerPasskey(label)`, `enrollPush(deviceLabel)`, `useSavedPassword()`). `LoginController` is the state machine behind it, usable without the default component.

## 6. Challenge types

| Type | TS params | Answers | Native work | Default screen |
|---|---|---|---|---|
| `username` | `allowEmail`, `hint` | `username` | none | ✅ slice 1 (`textContentType="username"`) |
| `password` | `usernameKnown` | `password` | none | ✅ slice 1 (read-only username for password managers) |
| `totp` | `digits`, `period`, `algorithm`, `credentials` | `totp` (+ `credentialId`) | none | ✅ slice 1 (authenticator picker, `oneTimeCode`) |
| `otp` | `channel`, `destinationMasked`, `digits`, `ttl`, `sent`, `resendAllowedAt` | `otp`, `otpResend` | none | phase 2 (resend countdown) |
| `recovery_code` | `remaining`, `warningThreshold`, `shouldWarn` | `recoveryCode` | none | phase 2 |
| `update_password` | `username`, `policy`, `hints` | `updatePassword`, `skip` | none | phase 2 |
| `verify_email` | `emailMasked`, `digits`, `sent`, … | `verifyEmail`, `verifyEmailResend` | none | phase 2 |
| `terms` | `text`, `url`, `version` | `terms` | none | phase 2 |
| `passkey` | `PasskeyAssertionParams` | native `usePasskey` | `kc.passkeys().assert` (ASAuthorization / Credential Manager) | phase 3 |
| `passkey_registration` | `PasskeyRegistrationParams` | native `registerPasskey(label)`, `skip` | `kc.passkeys().register` | phase 3 |
| `push` | `PushParams` (number match, poll interval) | `pushResend`, `pushPoll` | none (polling from JS on `pollInterval`) | phase 2 |
| `push_enrollment` | `PushEnrollmentParams` | native `enrollPush(deviceLabel, provider)`, `pushEnrollmentCheck` | `push.prepareEnrollment` + `commit` | phase 4 |
| `select`, `unknown` | raw params | `custom` | none | "Update required" screen |
| `redirectToWeb` step | `RedirectToWebRequest` | — | `webFallback().complete` | ✅ slice 1 |

Answers for types without native work are already accepted by both native bridges, so custom screens can use them before the default screens exist.

## 7. Platform anchors

- **iOS.** `ASAuthorizationController` (passkeys, saved passwords) and `ASWebAuthenticationSession` (browser fallback) present over `Options.presentationAnchor`, whose default is the key window, which is the React Native root window. Apps with several scenes will need a way to name the anchor (open question). Passkeys need the app's Associated Domains `webcredentials:<rp_id>` entitlement and the server's AASA, as for the Swift SDK.
- **Android.** Credential Manager needs the activity on screen: the platforms get `reactContext.currentActivity` through their `() -> Activity?` constructors. `AuthTabWebPresenter` must register its activity result launcher before the activity starts, which a lazily created TurboModule cannot do, so the app calls `KeycloakNativeActivity.register(this)` in `MainActivity.onCreate` (two presenters, normal and ephemeral; dropped on destroy) and declares `NativeAuthRedirectActivity` for its `redirect_uri` as for the SDK. Without the call the browser fallback fails with `web_fallback_failed` and a message naming the fix. The Expo config plugin writes both.
- **Push.** React Native apps already own their notifications through `@react-native-firebase/messaging`, `expo-notifications` or `react-native-notifications`, and a second `FirebaseMessagingService` or `UNUserNotificationCenter` delegate would fight them. The module will therefore take the provider token from JavaScript (`push.enroll({provider: 'fcm' | 'apns', token, deviceLabel})`, `push.updateToken`) and expose `push.handleMessage(data)` for the app's notification handler to forward payloads to the SDKs' `handleMessage`, which verifies and resolves them locally; approvals, rotation and lockout wrap `Push` (`KeycloakNativePush` / the `core` push package). The SDKs' `FcmPush` helpers stay usable from native code for apps that prefer them.

## 8. Distribution

- **npm.** `@phasetwo/react-native-keycloak-native` on the repository's version line, published from the release tag once the SDKs it pins are public. `package.json` names the SDK release it wraps (`keycloakNativeSdkVersion`), read by the podspec and the Gradle file, so one bump moves both platforms. npm versions cannot carry `-SNAPSHOT`; the development version is `0.3.0-dev`.
- **iOS: SPM through the pod, not a second pod.** React Native still links native modules with CocoaPods. Three ways to bring in the Swift SDK: (a) React Native's `spm_dependency` in the podspec, which adds the Swift package to the pod's target in the Pods project; (b) publish `KeycloakNativeCore` as its own pod; (c) vendor the Swift sources into this pod. **Recommended and implemented: (a).** The SDK keeps one distribution channel (the Swift package iOS apps already use, from this repository by tag), the pod builds the same sources the Swift tests verify, and React Native supports local package paths, so inside the repository the podspec points at the repository root and the module and the SDK change together. (b) would add a second release artifact on a channel whose central trunk is winding down to read-only, and (c) duplicates the sources. Costs of (a): React Native prints a static-linking warning for pods with Swift packages and flattens such pods' build directories to avoid duplicate module maps (if that fails in practice, `USE_FRAMEWORKS=dynamic` is the documented fallback); the package resolves on every `pod install`; it needs React Native 0.75 or later, and local package paths need a version whose `spm.rb` handles them (0.88 does). `KEYCLOAK_NATIVE_SPM_REMOTE=1` forces the remote package inside the repository to test what npm users get. When React Native links modules through SPM natively, the podspec drops out and nothing else changes.
- **Android: Maven Central artifacts, composite build in the repository.** The module depends on `io.phasetwo.keycloak.nativeauth:keycloak-native-android:<keycloakNativeSdkVersion>` (with `core` transitively), which apps resolve from Maven Central. The example's `settings.gradle` includes `../../../../android` as a composite build and substitutes `keycloak-native-core` and `keycloak-native-android` with its projects, so in-repo work never waits on a publication. Pins this forces on the example (documented there): the SDK's AGP 9.5.0 and Kotlin 2.4.21 (a composite build loads both builds' plugins into one Gradle run, and AGP refuses two versions), and Gradle 9.6.1, the one line that is new enough for AGP 9.5 (9.6.0 minimum) and still embeds a Kotlin that React Native 0.88's Gradle plugin, compiled with Kotlin 2.2, can read (Gradle 9.7 embeds 2.4).
- **Consumer requirements (Android).** minSdk 28 and compileSdk 37 (the SDK's), and a Kotlin compiler that reads the SDK's class metadata: the SDK is built with Kotlin 2.4, whose metadata a 2.2 compiler (React Native 0.88's default `kotlinVersion`) refuses. Either apps raise `kotlinVersion` to 2.3 or later, or the SDK compiles with `languageVersion`/`apiVersion` 2.2 before its Central release (a build setting, not an API change; recommended, §11).

## 9. Testing

- **TypeScript (Jest, every PR).** `model.test.ts`: the typed views per type, defaults, unknown types, errors, credentials; and a **drift sweep** over every recorded transcript: every challenge set parses, every type is known, and every descriptor, context and params field is one the model reads, so a field the server adds or renames fails the build until the model and its allow-list follow. `replay.test.ts`: the TypeScript API driven through `TranscriptNative`, a mock native module that replays a transcript, checks each request the TypeScript layer causes against the recording with the Swift and Kotlin harnesses' matching rules (same field set; values equal except `***` and the per-run `code_challenge`, `device_id`, `nonce`) and hands back the recorded responses in the native JSON shapes. Its form encoding mirrors `ChallengeAnswer.formFields` and `LoginFlow.start()`; the native SDKs' own replay suites pin those on the wire. `LoginController.test.ts` (the twin of the native model tests) and `NativeLoginScreen.test.tsx` (default screens and a replacement presenter rendered through to `authorized`).
- **Native bridges.** The Kotlin bridge compiles against the SDK in the example's Android build; the Swift bridge in the pod. Next: JVM unit tests for `BridgeJson` (answers and credentials encoding) in `android/src/test`, and Swift tests for `BridgeJSON` in the example's test target.
- **End to end.** The example app against the compose stack (Android emulator at `10.0.2.2`, iOS simulator at `localhost`), then a Detox or Maestro suite for the slice-1 logins, as the iOS XCUITests and the Android Compose test do.
- **CI.** A `react-native` job: typecheck, lint, Jest, and the example's `assembleDebug` through the composite build. Not a required check until it has run green for a while; an iOS `xcodebuild` job for the example follows once `pod install` with the local Swift package is proven on the runner.

## 10. Order of work

1. ✅ Plan (this document).
2. ✅ Scaffold (`create-react-native-library` 0.64, TurboModule, Kotlin + Objective-C++ with the Swift bridge behind it, vanilla example, Jest, ESLint), Apache-2.0, `spm_dependency` and the composite build.
3. ✅ First slice: `configure`, `startLogin` / `stepUp`, `start` / `respond` for every answer without native work, browser fallback, credentials (`store`, `stored`, `credentials` with refresh, `hasValid`, `logout`, `clear`), `resourceRequestHeaders`, `metadata`, `jkt`; default React screens for `username`, `password`, `totp`, the browser fallback, "Try another way" and an "Update required" screen; the example app.
4. ✅ Tests: 105 Jest tests, including the transcript drift sweep and replays; typecheck and lint clean. The native bridges are checked without the example app: the Kotlin bridge compiles against the SDK's `core` and `android` modules (through the composite build, with the React Native classes it uses stubbed from the Codegen output), and the Swift bridge type-checks against `KeycloakNativeCore`; the Objective-C++ selectors match the generated protocol.
5. Example builds on Android (`assembleDebug`) and iOS (`xcodebuild` for the simulator), and the CI job; then the slice-1 logins by hand against the compose stack on both platforms.
6. Phase 2: default screens for `otp`, `recovery_code`, `update_password`, `verify_email`, `terms`, `push` (number match, polling on `pollInterval`, resend countdowns); English and German strings like the native catalogues; bridge unit tests.
7. Phase 3: native ceremonies: passkey assertion and registration, the saved-password sheet and save prompt; the Expo config plugin; Associated Domains and `assetlinks.json` notes.
8. Phase 4: push (§7): enrollment mid-flow and in-app, approvals with number match, token updates, rotation, lockout, the approvals list as a React component, the event emitter.
9. Phase 5: npm publication with the SDKs' Central / tag release, the docs/ integration guide, an iOS CI job, Detox or Maestro end to end.

## 11. Open questions

- **Package name.** `@phasetwo/react-native-keycloak-native` assumes the `@phasetwo` npm scope; confirm it, or choose a shorter name.
- **Refresh token in JavaScript.** Withheld by design; some apps sync sessions to a web view or a backend and will ask for it. An explicit `exportRefreshToken()` would be the escape hatch if needed.
- **Kotlin metadata level of the Android SDK.** Build the SDK with `languageVersion = 2.2` so stock React Native 0.88 apps (Kotlin 2.2) can compile against it, or document Kotlin 2.3+ as a requirement.
- **iOS anchor for multi-window apps.** The key window is right for React Native's single root window; iPad apps with several scenes need a way to choose.
- **Expo support level.** Config plugin only (recommended), or also an Expo example app in CI.
- **Minimum React Native version.** New Architecture only. 0.88 is what the module is built against; the floor is set once CI covers older versions (local Swift package paths in `spm_dependency` and Codegen `EventEmitter` decide it).
