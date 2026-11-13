# Integrating the React Native module

[Index](README.md) · [Protocol](protocol-and-flows.md) · [iOS integration](ios-integration.md) · [Android integration](android-integration.md) · [Plan (spec/19)](../spec/19-react-native-plan.md)

`@p2-inc/keycloak-native-react-native` (in [`react-native/keycloak-native-react-native/`](../react-native/keycloak-native-react-native/)) signs users in to Keycloak with your app's React Native screens instead of a browser. It is a New Architecture TurboModule over the iOS and Android SDKs: the native side runs the challenge protocol, keeps credentials in the Keychain or Android Keystore, holds the DPoP key in the Secure Enclave or Keystore and runs the passkey, saved-password, browser and push ceremonies; JavaScript gets the challenge loop as a typed model and default React screens that can be replaced one challenge type at a time. The module is below 1.0 and not yet on npm.

## Requirements

- React Native 0.84 or later with the New Architecture (the floor and why it is there: [spec/19 §8](../spec/19-react-native-plan.md#8-distribution)). Expo SDK 56 or later works in development builds and EAS with the [config plugin](#expo), not in Expo Go.
- iOS 17 or later. The pod brings in the Swift package products `KeycloakNativeCore` and `KeycloakNativePush` through React Native's `spm_dependency`; `pod install` resolves them.
- Android minSdk 28 (API 28, Android 9), compileSdk 36 and Kotlin 2.2 or later (see the Android guide's [Kotlin version](android-integration.md#kotlin-version)). React Native 0.87 and later use Kotlin 2.2 already; on 0.84 to 0.86, whose template has Kotlin 2.1.20, set `kotlinVersion = "2.2.20"` in `android/build.gradle` and use it for the Kotlin Gradle plugin: `classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")`. The SDK comes from Maven Central.
- A public Keycloak client configured with the [server setup](README.md#practical-quick-start): PKCE S256 required, and a callback such as `demoapp://auth/callback` for the browser fallback.

## Setup

**iOS.** `pod install`. For passkeys and the saved-password sheet, add the Associated Domains entitlement `webcredentials:<rp_id>` and serve the AASA file, as for the [Swift SDK](ios-integration.md). The browser fallback needs no URL scheme registration. If the static-linking warning React Native prints for pods with Swift packages turns into linker errors in your app, build with `USE_FRAMEWORKS=dynamic`.

**Android.** The browser fallback registers an activity result launcher, which Android only allows before the activity starts, so register it in `MainActivity` and declare the SDK's callback activity for your `redirect_uri`:

```kotlin
import io.phasetwo.keycloak.nativeauth.reactnative.KeycloakNativeActivity

override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  KeycloakNativeActivity.register(this)
}
```

```xml
<activity
  android:name="io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity"
  android:exported="true"
  android:theme="@android:style/Theme.Translucent.NoTitleBar">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="demoapp" android:host="auth" android:path="/callback" />
  </intent-filter>
</activity>
```

Without the `register` call the browser fallback fails with `web_fallback_failed` and a message naming the fix. Passkeys need `assetlinks.json` for the RP ID, as for the [Android SDK](android-integration.md).

### Expo

The package ships a config plugin that does both platforms' setup during `npx expo prebuild`:

```json
{
  "expo": {
    "plugins": [
      ["@p2-inc/keycloak-native-react-native", {
        "redirectUri": "demoapp://auth/callback",
        "associatedDomains": ["idp.example.com"]
      }]
    ]
  }
}
```

It adds the `register` call to `MainActivity.onCreate`, declares `NativeAuthRedirectActivity` for `redirectUri`, raises `android.minSdkVersion`, `android.compileSdkVersion` and `android.kotlinVersion` in `gradle.properties` to 28, 36 and 2.2.0 (higher values are kept), sets the iOS deployment target to 17.0, and adds `webcredentials:` entries for `associatedDomains`.

## Configure

Keep one instance per issuer and client for the life of the app, so credentials, the DPoP key, the metadata cache and refreshes stay consistent:

```ts
import { KeycloakNative } from '@p2-inc/keycloak-native-react-native';

export const kc = KeycloakNative.configure({
  issuer: 'https://idp.example.com/realms/demo', // including /realms/<realm>
  clientId: 'demo-native',
});
```

Options: `dpop` (`automatic` by default: Secure Enclave or Keystore when available, software otherwise; `hardware`, `software`, `disabled`), `ephemeralWebSession` (a browser session that shares no cookies), `metadataCacheTtl` (seconds, default 300), `storageNamespace` (the Keychain service on iOS, the Keystore store namespace on Android) and `keychainAccessGroup` (iOS, to share credentials with app extensions). `allowRpIdMismatch` is for development tunnels only.

## Sign in with the default screens

```tsx
import { NativeLoginScreen, type NativeLoginFlow } from '@p2-inc/keycloak-native-react-native';

function Login({ onSignedIn }: { onSignedIn(): void }) {
  const [flow, setFlow] = useState<NativeLoginFlow>();
  useEffect(() => {
    kc.authentication.startLogin({ scope: 'openid profile' }).then(setFlow);
  }, []);
  if (!flow) return null;
  return (
    <NativeLoginScreen
      kc={kc}
      flow={flow}
      onResult={async (result) => {
        if (result.kind === 'authorized') {
          await kc.credentialsManager.store(result.credentials);
          onSignedIn();
        }
        flow.release();
      }}
    />
  );
}
```

`NativeLoginScreen` starts the flow, shows one screen per challenge with "Try another way" for the alternatives, runs the passkey and saved-password sheets and the browser fallback, and reports `authorized`, `cancelled` or `failed`. It does not store credentials or navigate. It has default screens for every challenge type of the protocol: username, password, TOTP (with an authenticator picker), email and SMS codes (send on request, resend countdown), recovery codes, passkeys, passkey registration (an offer with "Not now", or a requirement), push with number matching and polling, push enrollment, PIN entry (a slot per digit and a numeric keypad; a locked PIN explains the reset and offers only cancel) and the set-PIN required action of the optional PIN extension, and the password update, email verification and terms required actions. Unknown types get an "Update required" screen.

Props:

- `presenters={{ totp: MyTotpScreen }}` replaces one screen. A presenter receives `ChallengePresentationProps<'totp'>`: the typed `challenge`, the set (`challenges`, `alternatives`), `flowContext`, `isSubmitting`, `isStepUp`, `strings`, and the actions `submit(answer)`, `usePasskey()`, `registerPasskey(label)`, `enrollPush(deviceLabel)`, `useSavedPassword()`, `switchTo(other)` and `cancel()`. The building blocks (`ChallengeFrame`, `PrimaryButton`, `SecondaryButton`, `useNow`, `chooserTitle`) are exported.
- `chooser` replaces the "Try another way" list; `header` is shown above every screen (a logo); `strings` replaces some or all strings. The module ships English and German and picks them from the device locale; pass a whole `NativeLoginStrings` object for another language.
- `autoSelectPasskey` runs the passkey prompt as soon as a set contains `passkey`.
- `offerSavedPasswords` (default `true`) shows "Use a saved password" on the username and password screens. `offerToSavePassword` (default `true`) offers the typed password to Credential Manager after an authorized login on Android; iOS AutoFill offers to save from the screen's fields by itself.
- `pushRegistration` returns where push messages reach this device for a `push_enrollment` challenge, for example `async () => ({ type: 'fcm', id: await messaging().getToken() })`. Without it the device enrolls with `none` and reads its approvals itself.

`LoginController` is the state machine behind the screen, for apps that build their own container.

## Drive the flow yourself

```ts
const flow = await kc.authentication.startLogin({ scope: 'openid profile' });
let step = await flow.start();
while (step.kind === 'challenges') {
  const challenge = step.supportedChallenges[0];
  switch (challenge.type) {
    case 'passkey':
      step = await flow.usePasskey(challenge);
      break;
    case 'totp':
      step = await flow.respond({ kind: 'totp', code: await askForCode(challenge.params.digits) }, challenge);
      break;
    // …
  }
}
const credentials = step.kind === 'authorized' ? step.credentials : await kc.webFallback.complete(step.request, flow);
await kc.credentialsManager.store(credentials);
flow.release();
```

`Challenge` narrows on `type`, so `challenge.params` is typed per type; `wireType`, `label`, `required`, `error`, `retry`, `skippable`, `supported`, `requiredAction` and the raw descriptor are on every challenge. Instants are epoch milliseconds (`millisUntil(params.resendAllowedAt)` for countdowns). Answers are `{ kind, … }` objects named like the native `ChallengeAnswer` cases; `{ kind: 'skip' }` declines a skippable required action and `{ kind: 'custom', fields }` answers an extension type. With the optional PIN extension (spec/20), a `pin` challenge (`params.length`) is answered with `{ kind: 'pin', pin }`: `invalid_credential` carries `retry.remaining`, and `credential_locked` (`isChallengeLocked(challenge)`) means the PIN must be reset on the web or by an administrator, so offer cancel or another alternative, not a retry. A `pin_setup` challenge (`params.length`; `isWellFormedPin(params, pin)` pre-checks the shape) is answered with `{ kind: 'pinSetup', pin, confirm }` and may come back with `pin_mismatch`, `invalid_format` or `weak_pin`. Passkey assertion and registration and push enrollment run natively in one call (`flow.usePasskey`, `flow.registerPasskey`, `flow.enrollPush`), so WebAuthn material and device JWTs never pass through JavaScript.

A descriptor `error` on a new set is inline feedback (a wrong password), not a thrown error. Thrown errors are `NativeAuthError` with the SDKs' codes; branch on `code`, never on the message. `passkey_cancelled`, `saved_password_cancelled` and `web_fallback_cancelled` mean the user closed a sheet: the challenge set is still pending. `invalid_session`, `access_denied` and `invalid_client` end the flow.

Step-up: `kc.authentication.stepUp({ acrValues, maxAge })` starts a flow inside the stored session; it reads the post-login session natively and fails with `credentials_not_found` when there is none.

## Tokens and DPoP

Only the access token and the ID token reach JavaScript. The refresh token (and the post-login session a step-up uses) stays in the iOS Keychain or the Android Keystore-backed store, and the SDK refreshes on the native side; `Credentials` carries `hasRefreshToken` instead of the token. There is deliberately no API to export it, because the JavaScript side of a React Native app is the wrong place for a long-lived credential:

- every npm package in the app, including transitive dependencies, runs in the same JavaScript context and can read whatever JavaScript holds;
- the usual persistence, AsyncStorage, is plain text on the device;
- logging, crash reporting and developer tools (Flipper, React DevTools, network inspectors) capture values that pass through JavaScript;
- over-the-air updates can replace the JavaScript of a reviewed app;
- a refresh token lives for the whole session (or longer, for offline tokens), while an access token expires in minutes.

If a web view or a backend needs a session, let your server exchange tokens; do not move the refresh token through JavaScript.

Turn on DPoP as well. With Keycloak's `dpop` feature enabled and the client set to require DPoP-bound tokens, the SDK binds every token to its key in the Secure Enclave or Android Keystore, which cannot be exported, so an access token copied out of JavaScript is useless without a proof from the device. The module defaults to `dpop: 'automatic'`. The cost is on the resource-server side: your APIs must accept `Authorization: DPoP <token>` and validate the `DPoP` proof (the token's `cnf.jkt`, the request method and URL, the proof's age and `jti`), not only `Bearer`. On the client the module does its part:

- `kc.resourceRequestHeaders(method, url)` returns `Authorization`, and a `DPoP` proof for exactly that method and URL when the tokens are DPoP-bound. Send the request with the same method and URL; build new headers for every request.
- `kc.credentialsManager.credentials(minTtlSeconds)` returns the stored credentials, refreshed natively when the access token is within 30 seconds plus `minTtlSeconds` of expiry; `credentials_not_found` when nothing is stored, `reauthentication_required` when the refresh was refused.
- `stored()`, `hasValid(minTtlSeconds)`, `logout()` (server logout, then local clear) and `clear()`.
- `kc.dpopKeyThumbprint()` returns the key's `jkt`, the value resource servers compare with the token's `cnf.jkt`.

## Passkeys and saved passwords outside a flow

`kc.registerNewPasskey(label)` registers a passkey for the signed-in user through the authenticated registration endpoints; an old login is refused until a step-up with `maxAge`. `kc.pickSavedPassword()` shows the system sheet and returns `{ username, password }`; `kc.savePassword(username, password)` offers a login to Credential Manager on Android and does nothing on iOS.

## Push

The device side of push MFA is `kc.push`. The device key is the DPoP key and the device API is called with the stored DPoP-bound login, so sign in with DPoP first. Keep your notification library: pass its token to the module and forward its messages.

```ts
// Enroll from inside the app (or let a push_enrollment challenge do it, with pushRegistration).
await kc.push.enroll('Pixel 9', { type: 'fcm', id: await messaging().getToken() });

// Token changes.
messaging().onTokenRefresh((id) => kc.push.updateProvider({ type: 'fcm', id }));

// Messages: decode, then show the approval.
messaging().onMessage(async (message) => {
  const payload = await kc.push.handleMessage(message.data ?? {});
  if (payload) navigation.navigate('Approvals', { focus: payload.cid });
});
```

On iOS pass the APNs device token as hex with `type: 'apns'`, and forward the notification's custom keys to `handleMessage`. `<PushApprovalsScreen kc={kc} focus={cid} onResponded={…} />` lists the pending approvals with Approve / Deny, the number-match buttons or a PIN field; show it when a notification is tapped and when the app opens, because a backgrounded app may not see the message data until the user taps it. `kc.push.pendingApprovals()` and `kc.push.respond(approval, { kind: 'approve', userVerification })` are the building blocks; a wrong number is `user_verification_mismatch` (one more try), an approval resolved meanwhile `push_conflict`. `rotateKey()` registers a fresh device key and clears the stored credentials; `lockout()` is the panic button, which disables the account on the server.

## Example and tests

The [example app](../react-native/keycloak-native-react-native/example/) runs against the compose stack in `keycloak-native-auth/demo` (the Android emulator reaches the host at `10.0.2.2`): sign in on `demo-native`, `demo-native-passkey`, `demo-native-otp` or `demo-native-pin`, step up, create a passkey, enroll for push and answer sign-in requests. Inside this repository it builds the native SDKs from source: Android through a Gradle composite build of `../../android`, iOS through the Swift package at the repository root.

```sh
cd react-native/keycloak-native-react-native
yarn                 # the module and the example (Yarn 4 workspaces)
yarn typecheck && yarn lint && yarn test
yarn example android # or: cd example/android && ./gradlew :app:assembleDebug
yarn example ios     # or: cd example/ios && pod install, then xcodebuild
```

The Jest suite replays the server's recorded transcripts (`keycloak-native-auth/demo/transcripts`) through a mock native module, as the Swift and Kotlin suites do, and fails when the server adds or renames a challenge field the model does not read.
