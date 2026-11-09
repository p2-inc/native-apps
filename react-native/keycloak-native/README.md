# React Native module for native authentication with Keycloak

`@phasetwo/react-native-keycloak-native` signs users in to Keycloak with your app's own React Native screens instead of a browser. It wraps the [iOS SDK](../../ios/KeycloakNative) and the [Android SDK](../../android): the native side runs the challenge protocol, keeps credentials in the Keychain or Android Keystore, holds the DPoP key in the Secure Enclave or Keystore and runs the platform ceremonies; JavaScript gets the challenge loop as a typed model and default React screens that can be replaced one challenge type at a time. The design and the plan are in [spec/19](../../spec/19-react-native-plan.md).

**Status:** first slice, below 1.0 and not yet on npm. Username, password and TOTP challenges, the browser fallback, tokens, refresh and logout work; the other challenge types can be answered from custom screens (see the table in spec/19 §6), and passkeys, push and the remaining default screens come next.

## Requirements

React Native 0.88 with the New Architecture. iOS 17 or later. Android minSdk 28 and compileSdk 37, and Kotlin 2.3 or later in the app's build (the Android SDK is compiled with Kotlin 2.4). Expo works in development builds, not in Expo Go; a config plugin is planned.

## Setup

Configure a public Keycloak client with the [server setup](../../docs/README.md#practical-quick-start): PKCE S256 required, and a callback such as `demoapp://auth/callback` for the browser fallback.

**iOS:** `pod install`. The pod brings in the Swift package `KeycloakNativeCore` through React Native's `spm_dependency`. For passkeys, add the Associated Domains entitlement `webcredentials:<rp_id>`.

**Android:** register the browser fallback in `MainActivity` (it needs an activity result launcher, which Android only allows before the activity starts), and declare the callback activity for your `redirect_uri`:

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

## Usage

One instance per issuer and client, for the life of the app:

```tsx
import { KeycloakNative, NativeLoginScreen } from '@phasetwo/react-native-keycloak-native';

const kc = KeycloakNative.configure({ issuer: 'https://idp.example.com/realms/demo', clientId: 'demo-native' });

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
        flow.release();
        if (result.kind === 'authorized') {
          await kc.credentialsManager.store(result.credentials);
          onSignedIn();
        }
      }}
    />
  );
}
```

`NativeLoginScreen` starts the flow, shows one screen per challenge with "Try another way" for the alternatives, runs the browser fallback, and reports `authorized`, `cancelled` or `failed`. It does not store credentials or navigate. Replace a screen with `presenters={{ totp: MyTotpScreen }}`; the component receives `ChallengePresentationProps<'totp'>` with the typed `challenge`, the set, the flow context and `submit(answer)`, `switchTo(other)` and `cancel()`. Replace the alternatives list with `chooser`, the strings with `strings`.

To drive the flow yourself:

```ts
const flow = await kc.authentication.startLogin({ scope: 'openid profile' });
let step = await flow.start();
// step.kind: 'challenges' | 'authorized' | 'redirectToWeb'
if (step.kind === 'challenges') {
  const challenge = step.supportedChallenges[0];
  if (challenge.type === 'totp') {
    step = await flow.respond({ kind: 'totp', code }, challenge); // the answer first, then the challenge
  }
}
```

A descriptor `error` on a new set is inline feedback (a wrong password), not a thrown error. Thrown errors are `NativeAuthError` with the SDKs' codes (`invalid_session`, `access_denied`, `network_error`, `web_fallback_cancelled`, …); branch on `code`.

Tokens: `kc.credentialsManager.credentials(minTtlSeconds)` returns stored credentials, refreshed natively when needed; `kc.resourceRequestHeaders(method, url)` returns `Authorization` (and a `DPoP` proof for exactly that request when the tokens are DPoP-bound); `kc.credentialsManager.logout()` logs out on the server and clears local credentials. The refresh token and the post-login session never leave the native side.

## Development

```sh
yarn                 # installs the module and the example app (Yarn 4 workspaces)
yarn typecheck
yarn lint
yarn test            # Jest, including the replay of ../../keycloak-native-auth/demo/transcripts
yarn example android # or: cd example/android && ./gradlew :app:assembleDebug
yarn example ios     # pod install runs on the first build
```

Inside this repository the example app builds the native SDKs from source: Android through a Gradle composite build of `../../android` (see `example/android/settings.gradle` for the version pins this needs), iOS through the Swift package at the repository root. Run the compose stack from `keycloak-native-auth/demo` and sign in as `bob` / `bob-password` (password only) or `alice` / `alice-password` with the TOTP of the seeded secret ([keycloak-native-auth/README.md](../../keycloak-native-auth/README.md), `scripts/walkthrough.sh` prints the current code).

## License

Apache License 2.0 ([LICENSE](LICENSE)), like the iOS and Android SDKs. Copyright 2026 Phase Two, Inc.
