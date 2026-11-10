# React Native module for native authentication with Keycloak

`@phasetwo/keycloak-native-react-native` signs users in to Keycloak with your app's own React Native screens instead of a browser. It wraps the [iOS SDK](../../ios/KeycloakNative) and the [Android SDK](../../android): the native side runs the challenge protocol, keeps credentials in the Keychain or Android Keystore, holds the DPoP key in the Secure Enclave or Keystore and runs the passkey, saved-password, browser and push ceremonies; JavaScript gets the challenge loop as a typed model and default React screens for every challenge type, each replaceable on its own. An Expo config plugin does the native setup.

**Status:** below 1.0 and not yet on npm.

- Integration guide: [docs/react-native-integration.md](../../docs/react-native-integration.md)
- Design and plan: [spec/19](../../spec/19-react-native-plan.md)
- Example app: [example/](example/)

```tsx
import { KeycloakNative, NativeLoginScreen } from '@phasetwo/keycloak-native-react-native';

const kc = KeycloakNative.configure({ issuer: 'https://idp.example.com/realms/demo', clientId: 'demo-native' });

// flow = await kc.authentication.startLogin({ scope: 'openid profile' })
<NativeLoginScreen
  kc={kc}
  flow={flow}
  onResult={async (result) => {
    if (result.kind === 'authorized') await kc.credentialsManager.store(result.credentials);
    flow.release();
  }}
/>;
```

Requirements: React Native 0.88 or later with the New Architecture; iOS 17; Android minSdk 28, compileSdk 37 and Kotlin 2.2 or later.

## Development

```sh
yarn                 # installs the module and the example app (Yarn 4 workspaces)
yarn typecheck
yarn lint
yarn test            # Jest, including the replay of ../../keycloak-native-auth/demo/transcripts
yarn example android # or: cd example/android && ./gradlew :app:assembleDebug
yarn example ios     # pod install runs on the first build
```

Inside this repository the example app builds the native SDKs from source: Android through a Gradle composite build of `../../android` (see `example/android/settings.gradle` for the version pins this needs), iOS through the Swift package at the repository root. Run the compose stack from `keycloak-native-auth/demo` and sign in as `bob` / `bob-password` (password only) or `alice` / `alice-password` with the TOTP of the seeded secret ([keycloak-native-auth/README.md](../../keycloak-native-auth/README.md); `scripts/walkthrough.sh` prints the current code).

## License

Apache License 2.0 ([LICENSE](LICENSE)), like the iOS and Android SDKs. Copyright 2026 Phase Two, Inc.
