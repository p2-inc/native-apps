# keycloak_native

Native authentication for Keycloak in Flutter apps: your own screens instead of a browser or webview. The plugin wraps the [iOS and Android SDKs](../../README.md) of this repository, which run the challenge protocol, keep tokens in the Keychain or the Android Keystore, hold the DPoP key in secure hardware and open the system browser when a login must finish on the web. Dart gets the challenge flow as typed classes and default Flutter widgets you can replace per challenge type. Design and roadmap: [spec/18](../../spec/18-flutter-plugin-plan.md).

**Status:** first slice (0.3.0-dev, not on pub.dev). Username, password and TOTP have default screens; other challenge types can be answered from Dart or through your own `presenters`; passkeys and push come in later phases.

## Requirements

- iOS 17, Flutter's Swift Package Manager integration (the default; there is no podspec).
- Android `minSdk 28`, `compileSdk 37`, and a `MainActivity` that extends `FlutterFragmentActivity` (the browser fallback registers an activity result launcher). Declare `NativeAuthRedirectActivity` for your `redirect_uri`, as in the [example's manifest](example/android/app/src/main/AndroidManifest.xml) and [the Android guide](../../docs/android-integration.md#browser-fallback-callback).
- A Keycloak realm with the native authentication extensions and a public client (see [the docs](../../docs/README.md)).

## Usage

```dart
import 'package:keycloak_native/keycloak_native.dart';

// Once per issuer and client, for the life of the app.
final kc = await KeycloakNative.configure(
  issuer: Uri.parse('https://idp.example.com/realms/demo'),
  clientId: 'demo-native',
);

// Default widgets: pass an unstarted flow; store the credentials yourself.
final flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile'));
NativeLoginView(
  kc: kc,
  flow: flow,
  onResult: (result) async {
    if (result is NativeLoginAuthorized) await kc.credentialsManager.store(result.credentials);
    await flow.dispose();
  },
  presenters: {ChallengeType.otp: (context, p) => MyOtpScreen(p)},
);

// Or drive the flow with your own screens.
var step = await flow.start();
while (step is ChallengesStep) {
  final challenge = step.challenges.first;
  step = await flow.respond(switch (challenge) {
    UsernameChallenge() => ChallengeAnswer.username(await askUsername()),
    PasswordChallenge() => ChallengeAnswer.password(await askPassword()),
    TotpChallenge(:final digits) => ChallengeAnswer.totp(await askCode(digits)),
    _ => throw UnsupportedError('${challenge.type}'),
  }, challenge);
}
final credentials = switch (step) {
  AuthorizedStep(:final credentials) => credentials,
  RedirectToWebStep() => await kc.webFallback.complete(flow),
  ChallengesStep() => throw StateError('unreachable'),
};
await kc.credentialsManager.store(credentials);

// Later: valid (refreshed) credentials, headers for an API call, logout.
final current = await kc.credentialsManager.credentials();
final headers = await kc.credentialsManager.resourceRequestHeaders('GET', Uri.parse('https://api.example.com/me'));
await kc.credentialsManager.logout();
```

Errors are `NativeAuthException` with the SDKs' codes (`NativeAuthErrorCode`). The refresh token never reaches Dart; `Credentials.hasRefreshToken` says whether there is one.

## Development

```sh
flutter analyze
flutter test                     # model, transcript replay, widgets
cd example && flutter build apk --debug
cd example && flutter build ios --simulator --no-codesign
dart run pigeon --input pigeons/messages.dart   # after changing the channel
```

The replay tests read the server's recorded transcripts from `../../keycloak-native-auth/demo/transcripts` (`KEYCLOAK_NATIVE_TRANSCRIPTS` overrides).

## License

Apache License 2.0 ([LICENSE](LICENSE)), like the native SDKs.
