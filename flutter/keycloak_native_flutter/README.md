# keycloak_native_flutter

Native authentication for Keycloak in Flutter apps: your own screens instead of a browser or webview. The plugin wraps the [iOS and Android SDKs](../../README.md) of this repository, which run the challenge protocol, keep tokens in the Keychain or the Android Keystore, hold the DPoP key in secure hardware and open the system browser when a login must finish on the web. Dart gets the challenge flow as typed classes and default Flutter widgets you can replace per challenge type. Integration guide: [docs/flutter-integration.md](../../docs/flutter-integration.md); design and status: [spec/18](../../spec/18-flutter-plugin-plan.md).

**Status:** 0.3.0-dev, not on pub.dev yet. Every challenge type and required action has a default screen (username, password, TOTP, email and SMS codes, recovery codes, passkeys, passkey registration, update password, verify email, terms, push approval, push enrollment), with saved passwords, the browser fallback, push approvals and a diagnostics flow log. Verified with the transcript replay and widget tests and live on the iOS simulator; passkeys with a real RP ID and push delivery still need a device pass.

## Requirements

- iOS 17, Flutter's Swift Package Manager integration (the default; there is no podspec).
- Android: the app's Kotlin Gradle plugin 2.2 or newer (Flutter 3.47's template uses 2.4.0).
- Flutter 3.35 or newer.
- Android `minSdk 28`, `compileSdk 37`, and a `MainActivity` that extends `FlutterFragmentActivity` (the browser fallback registers an activity result launcher). Declare `NativeAuthRedirectActivity` for your `redirect_uri`, as in the [example's manifest](example/android/app/src/main/AndroidManifest.xml) and [the Android guide](../../docs/android-integration.md#browser-fallback-callback).
- A Keycloak realm with the native authentication extensions and a public client (see [the docs](../../docs/README.md)).

## Usage

```dart
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';

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

Errors are `NativeAuthException` with the SDKs' codes (`NativeAuthErrorCode`). The refresh token never reaches Dart (there is no API to export it); `Credentials.hasRefreshToken` says whether there is one, and the SDK refreshes natively. See [Tokens and DPoP](../../docs/flutter-integration.md#tokens-and-dpop).

### Passkeys, saved passwords, step-up

Passkey challenges are answered natively, so the WebAuthn material stays on the platform: `NativeLoginView` does it for you (`autoSelectPasskey: true` opens the sheet at once); with your own screens call `flow.usePasskey(challenge)` or `flow.registerPasskey(challenge, label: …)`. After login, `kc.passkeys.registerNewPasskey(label: …)`. The RP ID must be associated with the app (Associated Domains and `assetlinks.json`, see [the docs](../../docs/README.md)). `kc.pickSavedPassword()` shows the system's saved passwords; the default screens offer it and offer to save a typed password after success. When a call fails with `reauthentication_required` or `insufficient_authorization`, `kc.authentication.continueAfterTokenChallenge()` returns the step-up flow.

### Push MFA

The plugin does not register with APNs or FCM. Get the token with your messaging plugin and hand it in:

```dart
final registration = PushProviderRegistration('fcm', await FirebaseMessaging.instance.getToken());
await kc.push.enroll('Pixel 9', registration: registration);       // after sign-in
NativeLoginView(kc: kc, flow: flow, onResult: …, pushRegistration: () async => registration); // mid-flow push_enrollment
FirebaseMessaging.instance.onTokenRefresh.listen((t) => kc.push.updatePushProvider(PushProviderRegistration('fcm', t)));
// A tapped notification: focus its request in the approvals list.
final notification = await kc.push.handleMessage(message.data.map((k, v) => MapEntry(k, '$v')));
PushApprovalsView(push: kc.push, focus: notification?.cid);
```

On iOS use `PushProviderRegistration('apns', hexDeviceToken)`. Without a token, enroll with `PushProviderRegistration.none` and show `PushApprovalsView` when the app opens.

### Calling APIs

```dart
class KeycloakClient extends http.BaseClient {
  KeycloakClient(this.kc, [http.Client? inner]) : inner = inner ?? http.Client();
  final KeycloakNative kc;
  final http.Client inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    // Bearer, or DPoP with a fresh proof when the token is bound; refreshes when needed.
    request.headers.addAll(await kc.credentialsManager.resourceRequestHeaders(request.method, request.url));
    return inner.send(request);
  }
}
```

### Texts and diagnostics

The default screens are in English and German, picked by the app's locale; pass `strings:` with a `NativeLoginStrings` subclass to reword them or add a language. `KeycloakNativeOptions(observeFlow: true)` publishes the SDK's redacted requests and responses on `kc.flowLog`.

## Development

```sh
flutter analyze
flutter test                     # model, transcript replay, every default screen, flow log
cd example && flutter build apk --debug
cd example && flutter build ios --simulator --debug --no-codesign
# Live, against `docker compose up` in keycloak-native-auth/demo:
cd example && flutter test integration_test -d <simulator or emulator>
dart run pigeon --input pigeons/messages.dart   # after changing the channel
```

The replay tests read the server's recorded transcripts from `../../keycloak-native-auth/demo/transcripts` (`KEYCLOAK_NATIVE_TRANSCRIPTS` overrides).

## License

Apache License 2.0 ([LICENSE](LICENSE)), like the native SDKs.
