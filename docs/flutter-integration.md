# Integrating the Flutter plugin

[Index](README.md) · [Protocol](protocol-and-flows.md) · [iOS integration](ios-integration.md) · [Android integration](android-integration.md) · [Plan (spec/18)](../spec/18-flutter-plugin-plan.md)

`keycloak_native_flutter` (in [`flutter/keycloak_native_flutter/`](../flutter/keycloak_native_flutter/)) signs users in to Keycloak with your app's Flutter screens instead of a browser. It is a plugin over the iOS and Android SDKs, connected through Pigeon platform channels: the native side runs the challenge protocol, keeps credentials in the Keychain or Android Keystore, holds the DPoP key in the Secure Enclave or Keystore and runs the passkey, saved-password, browser and push ceremonies; Dart gets the challenge loop as sealed classes and default Flutter widgets that can be replaced one challenge type at a time. The plugin is below 1.0 and published on pub.dev by the phasetwo.io verified publisher.

## Requirements

- Flutter 3.35 or later.
- iOS 17 or later, with Flutter's Swift Package Manager integration (the default; the plugin has no podspec). The plugin brings in the Swift package products `KeycloakNativeCore` and `KeycloakNativePush`.
- Android minSdk 28, compileSdk 37 and Kotlin 2.2 or later (see the Android guide's [Kotlin version](android-integration.md#kotlin-version)). The SDK comes from Maven Central. Flutter's current app template already uses a newer Kotlin; apps created from older templates may have to raise `org.jetbrains.kotlin.android` in `android/settings.gradle.kts`.
- A public Keycloak client configured with the [server setup](README.md#practical-quick-start): PKCE S256 required, and a callback such as `demoapp://auth/callback` for the browser fallback.

## Setup

```yaml
# pubspec.yaml
dependencies:
  keycloak_native_flutter: ^0.3.0
```

**iOS.** Raise the deployment target to 17.0 (`IPHONEOS_DEPLOYMENT_TARGET` in the Runner project). For passkeys and the saved-password sheet, add the Associated Domains entitlement `webcredentials:<rp_id>` and serve the AASA file, as for the [Swift SDK](ios-integration.md). The browser fallback needs no URL scheme registration. For plain HTTP to a local Keycloak during development, add `NSAllowsLocalNetworking` to `NSAppTransportSecurity` in `Info.plist`.

**Android.** Raise `minSdk` to 28 and `compileSdk` to at least 36 in `android/app/build.gradle.kts`. The browser fallback registers an activity result launcher, which Android only allows while the activity is being created, and needs a `ComponentActivity` for it; make `MainActivity` a `FlutterFragmentActivity`:

```kotlin
import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity : FlutterFragmentActivity()
```

and declare the SDK's callback activity for your `redirect_uri` (used when the browser has no Auth Tab):

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

With a plain `FlutterActivity` the browser fallback fails with `web_fallback_failed` and a message naming the fix. Passkeys need `assetlinks.json` for the RP ID and the app's `android:apk-key-hash:` origin in the realm's Passwordless policy, as for the [Android SDK](android-integration.md).

## Configure

Keep one instance per issuer and client for the life of the app, so credentials, the DPoP key, the metadata cache and refreshes stay consistent:

```dart
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';

final kc = await KeycloakNative.configure(
  issuer: Uri.parse('https://idp.example.com/realms/demo'), // including /realms/<realm>
  clientId: 'demo-native',
);
```

`KeycloakNativeOptions`: `dpop` (`DPoPMode.automatic` by default: Secure Enclave or Keystore when available, software otherwise; `hardware`, `software`, `disabled`), `ephemeralWebSession` (a browser session that shares no cookies), `metadataCacheTtl` (default 5 minutes), `storageNamespace` (the Android Keystore store namespace, default the client ID) and `observeFlow` (publish the SDK's redacted requests and responses on `kc.flowLog`, for a diagnostics screen). `allowRpIdMismatch` is for development tunnels only.

## Sign in with the default screens

```dart
class Login extends StatefulWidget {
  const Login({super.key, required this.onSignedIn});
  final VoidCallback onSignedIn;

  @override
  State<Login> createState() => _LoginState();
}

class _LoginState extends State<Login> {
  NativeLoginFlow? _flow;

  @override
  void initState() {
    super.initState();
    kc.authentication.startLogin(const LoginParameters(scope: 'openid profile')).then((flow) => setState(() => _flow = flow));
  }

  @override
  Widget build(BuildContext context) {
    final flow = _flow;
    if (flow == null) return const SizedBox.shrink();
    return NativeLoginView(
      kc: kc,
      flow: flow,
      onResult: (result) async {
        if (result is NativeLoginAuthorized) {
          await kc.credentialsManager.store(result.credentials);
          widget.onSignedIn();
        }
        await flow.dispose();
      },
    );
  }
}
```

`NativeLoginView` starts the flow, shows one screen per challenge with "Try another way" for the alternatives, runs the passkey and saved-password sheets and the browser fallback, and reports `NativeLoginAuthorized`, `NativeLoginCancelled` or `NativeLoginFailed`. It does not store credentials or navigate. It has default screens for every challenge type of the protocol: username, password, TOTP (with an authenticator picker), email and SMS codes (send on request, resend countdown), recovery codes, passkeys, passkey registration (an offer with "Not now", or a requirement), push with number matching and polling, push enrollment, PIN entry (a slot per digit and a numeric keypad; a locked PIN explains the reset and offers only cancel) and the set-PIN required action of the optional PIN extension, and the password update (with the realm's policy as hints), email verification and terms required actions. Unknown types get an "Update required" screen.

Parameters:

- `presenters: {ChallengeType.totp: (context, p) => MyTotpScreen(p)}` replaces one screen. A presenter receives a `ChallengePresentation`: the typed `challenge`, `alternatives`, `flowContext`, `isSubmitting`, `isStepUp`, `strings`, `message`, and the actions `submit(answer)`, `usePasskey()`, `registerPasskey(label:)`, `enrollPush(deviceLabel)`, `useSavedPassword()`, `switchTo(other)` and `cancel()`. The default screens and their building blocks (`ChallengeFrame`, `Countdown`, `SavedPasswordButton`) are exported.
- `chooser` replaces the "Try another way" list; `header` is shown above every screen (a logo); `strings` replaces the texts. The plugin ships English and German (`NativeLoginStrings`, `NativeLoginStringsDe`) and picks them from the app's locale; subclass `NativeLoginStrings` to reword or add a language.
- `autoSelectPasskey` runs the passkey prompt as soon as a set contains `passkey`.
- `offerSavedPasswords` (default `true`) shows "Use a saved password" on the username and password screens. `offerToSavePassword` (default `true`) offers the typed password to Credential Manager after an authorized login on Android; iOS AutoFill offers to save from the screen's fields by itself.
- `pushRegistration` returns where push messages reach this device for a `push_enrollment` challenge, for example `() async => PushProviderRegistration('fcm', await FirebaseMessaging.instance.getToken())`. Without it the device enrolls with `none` and reads its approvals itself.

`NativeLoginController` is the state machine behind the view (a `ChangeNotifier`), for apps that build their own container.

## Drive the flow yourself

```dart
final flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile'));
var step = await flow.start();
while (step is ChallengesStep) {
  final challenge = step.supportedChallenges.first;
  step = await switch (challenge) {
    PasskeyChallenge() => flow.usePasskey(challenge),
    UsernameChallenge() => flow.respond(ChallengeAnswer.username(await askForUsername()), challenge),
    PasswordChallenge() => flow.respond(ChallengeAnswer.password(await askForPassword()), challenge),
    TotpChallenge(:final digits) => flow.respond(ChallengeAnswer.totp(await askForCode(digits)), challenge),
    _ => throw UnsupportedError('${challenge.type}'), // …
  };
}
final credentials = switch (step) {
  AuthorizedStep(:final credentials) => credentials,
  RedirectToWebStep() => await kc.webFallback.complete(flow),
  ChallengesStep() => throw StateError('unreachable'),
};
await kc.credentialsManager.store(credentials);
await flow.dispose();
```

`Challenge` is a sealed class with one subclass per type (`UsernameChallenge`, `TotpChallenge`, `OtpChallenge`, `PushChallenge`, …) carrying typed getters for its params; `id`, `type`, `label`, `required`, `error`, `retryRemaining`, `isSkippable` and the raw `params` are on every challenge. Answers are `ChallengeAnswer` factory constructors named like the native cases; `ChallengeAnswer.skip(type)` declines a skippable required action and `ChallengeAnswer.custom(type, fields)` answers an extension type. With the optional PIN extension (spec/20), `PinChallenge` (`length`) is answered with `ChallengeAnswer.pin(input)`: `invalid_credential` carries `retryRemaining`, and `credential_locked` (`challenge.isLocked`) means the PIN must be reset on the web or by an administrator, so offer cancel or another alternative, not a retry. `PinSetupChallenge` (`length`, `isWellFormed(pin)`) is answered with `ChallengeAnswer.pinSetup(input, confirm: confirmation)` and may come back with `pin_mismatch`, `invalid_format` or `weak_pin`. Passkey assertion and registration and push enrollment run natively in one call (`flow.usePasskey`, `flow.registerPasskey`, `flow.enrollPush`), so WebAuthn material and device JWTs never pass through Dart.

A descriptor `error` on a new set is inline feedback (a wrong password), not a thrown error. Thrown errors are `NativeAuthException` with the SDKs' codes (`NativeAuthErrorCode`); branch on `code`, never on the message. `passkey_cancelled`, `saved_password_cancelled` and `web_fallback_cancelled` mean the user closed a sheet: the challenge set is still pending. `invalid_session`, `access_denied` and `invalid_client` end the flow. Serialize `respond` calls: a second one while the first is in flight answers a set that is about to be replaced.

Step-up: `kc.authentication.stepUp(LoginParameters(acrValues: '2'))` starts a flow inside the stored session; it reads the post-login session natively and fails with `credentials_not_found` when there is none. When a call fails with `reauthentication_required` or `insufficient_authorization`, `kc.authentication.continueAfterTokenChallenge()` returns the step-up flow for the session the server named.

## Tokens and DPoP

- `kc.credentialsManager.credentials(minTtl: …)` returns the stored credentials, refreshed natively when the access token is within 30 seconds plus `minTtl` of expiry; `credentials_not_found` when nothing is stored, `reauthentication_required` when the refresh was refused.
- `kc.credentialsManager.resourceRequestHeaders(method, url)` returns `Authorization`, and a `DPoP` proof for exactly that method and URL when the tokens are DPoP-bound. Send the request with the same method and URL.
- `stored()`, `hasValid(minTtl: …)`, `logout()` (server logout, then local clear) and `clear()`.

Only the access token and the ID token reach Dart. The refresh token and the post-login session stay in the Keychain or Keystore, and there is no API to export them: `Credentials.hasRefreshToken` says whether there is one, and the SDK uses it itself when `credentials()` refreshes. The reasons:

- **Everything in the isolate can read Dart memory.** Third-party packages run in the same isolate as your code; a refresh token in a Dart object is available to all of them.
- **Dart storage is easy to get wrong.** The common persistence packages (`shared_preferences`, files, many caches) store plain text, outside the hardware-backed store.
- **Logs and crash reports.** Objects end up in `print`, error reporters and analytics payloads; `Credentials.toString()` never prints a token, but a refresh token passed around as a `String` has no such protection.
- **Refresh tokens live long.** An access token expires in minutes; a refresh token (an offline token even more so) can mint new ones for days or months, so leaking it is far worse.

To limit what a leaked access token is worth too, enable DPoP in Keycloak, so tokens are bound to the device key, which is non-exportable on devices with a Secure Enclave or Keystore. The SDK sends DPoP proofs by default (`DPoPMode.automatic`); with Keycloak's DPoP feature enabled (it is a server feature; check that it is on for your version) the tokens it receives are DPoP-bound, and the client setting that requires DPoP-bound tokens makes binding mandatory. The caveat: every resource server that receives these tokens must then accept `Authorization: DPoP <token>` and validate the `DPoP` proof (signature, `htm`, `htu`, `iat`, `jti` replay, `ath` and the token's `cnf.jkt`); a resource server that only understands `Bearer` rejects them. The client side is covered by `resourceRequestHeaders`, for example in a `package:http` client:

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

See [security](security.md) for how the server binds sessions and codes to the proof key.

## Passkeys and saved passwords outside a flow

`kc.passkeys.registerNewPasskey(label: …)` registers a passkey for the signed-in user through the authenticated registration endpoints; an old login is refused with `insufficient_authorization` until a step-up (`continueAfterTokenChallenge`). `kc.pickSavedPassword()` shows the system sheet and returns a `SavedPassword`; `kc.savePassword(username, password)` offers a login to Credential Manager on Android and does nothing on iOS.

## Push

The device side of push MFA is `kc.push`. The device key is the DPoP key and the device API is called with the stored DPoP-bound login, so sign in with DPoP first. The plugin does not register with APNs or FCM: keep your messaging plugin, pass its token to the SDK and forward its messages.

```dart
// Enroll from inside the app (or let a push_enrollment challenge do it, with pushRegistration).
await kc.push.enroll('Pixel 9', registration: PushProviderRegistration('fcm', await FirebaseMessaging.instance.getToken()));

// Token changes.
FirebaseMessaging.instance.onTokenRefresh.listen((token) => kc.push.updatePushProvider(PushProviderRegistration('fcm', token)));

// Messages: decode, then show the approval.
FirebaseMessaging.onMessage.listen((message) async {
  final notification = await kc.push.handleMessage(message.data.map((k, v) => MapEntry(k, '$v')));
  if (notification != null) navigator.push(MaterialPageRoute(builder: (_) => PushApprovalsView(push: kc.push, focus: notification.cid)));
});
```

On iOS pass the APNs device token as hex with type `apns`, and forward the notification's custom keys to `handleMessage`. `PushApprovalsView(push: kc.push, focus: cid, onResponded: …)` lists the pending approvals with Approve / Deny, the number-match buttons or a PIN field; show it when a notification is tapped and when the app opens, because a backgrounded app may not see the message data until the user taps it. `kc.push.pendingApprovals()` and `kc.push.respond(approval, PushApprovalAction.approve(number))` are the building blocks; a wrong number is `user_verification_mismatch` (one more try), an approval resolved meanwhile `push_conflict`. `rotateKey()` registers a fresh device key and clears the stored credentials; `lockout()` is the panic button, which disables the account on the server; `forgetEnrollment()` deletes only the local enrollment.

## Example and tests

The [example app](../flutter/keycloak_native_flutter/example/) runs against the compose stack in `keycloak-native-auth/demo` (the Android emulator reaches the host at `10.0.2.2`, the iOS simulator at `localhost`): sign in on `demo-native`, `demo-native-passkey`, `demo-native-otp`, `demo-native-stepup` or `demo-native-pin`, step up, create a passkey, enroll for push and answer sign-in requests, and read the flow log. Inside this repository it builds the native SDKs from source: Android through a Gradle composite build of `../../../../android`, iOS through the Swift package at the repository root.

```sh
cd flutter/keycloak_native_flutter
flutter analyze && flutter test
cd example
flutter build apk --debug
flutter build ios --simulator --debug --no-codesign
flutter test integration_test -d <device>   # live, against docker compose up in keycloak-native-auth/demo
```

The Dart tests replay the server's recorded transcripts (`keycloak-native-auth/demo/transcripts`) through a fake of the platform channel, as the Swift and Kotlin suites do, and fail when the server adds or renames a challenge field or a request field changes; widget tests drive every default screen through the transcript that exercises it. The integration test signs alice in with username, password and TOTP and bob with an email code read from mailpit, through the real plugin and SDKs.
