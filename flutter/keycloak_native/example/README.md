# keycloak_native example

Signs in to the demo realm of [`keycloak-native-auth/demo`](../../../keycloak-native-auth/demo) with `NativeLoginView`, then shows the token's subject, refreshes and logs out.

Start the stack (`docker compose up` in `keycloak-native-auth/demo`), then `flutter run` here. The Android emulator reaches the host as `10.0.2.2`, the iOS simulator as `localhost`; override with `--dart-define=ISSUER=https://…/realms/demo` and `--dart-define=CLIENT_ID=…`. Users: alice (password, then TOTP), bob (password only); see [the sample app guide](../../../docs/sample-app.md).

The Android build includes the Android SDK from `../../../android` (a Gradle composite build) and the iOS build the Swift package at the repository root, so SDK changes are picked up directly.
