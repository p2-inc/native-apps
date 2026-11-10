# keycloak_native_flutter example

Signs in to the demo realm of [`keycloak-native-auth/demo`](../../../keycloak-native-auth/demo) with `NativeLoginView` on any of its four native clients, then shows the claims and offers refresh, step-up, passkey registration, push enrollment with the approvals list, the flow log and logout.

Start the stack (`docker compose up` in `keycloak-native-auth/demo`), then `flutter run` here. The Android emulator reaches the host as `10.0.2.2`, the iOS simulator as `localhost`; override with `--dart-define=ISSUER=https://…/realms/demo` and `--dart-define=CLIENT_ID=…`. Users: alice (`alice-password`, then TOTP), bob (`bob-password`); see [the sample app guide](../../../docs/sample-app.md). Push enrolls without delivery (`none`); passkeys need an HTTPS RP ID associated with the app.

`flutter test integration_test -d <device>` runs the live suite against the stack: alice with TOTP (computed from the realm's seeded secret), in-app push enrollment and the approvals list, and bob with an email code read from mailpit.

The Android build includes the Android SDK from `../../../android` (a Gradle composite build) and the iOS build the Swift package at the repository root, so SDK changes are picked up directly.
