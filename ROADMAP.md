# Roadmap

Where the project stands and what comes next. The design record behind it, including every decision and why it was taken, is in [`spec/`](spec/00-README.md); the detailed task list is [spec/10](spec/10-status-and-task-list.md). The project is below 1.0: any release may still change the protocol or the API.

## Done

- **Keycloak extensions** (Keycloak 26.4, 26.6 and 26.8): the challenge endpoint with step-up, browser fallback and DPoP binding; native username, password, TOTP, passkey (with enrollment on first login), recovery code and email/SMS one-time-code authenticators; native required actions for passkey registration, password update, email verification, terms and push enrollment; push MFA with number matching on top of ba-itsys' [`keycloak-push-mfa-extension`](https://github.com/ba-itsys/keycloak-push-mfa-extension), with an APNs sender and in-app enrollment.
- **Protocol**: [spec/03](spec/03-protocol-spec.md), with recorded request/response transcripts that every client replays in its tests.
- **iOS SDK**: `KeycloakNativeCore`, `KeycloakNativePush` and `KeycloakNativeUI` (default SwiftUI screens, replaceable per challenge), password-manager support, and the demo app with UI tests.
- **Android SDK**: `core` (the login state machine, tokens, DPoP, credentials, the push protocol; replays the same transcripts as iOS), `android` (Credential Manager passkeys and saved passwords, Keystore keys and storage, the Auth Tab browser fallback), `ui` (default Jetpack Compose screens, replaceable per challenge, with password-manager support and the push approvals list), `push` (Firebase Cloud Messaging enrollment, approvals with number matching, token sync) and the demo app.

## In progress

- **React Native module** ([spec/19](spec/19-react-native-plan.md), `react-native/keycloak-native-react-native/`): a TurboModule over both SDKs with a typed challenge model, default React screens for every challenge type, passkeys, saved passwords, push enrollment and approvals, and an Expo config plugin. Not yet on npm.

- **Real-device verification on Android**: passkeys and saved passwords behind a public hostname with `assetlinks.json`, the browser fallback, and real FCM delivery on a phone.
- **Android integration guide** in `docs/`, alongside the iOS one.

## Next

- **Real-device verification on iOS**: passkeys behind a public hostname, real APNs delivery and the notification service extension. Everything so far ran on the simulator.
- **Push on multi-tenant Keycloak**: the push senders read one APNs key and one Firebase project from server configuration, so every realm on a Keycloak instance shares them. Apps from different organizations on one instance need a sender that takes its credentials from the realm or the client.
- **Hardening for 1.0**: app attestation as client authentication (`client_attestation_required`), rate limiting at the challenge endpoint, a risk-evaluation hook, custom event types and metrics, a security review against [spec/07](spec/07-security-considerations.md), and a load test.
- **Distribution**: from 0.3.0 the Android libraries are published to Maven Central, and each release still attaches them as a zipped Maven repository.
- **Upstream to ba-itsys**: a Java 21 build, the programmatic enrollment service, the APNs sender, and a challenge issuer for non-HTML authenticators.

## Later

- Native SSO between several first-party apps (OpenID Native SSO) instead of repeating the login per app.
- Flutter wrapper.
- Account-console support for listing and removing native devices (push credentials, DPoP-bound sessions).
- Publishing the challenge profile as an Internet-Draft profile of OAuth 2.0 for First-Party Applications.
- Optional: completion-handler and Combine variants of the iOS API, and the well-known `authorization_challenge_endpoint` override.

## Not planned for native screens

New-user registration, forgotten-password recovery, TOTP enrollment, recovery-code generation and social/identity-provider login stay on Keycloak's own pages in the browser.
