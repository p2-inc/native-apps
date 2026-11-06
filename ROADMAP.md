# Roadmap

Where the project stands and what comes next. The design record behind it, including every decision and why it was taken, is in [`spec/`](spec/00-README.md); the detailed task list is [spec/10](spec/10-status-and-task-list.md). The project is below 1.0: any release may still change the protocol or the API.

## Done

- **Keycloak extensions** (Keycloak 26.4, 26.6 and 26.8): the challenge endpoint with step-up, browser fallback and DPoP binding; native username, password, TOTP, passkey (with enrollment on first login), recovery code and email/SMS one-time-code authenticators; native required actions for passkey registration, password update, email verification, terms and push enrollment; push MFA with number matching on top of ba-itsys' [`keycloak-push-mfa-extension`](https://github.com/ba-itsys/keycloak-push-mfa-extension), with an APNs sender and in-app enrollment.
- **Protocol**: [spec/03](spec/03-protocol-spec.md), with recorded request/response transcripts that every client replays in its tests.
- **iOS SDK**: `KeycloakNativeCore`, `KeycloakNativePush` and `KeycloakNativeUI` (default SwiftUI screens, replaceable per challenge), password-manager support, and the demo app with UI tests.
- **Android SDK, first three modules**: `core` (the login state machine, tokens, DPoP, credentials; replays the same transcripts as iOS), `android` (Credential Manager passkeys and saved passwords, Keystore keys and storage, the Auth Tab browser fallback) and `ui` (default Jetpack Compose screens, replaceable per challenge, with password-manager support).

## In progress

- **Android push**: FCM enrollment, approvals with number matching, token sync, and the push enrollment screen ([spec/17](spec/17-android-sdk-plan.md) step 9).
- **Android demo app** (step 10), then passkeys, saved passwords and the browser fallback checked on an emulator with a Google account and on a phone.
- **Android integration guide** in `docs/`, alongside the iOS one.

## Next

- **Real-device verification on iOS**: passkeys behind a public hostname, real APNs delivery and the notification service extension. Everything so far ran on the simulator.
- **Push on multi-tenant Keycloak**: the push senders read one APNs key and one Firebase project from server configuration, so every realm on a Keycloak instance shares them. Apps from different organizations on one instance need a sender that takes its credentials from the realm or the client.
- **Hardening for 1.0**: app attestation as client authentication (`client_attestation_required`), rate limiting at the challenge endpoint, a risk-evaluation hook, custom event types and metrics, a security review against [spec/07](spec/07-security-considerations.md), and a load test.
- **Distribution**: the Android libraries are attached to each release as a zip of a Maven repository; a public Maven repository comes with 1.0.
- **Upstream to ba-itsys**: a Java 21 build, the programmatic enrollment service, the APNs sender, and a challenge issuer for non-HTML authenticators.

## Later

- Native SSO between several first-party apps (OpenID Native SSO) instead of repeating the login per app.
- React Native and Flutter wrappers.
- Account-console support for listing and removing native devices (push credentials, DPoP-bound sessions).
- Publishing the challenge profile as an Internet-Draft profile of OAuth 2.0 for First-Party Applications.
- Optional: completion-handler and Combine variants of the iOS API, and the well-known `authorization_challenge_endpoint` override.

## Not planned for native screens

New-user registration, forgotten-password recovery, TOTP enrollment, recovery-code generation and social/identity-provider login stay on Keycloak's own pages in the browser.
