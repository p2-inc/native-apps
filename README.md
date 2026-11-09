# Native authentication for Keycloak

[![CI](https://github.com/p2-inc/native-apps/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/p2-inc/native-apps/actions/workflows/ci.yml)
![Keycloak 26.4 to 26.8](https://img.shields.io/badge/Keycloak-26.4%20to%2026.8-4d4d4d?logo=keycloak)
![iOS 17+](https://img.shields.io/badge/iOS-17%2B-000000?logo=apple)
![Android 9+](https://img.shields.io/badge/Android-9%2B%20(API%2028)-3ddc84?logo=android&logoColor=white)
[![SDKs: Apache 2.0](https://img.shields.io/badge/SDKs-Apache%202.0-blue)](LICENSE)
[![Extensions: ELv2](https://img.shields.io/badge/extensions-ELv2-blue)](keycloak-native-auth/COPYING)

Sign users in to Keycloak with your app's own screens instead of a browser or webview. A set of Keycloak extensions serves the login flow as structured JSON challenges, and the iOS and Android SDKs turn them into native screens and tokens. Passwords, one-time codes, passkeys, recovery codes, push approvals and required actions all run natively. Anything the native flow can't handle falls back to the system browser.

**Status:** the Keycloak extensions, the iOS SDK and the Android SDK are implemented, each with a demo app. Both SDKs are still being verified on real devices, and the project is below 1.0.

See the [roadmap](ROADMAP.md) for what comes next. Start with the [developer documentation](docs/README.md) for setup, the protocol, flow examples, iOS integration, the demo app, troubleshooting and security.

| Directory | What |
|---|---|
| `spec/` | Investigation, protocol specification (`03`), architecture and plans. Read `spec/00-README.md` first, then `spec/10-status-and-task-list.md` for the current state and open tasks. |
| `keycloak-native-auth/` | Keycloak extensions (Maven multi-module): the FiPA-style challenge endpoint (with step-up, redirect-to-web and DPoP binding), native authenticators (username with a phantom challenge for unknown users, password, TOTP, passkey with enrol-on-first-login, recovery codes, email/SMS OTP), native required actions (passkey registration, update password, verify email, terms, push enrolment), push MFA on ba-itsys' `keycloak-push-mfa-extension` (rebuilt for Java 21, an `apns` sender, in-app enrolment, the `native-push` challenge with number match), demo realm, docker-compose (Keycloak, mailpit, a step-up demo API), integration tests that also record the wire transcripts in `demo/transcripts/`. See its `README.md`. |
| `ios/KeycloakNative/` | Swift package, products `KeycloakNativeCore` (challenge state machine, PKCE, DPoP, passkeys, step-up, browser fallback, OTP, recovery codes, required actions, tokens, Keychain credentials), `KeycloakNativePush` (push enrolment, approvals with number match, APNs token, key rotation, lockout; the DPoP key is the device key) and `KeycloakNativeUI` (default SwiftUI screens with a string catalogue, replaceable per challenge type, plus the approvals list). Tests replay the recorded transcripts; the UI product has its own tests. See its `README.md`. |
| `ios/KeycloakNativeDemo/` | Example iOS app (scenarios S1–S14, passkey and push enrolment, the required actions, recovery codes, Diagnostics log) with XCUITests for the simulator and local-setup notes for real passkeys. |
| `android/` | Android SDK (spec/17): Gradle build with the plain Kotlin/JVM `core` module (the port of `KeycloakNativeCore`), whose tests replay the same transcripts as the iOS SDK (`cd android && ./gradlew :core:test`, needs only a JDK 21), the `android` library module with the platform pieces, the `ui` module with the Compose screens, the `push` module with Firebase Cloud Messaging, and the `demo` app (all four need the Android SDK; see `android/demo/README.md`). |
| `react-native/keycloak-native/` | React Native module (spec/19, first slice): a TurboModule over both SDKs with a typed challenge model, default React screens replaceable per challenge type, and Jest tests that replay the same transcripts; an example app. See its `README.md`. |
| `.github/workflows/ci.yml` | Build + unit + integration tests; docker compose + curl walkthrough; Swift package build + tests and app build-for-testing on macOS. |

Quick start:

```bash
cd keycloak-native-auth
mvn verify                                  # needs Docker
mvn -DskipTests -DskipITs package && cd demo && docker compose up --wait && ./scripts/walkthrough.sh
cd ../.. && swift test                      # SDK contract tests; the manifest is at the repo root (see ios/KeycloakNative/README.md for a CLT-only Mac)
cd ios/KeycloakNativeDemo && xcodebuild test -scheme KeycloakNativeDemo -destination 'platform=iOS Simulator,name=iPhone 18 Pro' CODE_SIGN_IDENTITY="-"   # app smoke tests against the compose stack
```

## Releases

One version line covers the server extensions and both SDKs, because SwiftPM reads versions from plain tags on this repository. Releases are tags without a prefix (`0.1.0`, not `v0.1.0`) with a GitHub release marked as a pre-release while the version is below 1.0. Below 1.0 any release may change the protocol or the API ([semantic versioning](https://semver.org/#spec-item-4)); consumers pin exact versions.

To cut a release from `main`: `gh release create <version> --target main --prerelease --generate-notes`. Publishing it starts the [release workflow](.github/workflows/release.yml), which builds that tag and attaches two files: `keycloak-native-auth-providers-<version>.zip` with the provider jars for Keycloak's `providers/` directory, and `keycloak-native-android-<version>-maven-repo.zip` with the Android SDK as a Maven repository (group `io.phasetwo.keycloak.nativeauth`, artifacts `keycloak-native-core`, `keycloak-native-android`, `keycloak-native-ui` and `keycloak-native-push`; unzip it and add the directory as a `maven { url = uri(...) }` repository). The workflow also signs the Android libraries with the org's release key and publishes them to Maven Central. Central keeps every version permanently, so a published tag can't be replaced, only superseded. Then open a PR that sets the next development version in `keycloak-native-auth` (`mvn -f keycloak-native-auth versions:set -DnewVersion=<next>-SNAPSHOT -DgenerateBackupPoms=false`) and in `android/build.gradle.kts`. The Keycloak provider modules aren't in a public Maven repository.

## License

The SDKs, the protocol and the demo assets are under the [Apache License 2.0](LICENSE), so apps can bundle them and integrators can copy the demo setup freely. The Keycloak extensions that implement native authentication (the challenge endpoint, the native authenticators and required actions, and the push and one-time-code support built for them) are under the [Elastic License 2.0](keycloak-native-auth/COPYING) (ELv2), like Phase Two's other extensions.

| Path | License |
|---|---|
| `Package.swift`, `ios/`, `android/`, `react-native/`, `spec/`, `docs/` | Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)) |
| `keycloak-native-auth/demo/` except `src/`: the compose files, realm export, resource server, scripts and the recorded transcripts (the conformance fixtures for any client) | Apache-2.0 ([LICENSE](keycloak-native-auth/demo/LICENSE)) |
| `keycloak-native-auth/push-mfa-extension-java21/` | Apache-2.0 ([LICENSE](keycloak-native-auth/push-mfa-extension-java21/LICENSE), [NOTICE](keycloak-native-auth/push-mfa-extension-java21/NOTICE)): ba-itsys' push MFA extension, recompiled for Java 21 |
| Everything else in `keycloak-native-auth/`: `native-auth-core`, `-authenticators`, `-endpoint`, `-required-actions`, `-otp-sender`, `-push`, `-push-apns`, and the integration tests in `demo/src/` | ELv2 ([COPYING](keycloak-native-auth/COPYING)) |

Copyright 2026 Phase Two, Inc.
