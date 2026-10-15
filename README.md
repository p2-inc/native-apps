# native-apps — browserless native authentication for Keycloak

Start with the [developer documentation](docs/README.md) for setup, protocol and flow examples,
iOS integration, sample walkthrough, troubleshooting, and security responsibilities.
The iOS SDK and sample are implemented; Android SDK and sample support is planned and **not implemented**.

| Directory | What |
|---|---|
| `spec/` | Investigation, protocol specification (`03`), architecture and plans. Read `spec/00-README.md` first, then `spec/10-status-and-task-list.md` for the current state and open tasks. |
| `keycloak-native-auth/` | Keycloak extensions (Maven multi-module): the FiPA-style challenge endpoint (with step-up, redirect-to-web and DPoP binding), native authenticators (username with a phantom challenge for unknown users, password, TOTP, passkey with enrol-on-first-login, recovery codes, email/SMS OTP), native required actions (passkey registration, update password, verify email, terms, push enrolment), push MFA on ba-itsys' `keycloak-push-mfa-extension` (rebuilt for Java 21, an `apns` sender, in-app enrolment, the `native-push` challenge with number match), demo realm, docker-compose (Keycloak, mailpit, a step-up demo API), integration tests that also record the wire transcripts in `demo/transcripts/`. See its `README.md`. |
| `ios/KeycloakNative/` | Swift package, products `KeycloakNativeCore` (challenge state machine, PKCE, DPoP, passkeys, step-up, browser fallback, OTP, recovery codes, required actions, tokens, Keychain credentials), `KeycloakNativePush` (push enrolment, approvals with number match, APNs token, key rotation, lockout; the DPoP key is the device key) and `KeycloakNativeUI` (default SwiftUI screens with a string catalogue, replaceable per challenge type, plus the approvals list). Tests replay the recorded transcripts; the UI product has its own tests. See its `README.md`. |
| `ios/KeycloakNativeDemo/` | Example iOS app (scenarios S1–S14, passkey and push enrolment, the required actions, recovery codes, Diagnostics log) with XCUITests for the simulator and local-setup notes for real passkeys. |
| `.github/workflows/ci.yml` | Build + unit + integration tests; docker compose + curl walkthrough; Swift package build + tests and app build-for-testing on macOS. |

Quick start:

```bash
cd keycloak-native-auth
mvn verify                                  # needs Docker
mvn -DskipTests -DskipITs package && cd demo && docker compose up --wait && ./scripts/walkthrough.sh
cd ../../ios/KeycloakNative && swift test     # SDK contract tests (see its README for a CLT-only Mac)
cd ../KeycloakNativeDemo && xcodebuild test -scheme KeycloakNativeDemo -destination 'platform=iOS Simulator,name=iPhone 18 Pro' CODE_SIGN_IDENTITY="-"   # app smoke tests against the compose stack
```
