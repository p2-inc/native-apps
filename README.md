# native-apps — browserless native authentication for Keycloak

| Directory | What |
|---|---|
| `spec/` | Investigation, protocol specification (`03`), architecture and plans. Read `spec/00-README.md` first, then `spec/10-status-and-task-list.md` for the current state and open tasks. |
| `keycloak-native-auth/` | Keycloak extensions (Maven multi-module): the FiPA-style challenge endpoint (with step-up, redirect-to-web and DPoP binding), native authenticators (username, password, TOTP, passkey, email/SMS OTP), the native passkey-registration required action and endpoints, demo realm, docker-compose (Keycloak, mailpit, a step-up demo API), integration tests that also record the wire transcripts in `demo/transcripts/`. See its `README.md`. |
| `ios/KeycloakNative/` | Swift package, products `KeycloakNativeCore` (challenge state machine, PKCE, DPoP, passkeys, step-up, browser fallback, OTP, tokens, Keychain credentials) and `KeycloakNativeUI` (default SwiftUI screens, replaceable per challenge type). Tests replay the recorded transcripts. See its `README.md`. |
| `ios/KeycloakNativeDemo/` | Example iOS app (scenarios S1–S8, S11, S13, S14, passkey enrolment, Diagnostics log) with XCUITest smoke tests for the simulator and local-setup notes for real passkeys. |
| `.github/workflows/ci.yml` | Build + unit + integration tests; docker compose + curl walkthrough; Swift package build + tests and app build-for-testing on macOS. |

Quick start:

```bash
cd keycloak-native-auth
mvn verify                                  # needs Docker
mvn -DskipTests -DskipITs package && cd demo && docker compose up --wait && ./scripts/walkthrough.sh
cd ../../ios/KeycloakNative && swift test     # SDK contract tests (see its README for a CLT-only Mac)
cd ../KeycloakNativeDemo && xcodebuild test -scheme KeycloakNativeDemo -destination 'platform=iOS Simulator,name=iPhone 18 Pro' CODE_SIGN_IDENTITY="-"   # app smoke tests against the compose stack
```
