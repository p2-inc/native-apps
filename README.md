# native-apps — browserless native authentication for Keycloak

| Directory | What |
|---|---|
| `spec/` | Investigation, protocol specification (`03`), architecture and plans. Read `spec/00-README.md` first, then `spec/10-status-and-task-list.md` for the current state and open tasks. |
| `keycloak-native-auth/` | Keycloak extensions (Maven multi-module): the FiPA-style challenge endpoint, native authenticators (username, password, TOTP, passkey), the native passkey-registration required action and endpoints, demo realm, docker-compose, integration tests that also record the wire transcripts in `demo/transcripts/`. See its `README.md`. |
| `ios/KeycloakNative/` | Swift package, product `KeycloakNativeCore`: the SDK (challenge state machine, PKCE, DPoP, passkey bridge, tokens, Keychain credentials). Tests replay the recorded transcripts. See its `README.md`. |
| `ios/KeycloakNativeDemo/` | Example iOS app (scenarios S1, S2, S3, S11, S14, passkey enrolment, Diagnostics log) with local-setup notes for real passkeys. |
| `.github/workflows/ci.yml` | Build + unit + integration tests; docker compose + curl walkthrough; Swift package build + tests on macOS. |

Quick start:

```bash
cd keycloak-native-auth
mvn verify                                  # needs Docker
mvn -DskipTests -DskipITs package && cd demo && docker compose up --wait && ./scripts/walkthrough.sh
cd ../../ios/KeycloakNative && swift test     # SDK contract tests (see its README for a CLT-only Mac)
```
