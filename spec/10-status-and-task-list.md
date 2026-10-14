# 10 — Project status and task list

**Updated:** 14 October 2026 (end of Phase 0)
**Authoritative for:** what exists, what is verified, what comes next. Decisions and their evidence are in `09-phase0-decisions.md`; the phase plan and estimates are in `08-roadmap-and-open-questions.md`.

## 1. Current state

### What exists (all on `main`, `keycloak-native-auth/`)

| Piece | State | Verified by |
|---|---|---|
| Parent POM, Keycloak **26.8.1**, Java 21 | done | `mvn verify` |
| `native-auth-core`: protocol model (snake_case), `AuthSessionCodec` (JWE), `NativeAuthenticator` SPI, `NativeRequestContext`/`ChallengeEnvelope` | done | 11 unit tests |
| `native-auth-endpoint`: `GET /realms/{r}/native-auth/metadata`, `POST …/challenge`, `ChallengeFlowDriver`, `CodeIssuer`, `NativeAuthConfig` | done | 1 unit test + ITs |
| `native-auth-authenticators`: `native-username`, `native-password`, `native-totp`, `NativeAuthenticatorBase` (multi-alternative `challenges[]`) | done | ITs |
| `demo/`: docker-compose (Keycloak + Postgres), `realm-export/demo-realm.json` (flows `native`, `native-alternatives`; clients `demo-ios`, `demo-ios-alt`, `web-app`; users alice/bob/carol), `scripts/walkthrough.sh` | done | walkthrough exits 0 from a clean clone |
| Integration tests `demo/src/test/java/.../NativeAuthIT.java` (19 tests, Testcontainers + REST Assured) | done, green | `mvn verify` ≈ 1 min after image pull |
| CI `.github/workflows/ci.yml`: `mvn verify` job + `docker compose up` & walkthrough job | written, **not yet executed on GitHub** (repo not pushed) | — |
| `keycloak-native-auth/README.md` (build, run, configuration reference) | done | — |

### Protocol coverage vs `03-protocol-spec.md`

| Spec item | Status |
|---|---|
| §1 metadata, challenge endpoint | ✅ (`code_exchange` added; `passkey`/`push` blocks absent until implemented) |
| §2 initial / continuation requests, `action=cancel` | ✅ (`action=resend`/`select` unused yet) |
| §3.1 success body | ✅ without post-login `auth_session` (step-up not implemented) |
| §3.2/3.3 challenge envelope, descriptors, `error`, `required`, `context`, `expires_in` | ✅ (`retry.remaining` not emitted) |
| §3.4 `redirect_to_web` | ❌ not implemented — pending required actions answer `403 access_denied` (extension point in `ChallengeFlowDriver.complete`) |
| §3.5 errors | ✅ `invalid_request`, `invalid_session`, `invalid_client`, `access_denied`, `server_error`; `invalid_dpop_proof`, `slow_down`, `client_attestation_required` not yet |
| §4.1 username | ✅ with limitation: unknown user re-challenges `username`, so existence is still observable (phantom password challenge = Phase 2) |
| §4.2 password, §4.5 totp | ✅ (`params.credentials` added to totp) |
| §4.3 passkey, §4.4 passkey_registration, §4.6 otp, §4.7 push, §4.8 recovery_code, §4.9 select | ❌ Phases 1–3 |
| §5 session semantics | ✅ in-flow; step-up / refresh-triggered re-auth ❌ |
| §6 passkey registration endpoints, §7 push device API | ❌ |
| §8 DPoP | ❌ (claims/`OAuth2Code.dpopJkt` plumbed, always null); metadata advertises `[]` |
| §9 attestation | ❌ (reserved) |

### Known limitations / debt carried into Phase 1

- Username enumeration resistance is partial (see above).
- `retry.remaining` is not emitted (Keycloak does not expose remaining attempts cheaply).
- No `jboss-logging` of success events at INFO (default Keycloak behaviour); events verified through the admin API.
- Demo realm sets `otpPolicyCodeReusable=true` for repeatable logins; ITs pause 1.1 s before deliberate failures to stay under Keycloak's quick-login lockout.
- The Keycloak source clone used for reading internals is on *nightly*; always verify signatures against the 26.8.1 jars (09 Q4).
- No spotless/formatting plugin yet; code is hand-formatted (Google style, 2 spaces).

## 2. Task list

Legend: `[x]` done · `[ ]` open · `[~]` partially done. Phase numbering follows 08.

### Phase 0 — Spike ✅
- [x] Maven multi-module skeleton; pin Keycloak 26.8.1 (Q4)
- [x] `auth_session` JWE codec + unit tests
- [x] Challenge endpoint + metadata (Q3)
- [x] username / password / totp authenticators
- [x] `CodeIssuer` + `native-auth.code-redirect-uri-mode` (Q1)
- [x] Multi-alternative `challenges[]` (Q2)
- [x] Demo realm, docker-compose, curl walkthrough
- [x] Integration tests + CI workflow
- [x] Decisions memo `09`, spec edits
- [ ] Push the repository and confirm both CI jobs pass on GitHub Actions
- [ ] Decide Q6 (push device client credentials) before Phase 3 starts (08 recommends token exchange)

### Phase 1 — Passkeys (server) + SDK core + example app
Server (`keycloak-native-auth`):
- [ ] `native-passkey` authenticator (03 §4.3): assertion options from the realm's WebAuthn **Passwordless** policy + user's credentials (`allow_credentials`) or discoverable; store challenge in an auth note keyed by execution id (describe() is also called for siblings); validate with `WebAuthnCredentialProvider`/webauthn4j; set user from `user_handle` when discoverable
- [ ] `native-passkey-register` required action (03 §4.4) in a new module `native-auth-required-actions`, emitting a JSON challenge through the same envelope; wire `ChallengeFlowDriver.complete` to run native required actions instead of returning `access_denied`
- [ ] `POST /native-auth/passkey/register/options` and `/finish` (03 §6) with bearer/DPoP auth (`AppAuthManager.BearerTokenAuthenticator`), single-use `registration_id`
- [ ] Metadata `passkey` block (rp_id, endpoints)
- [ ] Demo realm: WebAuthn passwordless policy (RP ID, UV required, resident key required, attestation none), `native-passkey` ALTERNATIVE in "native - primary factor", user with a pre-registered passkey for tests
- [ ] ITs with a software authenticator (webauthn4j test helpers or `com.yubico.webauthn` test utils): S1 allow-list login, S2 discoverable login, registration via required action and via the authenticated endpoints, wrong signature → re-challenge
- [ ] Post-login `auth_session` re-mint (03 §5) so the SDK can persist it now (step-up consumption is Phase 2)
- [ ] Keep `ChallengeFlowDriver`/`CodeIssuer` as the only internal-API users (08 R2)

iOS SDK (`KeycloakNative` Swift package, 05):
- [ ] `KeycloakNativeCore`: configuration from `/native-auth/metadata`, challenge state machine `start() -> .challenges([...]) -> respond(...) -> .authorized(credentials)`, PKCE, form-encoded transport, typed errors with stable `code`s, redacting logger
- [ ] Passkey bridge over `ASAuthorizationPlatformPublicKeyCredentialProvider` (assertion + registration)
- [ ] `CredentialsManager` (Keychain, refresh, logout)
- [ ] DPoP: Secure Enclave + software key, proof generation; server-side binding lands in Phase 4 but the client should send proofs from day one
- [ ] Unit tests with recorded transcripts from the ITs (03 §11)

Example app (06):
- [ ] Scenarios S1, S2, S3, S11, S14 + Diagnostics flow log
- [ ] Local setup against the demo compose stack (document `KC_PORT`, hostnames, associated domains for passkeys)

Spec:
- [ ] Freeze protocol v1.0-rc for implemented challenge types; conformance suite covers them (04 §8)

### Phase 2 — Remaining factors, step-up, fallback, UI
- [ ] `native-otp` (email via Keycloak templates, `sms-webhook` sender) in `native-auth-otp-sender`; `action=resend` with cooldown
- [ ] `native-recovery-code`
- [ ] `native-select` (optional) and `native-redirect-to-web` authenticators
- [ ] `RedirectToWebBuilder`: PAR `request_uri` for unsupported required actions (03 §3.4); only when PKCE was present
- [ ] Native variants of UPDATE_PASSWORD, VERIFY_EMAIL, TERMS (08 Q7)
- [ ] Step-up: `auth_session` + `acr_values` → resume user session, LoA conditions, new `acr` (03 §5); map `acr_values` to `REQUESTED_LEVEL_OF_AUTHENTICATION`
- [ ] Refresh-triggered re-auth (`insufficient_authorization` from the token endpoint)
- [ ] Username phantom challenge (03 §4.1) and `retry.remaining`
- [ ] SDK `WebFallback`, `KeycloakNativeUI` default screens + presenter override, localisation, accessibility
- [ ] Example app S4–S8, S13
- [ ] Spec v1.0; conformance suite complete for the native flow

### Phase 3 — Push MFA
- [ ] Integrate ba-itsys `keycloak-push-mfa-extension` (scenario A) in the demo compose
- [ ] `native-auth-push-apns` sender (HTTP/2, token auth)
- [ ] `/native-auth/push/enroll/start`, `native-push-enroll` required action, `native-push` authenticator (scenario B, `action=poll`)
- [ ] Q6 implementation (token exchange for the device client)
- [ ] SDK `KeycloakNativePush`, approval UI, notification service extension; example app S9, S10, S12
- [ ] Upstream contributions to ba-itsys

### Phase 4 — Hardening & release
- [ ] DPoP binding of `auth_session` and code (03 §8), metadata `dpop_signing_alg_values_supported`
- [ ] Attestation-based client auth + `client_attestation_required`
- [ ] Rate limiting (`slow_down`), `NativeRiskEvaluator` SPI hook
- [ ] Custom event types, metrics (04 §9)
- [ ] CI matrix: last two 26.x minors + nightly (allowed to fail); spotless
- [ ] Security review against 07 §10; load test; docs; Maven Central / SwiftPM release

### Phase 5 — Android (post-v1)
- [ ] Kotlin port per 08
