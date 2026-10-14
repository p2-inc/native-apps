# 10 — Project status and task list

**Updated:** 14 October 2026 (end of Phase 1b — iOS SDK core + example app)
**Authoritative for:** what exists, what is verified, what comes next. Decisions and their evidence are in `09-phase0-decisions.md` (Phase 0), `11-phase1-decisions.md` (Phase 1a) and `12-phase1b-decisions.md` (Phase 1b); the phase plan and estimates are in `08-roadmap-and-open-questions.md`.

## 1. Current state

### What exists (all on `main`, `keycloak-native-auth/`)

| Piece | State | Verified by |
|---|---|---|
| Parent POM, Keycloak **26.8.1**, Java 21 | done | `mvn verify` |
| `native-auth-core`: protocol model (snake_case), `AuthSessionCodec` (JWE, in-flow and post-login shapes), `NativeAuthenticator` + `NativeRequiredAction` SPIs, `NativeRequestContext`/`ChallengeEnvelope` | done | 14 unit tests |
| `native-auth-endpoint`: `GET /realms/{r}/native-auth/metadata`, `POST …/challenge`, `POST …/passkey/register/options|finish`; `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver`, `NativeAuthConfig` | done | 1 unit test + ITs |
| `native-auth-authenticators`: `native-username`, `native-password`, `native-totp`, `native-passkey`, `NativeAuthenticatorBase` (multi-alternative `challenges[]`, flow-ordered) | done | ITs |
| `native-auth-required-actions`: `native-passkey-register`, `PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier` | done | ITs |
| `demo/`: docker-compose (Keycloak + Postgres), `realm-export/demo-realm.json` (flows `native`, `native-alternatives`, `native-passkey-first`; clients `demo-ios`, `demo-ios-alt`, `demo-ios-passkey`, `web-app`; users alice/bob/carol/dave; Passwordless WebAuthn policy; required actions incl. `native-passkey-register`), `scripts/walkthrough.sh`, `scripts/passkey-walkthrough.md` | done | walkthrough exits 0 from a clean clone |
| Integration tests `demo/src/test/java/.../NativeAuthIT.java` (21) + `PasskeyIT.java` (8, software authenticator `SoftwareAuthenticator`/`Cbor`); `TranscriptRecorder` writes one wire transcript per test; committed fixture set `demo/transcripts/` (30 files, `scripts/update-transcripts.sh`) | done, green | `mvn verify` ≈ 2.5 min after image pull |
| `ios/KeycloakNative`: Swift package, product `KeycloakNativeCore` (metadata, challenge state machine, PKCE, DPoP with Secure Enclave/software key, passkey bridge, registration client, tokens, Keychain `CredentialsManager`, redacting logger + flow observer) | done | 65 Swift Testing tests replaying the transcripts + 4 live tests against the compose stack — **on macOS only** (12) |
| `ios/KeycloakNativeDemo`: example app (S1, S2, S3, S11, S14, dave enrolment, Diagnostics), XcodeGen project, tunnel/AASA setup notes | written, `swift build` OK on macOS | **not run on a simulator or device** (no Xcode on the build Mac, 12) |
| CI `.github/workflows/ci.yml`: `mvn verify` job + `docker compose up` & walkthrough job | written, **not yet executed on GitHub** (repo not pushed) | — |
| `keycloak-native-auth/README.md` (build, run, configuration reference) | done | — |

### Protocol coverage vs `03-protocol-spec.md`

| Spec item | Status |
|---|---|
| §1 metadata, challenge endpoint | ✅ (`code_exchange`, `passkey` block; `push` block absent until Phase 3) |
| §2 initial / continuation requests, `action=cancel` | ✅ (`action=resend`/`select` unused yet) |
| §3.1 success body | ✅ with post-login `auth_session` (minted; consumption = step-up is Phase 2, presenting it → `invalid_session`) |
| §3.2/3.3 challenge envelope, descriptors, `error`, `required`, `context`, `expires_in` | ✅ (`retry.remaining` not emitted; order = flow layout, 11 D3) |
| §3.4 `redirect_to_web` | ❌ not implemented — pending **non-native** required actions answer `403 access_denied` (extension point in `ChallengeFlowDriver.complete`); native ones run in-band (11 D1) |
| §3.5 errors | ✅ `invalid_request`, `invalid_session`, `invalid_client`, `access_denied`, `server_error`; `invalid_dpop_proof`, `slow_down`, `client_attestation_required` not yet |
| §4.1 username | ✅ with limitation: unknown user re-challenges `username`, so existence is still observable (phantom password challenge = Phase 2) |
| §4.2 password, §4.5 totp | ✅ (`params.credentials` added to totp) |
| §4.3 passkey (allow-list and discoverable), §4.4 passkey_registration (required action) | ✅ (11 D2, D1) |
| §4.6 otp, §4.7 push, §4.8 recovery_code, §4.9 select | ❌ Phases 2–3 |
| §5 session semantics | ✅ in-flow; post-login `auth_session` minted ✅; step-up / refresh-triggered re-auth ❌ |
| §6 passkey registration endpoints (bearer/DPoP token, freshness rule, single-use `registration_id`) | ✅ (11 D5) |
| §7 push device API | ❌ |
| §8 DPoP | challenge endpoint ❌ (claims/`OAuth2Code.dpopJkt` plumbed, always null; metadata advertises `[]`); **token endpoint binds** when a proof is sent (Keycloak built-in, 12 D2) and the SDK handles `token_type: DPoP` |
| §9 attestation | ❌ (reserved) |

### Known limitations / debt carried into Phase 1

- Username enumeration resistance is partial (see above).
- `retry.remaining` is not emitted (Keycloak does not expose remaining attempts cheaply).
- No `jboss-logging` of success events at INFO (default Keycloak behaviour); events verified through the admin API.
- Demo realm sets `otpPolicyCodeReusable=true` for repeatable logins; ITs pause 1.1 s before deliberate failures to stay under Keycloak's quick-login lockout.
- The Keycloak source clone used for reading internals is on *nightly*; always verify signatures against the 26.8.1 jars (09 Q4).
- No spotless/formatting plugin yet; code is hand-formatted (Google style, 2 spaces).

### Known limitations added in Phase 1a

- Passkey origin: Keycloak compares `client_data_json.origin` with the request base origin plus the Passwordless policy's extra origins; deployments where the public base URI is not `https://<rp_id>` must add `https://<rp_id>` to the extra origins (11 D2).
- `native-passkey-register` is served only through the native endpoint; in a browser login it is ignored for that login (with a warning) and stays on the user. A native required action that calls `ignore()` is treated as a failure (11 D1).
- Registration freshness is measured from the user session's `AUTH_TIME`, not from the token; refusal is `403 insufficient_authorization` without `auth_session` because step-up does not exist yet (11 D5).
- Realm exports that list `requiredActions` must include Keycloak's default actions as well (Keycloak seeds them only into an empty list); the demo export does.
- Challenge order follows the flow layout; a user's credential priority (account console "move up") no longer affects it (11 D3).
- No passkey curl walkthrough: an assertion needs a WebAuthn signer; `demo/scripts/passkey-walkthrough.md` documents the sequence and points at the Java simulator used by the ITs.
- "Enrol on first login" (`native-passkey` setting `native-passkey-register` via `setRequiredActions`) is not wired; operators assign the action explicitly.

### Known limitations added in Phase 1b (details in 12)

- Nothing was executed on an iOS simulator or device: the real `ASAuthorizationController` ceremony, the Secure Enclave key on hardware, the iOS Keychain path and the app UI are compiled but untested. First task of whoever has Xcode: open `ios/KeycloakNativeDemo/KeycloakNativeDemo.xcodeproj`, run S3 on a simulator, then the passkey scenarios on a device behind a tunnel.
- On a CLT-only Mac the SDK tests need `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` (swift-testing 6.2.4 from source).
- Keycloak binds tokens to the SDK's DPoP key (token endpoint) although the challenge endpoint does not bind `auth_session`/code yet; a client that drops or rotates its key loses the ability to refresh.
- Transcript fixtures contain inert but real-looking JWTs; secret scanners may flag them.
- Demo realm `failureFactor` is 5 (was 30) and user `erin` exists for S14.
- The SDK has no Combine/completion-handler API, no `KeycloakNativeUI`, no `WebFallback`, no step-up; `redirect_to_web` surfaces as an error.

## 2. Task list

Legend: `[x]` done · `[ ]` open · `[~]` partially done. Phase numbering follows 08.

**Where we are (14 Oct 2026):** Phases 0, 1a and 1b are complete on `main`; the SDK and example app
are verified on macOS against the compose stack but **not yet on an iOS simulator/device** (12).
**Next:** (1) a device pass of the example app (Xcode needed: S3 on a simulator, then S1/S2/S11/dave
behind a tunnel per `ios/KeycloakNativeDemo/README.md`); (2) Phase 2 server items (OTP, step-up
consuming the post-login `auth_session`, `redirect_to_web`, native update-password/verify-email/terms)
and the matching SDK pieces (`WebFallback`, `stepUp`, `KeycloakNativeUI`). Server and SDK work can
proceed in parallel; the shared contract is `spec/03-protocol-spec.md` plus the recorded transcripts
(change the spec first, re-record with `mvn verify && demo/scripts/update-transcripts.sh`, then fix
the SDK tests).

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
Server (`keycloak-native-auth`) — **Phase 1a done** (decisions in 11):
- [x] `native-passkey` authenticator (03 §4.3): assertion options from the realm's WebAuthn **Passwordless** policy + user's credentials (`allow_credentials`) or discoverable; challenge in an auth note keyed by execution id; validate with `WebAuthnCredentialProvider`/webauthn4j; user from `user_handle` when discoverable (11 D2)
- [x] `native-passkey-register` required action (03 §4.4) in the new module `native-auth-required-actions`; `ChallengeFlowDriver.complete` runs native required actions in-band through `RequiredActionDriver` (11 D1)
- [x] `POST /native-auth/passkey/register/options` and `/finish` (03 §6) with bearer/DPoP auth, single-use `registration_id`, freshness rule (11 D5)
- [x] Metadata `passkey` block (rp_id, endpoints); `challenge_types_supported` includes `passkey`, `passkey_registration`
- [x] Demo realm: WebAuthn passwordless policy, `native-passkey` first ALTERNATIVE in "native - primary factor", `native-passkey-first` flow for discoverable login, user `dave` with the required action; passkeys are registered by the ITs (no pre-registered credential in the export, 11 "Other decisions")
- [x] ITs with a hand-written software authenticator (11 D6): allow-list login, discoverable login, registration via required action and via the authenticated endpoints, wrong signature → re-challenge, stale token refused, `[passkey, password]` for alice after username
- [x] Post-login `auth_session` re-mint (03 §5); `resume()` rejects it with `invalid_session` until step-up (11 D4)
- [x] Internal-API usage confined to `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver` (08 R2, 11)
- [ ] "Enrol on first login": `native-passkey` adds `native-passkey-register` via `setRequiredActions` when policy says so (04 §4)
- [ ] Optional: restrict `/passkey/register/*` to native-enabled clients (11 D5)

**Phase 1b — iOS SDK core + example app** (next; plan in 05 and 06, decisions go into a new `12-phase1b-decisions.md`):

Server prerequisites (small, Java, do first so the SDK has fixtures):
- [x] Record wire transcripts: make `NativeAuthIT`/`PasskeyIT` write every request/response pair (form fields with secrets masked, JSON bodies verbatim) to `keycloak-native-auth/demo/target/transcripts/*.json` and copy a curated, committed set to `keycloak-native-auth/demo/transcripts/` — these are the SDK's contract fixtures (05 §7, 03 §11)
- [x] Publish the realm's TOTP/passkey test material the SDK unit tests need (alice's TOTP secret is already in the README; the software authenticator's key is generated per run — fixtures must therefore carry full responses, not re-derive signatures)

iOS SDK (`KeycloakNative` Swift package at `ios/KeycloakNative/`, Swift 6, iOS 17+, zero third-party dependencies):
- [x] `KeycloakNativeCore`: configuration from `/native-auth/metadata` (`code_exchange`, `passkey.rp_id`, `challenge_types_supported`), challenge state machine `start() -> .challenges([...], context) -> respond(...) -> .authorized(credentials)`, PKCE S256, form-encoded transport (`Accept: application/json`, tolerate 400 and 403 for `insufficient_authorization`), typed errors with stable `code`s, unknown challenge types → `.unknown`, redacting logger
- [x] Wire mapping for the implemented types: `username`, `password`, `totp` (+ `credential_id`), `passkey` (§4.3), `passkey_registration` (§4.4, `challenge_id` = provider id, `error.code = invalid_attestation`), success body with `auth_session` (store it; do **not** send it to the challenge endpoint until step-up exists — the server answers `invalid_session`)
- [x] Passkey bridge over `ASAuthorizationPlatformPublicKeyCredentialProvider` (compiled, mock-tested; device-untested, 12) (assertion with `allowedCredentials`/discoverable, registration), base64url without padding, `passkey_cancelled` not a flow failure
- [x] Authenticated registration client for `/passkey/register/options|finish` (bearer; JSON `finish` body; handle `401 invalid_token`, `403 insufficient_authorization` = re-login)
- [x] `Tokens` (code exchange without `redirect_uri` unless metadata says so, refresh, revoke, logout) and `CredentialsManager` (Keychain, serialised refresh, clear)
- [x] DPoP: `DPoPKey` protocol with Secure Enclave + software (CryptoKit) keys (the token endpoint already binds, 12 D2), proof builder (`htm/htu/iat/jti/ath`); send proofs on challenge + token requests from day one — the server ignores them until Phase 4 (metadata advertises `dpop_signing_alg_values_supported: []`), so the SDK must treat absence of binding as normal
- [x] Unit tests: `MockTransport` replaying the recorded transcripts; JOSE/PKCE vectors; passkey bridge behind a `PasskeyPlatform` protocol mock
- [x] Decide and record in 12: dev-time RP ID / Associated Domains strategy (06 §3: tunnel with fixed hostname vs `?mode=developer`), and the `rp_id` ≠ issuer host rule (`allowRpIdMismatch`)

Example app (06):
- [~] Scenarios S1 (username → passkey), S2 (discoverable passkey, client `demo-ios-passkey`), S3 (password → TOTP), S11 (register a second passkey after login), S14 (brute force → `access_denied`), plus the `native-passkey-register` enrolment path (user `dave`) and the Diagnostics flow log — implemented and type-checked; the same paths pass as SDK live tests on macOS; **app not yet run on iOS** (12)
- [ ] Device pass: run the app on a simulator (S3, S14) and on a device behind a tunnel (S1, S2, S11, dave); fix whatever the real passkey sheet and Keychain reveal
- [x] Local setup against the demo compose stack: document `KC_PORT`, hostnames, HTTPS/tunnel for passkeys, and the Passwordless policy's **extra origins** (`https://<rp_id>`, 11 D2) that a tunnel setup needs

Spec:
- [ ] Freeze protocol v1.0-rc for the implemented challenge types (`username`, `password`, `totp`, `passkey`, `passkey_registration`); conformance suite = the recorded transcripts (04 §8)

Deferred server items (do when the SDK needs them or in Phase 2):
- [ ] Well-known `authorization_challenge_endpoint` override (04 §2.3, optional)
- [ ] `retry.remaining` on descriptors (needs a cheap brute-force attempt counter)

### Phase 2 — Remaining factors, step-up, fallback, UI
- [ ] `native-otp` (email via Keycloak templates, `sms-webhook` sender) in `native-auth-otp-sender`; `action=resend` with cooldown
- [ ] `native-recovery-code`
- [ ] `native-select` (optional) and `native-redirect-to-web` authenticators
- [ ] `RedirectToWebBuilder`: PAR `request_uri` for unsupported required actions (03 §3.4); only when PKCE was present
- [ ] Native variants of UPDATE_PASSWORD, VERIFY_EMAIL, TERMS (08 Q7)
- [ ] Step-up: post-login `auth_session` (minted since Phase 1a, rejected by `resume()` today — 11 D4) + `acr_values` → resume user session, LoA conditions, new `acr` (03 §5); map `acr_values` to `REQUESTED_LEVEL_OF_AUTHENTICATION`; also lets the passkey registration endpoints answer a stale token with a real step-up instead of "log in again"
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
- [ ] DPoP binding of `auth_session` and code at the challenge endpoint (03 §8; tokens are already bound by Keycloak, 12 D2), metadata `dpop_signing_alg_values_supported`
- [ ] Attestation-based client auth + `client_attestation_required`
- [ ] Rate limiting (`slow_down`), `NativeRiskEvaluator` SPI hook
- [ ] Custom event types, metrics (04 §9)
- [ ] CI matrix: last two 26.x minors + nightly (allowed to fail); spotless
- [ ] Security review against 07 §10; load test; docs; Maven Central / SwiftPM release

### Phase 5 — Android (post-v1)
- [ ] Kotlin port per 08
