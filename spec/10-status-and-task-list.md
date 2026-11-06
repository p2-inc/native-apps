# 10 — Project status and task list

**Updated:** 15 October 2026 (end of Phase 1c simulator pass + Phase 2 — step-up, redirect-to-web, OTP, UI product; manual testing notes in 13)
**Authoritative for:** what exists, what is verified, what comes next. Decisions and their evidence are in `09-phase0-decisions.md` (Phase 0), `11-phase1-decisions.md` (Phase 1a), `12-phase1b-decisions.md` (Phase 1b) and `13-phase2-decisions.md` (Phase 1c + 2); the phase plan and estimates are in `08-roadmap-and-open-questions.md`.

## 1. Current state

### What exists (all on `main`, `keycloak-native-auth/`)

| Piece | State | Verified by |
|---|---|---|
| Parent POM, Keycloak **26.8.1**, Java 21 | done | `mvn verify` |
| `native-auth-core`: protocol model (snake_case), `AuthSessionCodec` (JWE, in-flow and post-login shapes), `NativeAuthenticator` + `NativeRequiredAction` SPIs, `NativeRequestContext`/`ChallengeEnvelope` | done | 14 unit tests |
| `native-auth-endpoint`: `GET /realms/{r}/native-auth/metadata`, `POST …/challenge`, `POST …/passkey/register/options|finish`; `ChallengeFlowDriver` (incl. step-up), `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver`, `DPoPProofChecker`, `RedirectToWebBuilder`, `NativeAuthConfig` | done | 1 unit test + ITs |
| `native-auth-authenticators`: `native-username` (skips itself on step-up), `native-password`, `native-totp`, `native-passkey`, `NativeAuthenticatorBase` (multi-alternative `challenges[]`, flow-ordered, `prepare` hook) | done | ITs |
| `native-auth-otp-sender`: `native-otp`, SPI `native-otp-sender` with `email` and `sms-webhook` | done (sms-webhook untested) | `OtpIT` |
| `native-auth-required-actions`: `native-passkey-register`, `PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier` | done | ITs |
| `demo/`: docker-compose (Keycloak + Postgres + mailpit + Node resource server), `realm-export/demo-realm.json` (flows `native`, `native-alternatives`, `native-passkey-first`, `native-step-up`, `native-otp`; clients `demo-ios`, `demo-ios-alt`, `demo-ios-passkey`, `demo-ios-stepup`, `demo-ios-otp`, `web-app`; users alice/bob/carol/dave/erin; SMTP → mailpit), `scripts/walkthrough.sh`, `scripts/passkey-walkthrough.md`, `resource-server/server.mjs` | done | walkthrough exits 0 from a clean clone |
| Integration tests `NativeAuthIT` (20), `PasskeyIT` (8), `StepUpIT` (5), `OtpIT` (3), `RedirectToWebIT` (1), `DPoPBindingIT` (4); `TranscriptRecorder`; committed fixture set `demo/transcripts/` (42 files) | done, green | `mvn verify` ≈ 3 min after image pulls |
| `ios/KeycloakNative`: products `KeycloakNativeCore` (metadata, state machine, PKCE, DPoP, passkeys, step-up, `WebFallback`, OTP, tokens, Keychain `CredentialsManager`, redaction), `KeycloakNativePush` (enrolment, approvals, APNs token, key rotation, lockout, notification-service helper) and `KeycloakNativeUI` (`NativeLoginView`, default screens incl. push, `PushApprovalsView`, chooser, presenter overrides, string catalogue) | done | 115 Swift Testing tests replaying the transcripts (both toolchain modes) + 14 live tests against the compose stack |
| `ios/KeycloakNativeDemo`: example app (S1–S14, dave / carol / grace / hank / ivy / judy, Diagnostics), XcodeGen project with an XCUITest target, tunnel/AASA setup notes | done | 14 XCUITests on the **iOS 27 simulator** (13, 14 D7, 14 D9); passkey scenarios and real APNs still need a device |
| CI `.github/workflows/ci.yml`: `mvn verify` job, `docker compose up` & walkthrough job, Swift package build + tests + app `build-for-testing` | written, **not yet executed on GitHub** (repo not pushed) | — |
| `keycloak-native-auth/README.md` (build, run, configuration reference) | done | — |

### Protocol coverage vs `03-protocol-spec.md`

| Spec item | Status |
|---|---|
| §1 metadata, challenge endpoint | ✅ (`code_exchange`, `passkey`, `authorization_endpoint`, verified DPoP algorithms, `push` block when `native-auth-push` is installed) |
| §2 initial / continuation requests, `action=cancel`, `action=resend` | ✅ (`action=select` unused: no `native-select`) |
| §3.1 success body | ✅ with post-login `auth_session` (consumed by step-up, 13 D1; DPoP-bound when the login used a key, 13 D3) |
| §3.2/3.3 challenge envelope, descriptors, `error`, `required`, `context` (incl. `step_up`, `acr_requested`), `expires_in` | ✅ (`retry.remaining` not emitted; order = flow layout, 11 D3) |
| §3.4 `redirect_to_web` | ✅ PAR `request_uri` for non-native required actions when PKCE + a redirect URI exist (13 D2); otherwise `access_denied` |
| §3.5 errors | ✅ `invalid_request`, `invalid_session`, `invalid_client`, `access_denied`, `server_error`, `invalid_dpop_proof`; `slow_down`, `client_attestation_required` not yet |
| §4.1 username | ✅ with limitation: unknown user re-challenges `username`, so existence is still observable (phantom password challenge still open) |
| §4.2 password, §4.5 totp | ✅ |
| §4.3 passkey (allow-list and discoverable), §4.4 passkey_registration (required action) | ✅ (11 D2, D1) |
| §4.6 otp | ✅ email (and an untested sms-webhook sender); sent only when the single option or on `action=resend` (13 D4) |
| §4.7 push (number match, `action=resend` / `action=poll`), §4.8 recovery_code, §4.15 push_enrollment | ✅ (14 D9, `PushMfaIT`) |
| §4.9 select | ❌ optional, no authenticator emits it |
| §5 session semantics | ✅ in-flow, post-login `auth_session` minted and consumed by step-up (LoA conditions, `max_age`, `prompt=login`); refresh-triggered `insufficient_authorization` ❌ (Keycloak's token endpoint has no hook; the SDK handles it) |
| §6 passkey registration endpoints (bearer/DPoP token, freshness rule → `insufficient_authorization` + `auth_session` + `max_age`, single-use `registration_id`) | ✅ (11 D5, 13 D1) |
| §7 push device API | ✅ ba-itsys' API unchanged, the DPoP key as device key and the native token as device token (§7.1, 14 D9); `/native-auth/push/enroll/start` added; `apns` sender (14 D10) |
| §8 DPoP | ✅ proofs verified at the challenge endpoint; in-flow `auth_session`, code (`dpop_jkt`) and post-login `auth_session` bound to the key when the first request carried a proof (13 D3); token binding by Keycloak (12 D2); no nonces, binding not mandatory |
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
- The SDK has no Combine/completion-handler API.

### Known limitations added in Phase 1c / Phase 2 (details in 13)

- The passkey ceremonies, the Secure Enclave key and Associated Domains are still unverified on hardware: no device and no signing identity on the build Mac. Simulator builds must be code-signed (ad hoc is enough); otherwise the simulator Keychain answers `-34018` and the SDK fails with `keychain_error`.
- A step-up on a flow without `conditional-level-of-authentication` executions re-runs every factor and keeps `acr=1`; LoA levels need the step-up flow layout (`native-step-up` is the template).
- `redirect_to_web` requires a full browser login (no hand-off of the native session), PKCE on the native request and a registered redirect URI; the `request_uri` is single use and lives 60 s (realm PAR lifespan).
- DPoP binding is opportunistic (a session started without a proof stays unbound); no `DPoP-Nonce` at the challenge endpoint; a failed code exchange consumes the code (Keycloak).
- `native-otp`'s `configuredFor` uses the realm-default channel (`email`), not the execution's config; OTP codes are hashed in the authentication session and die with it. (The SMS webhook sender has an integration test since Phase 2b.)
- (Phase 2b) `KeycloakNativeUI` has a string catalogue (en, de) with an override bundle and model tests; the XCUITests cover S4/S5/S6/S8/S13 and the required actions; S7 stays manual. A VoiceOver / Dynamic Type pass needs a device.

## 2. Task list

Legend: `[x]` done · `[ ]` open · `[~]` partially done. Phase numbering follows 08.

**Where we are (15 Oct 2026, end of Phase 3):** Phases 0, 1a, 1b, the simulator half of 1c, Phase 2,
Phase 2b and **Phase 3 (push MFA)** are complete on `main` and pushed to `origin` (14). Verified by
`mvn verify` (58 ITs, 17 unit tests), `swift test` (115 tests across Core, Push and UI, both toolchain
modes), 14 live SDK tests against the compose stack, the curl walkthrough from a clean compose stack
and 14 XCUITests on the iOS 27 simulator. The protocol is frozen as v1.0-rc for everything
implemented (03 §10.1); `push`, §4.15 and §7 are now implemented on both sides too.

**Next, in this order:**
1. **Hardware half of Phase 1c and Phase 3** whenever a device and an Apple team are available (S1,
   S2, S11, dave, the cancel path, Secure Enclave, Associated Domains behind a tunnel, real APNs
   delivery with the `apns` sender, the notification service extension, a VoiceOver pass).
2. **Upstream to ba-itsys** (14 D10) and **Phase 4** hardening.

Working rule (unchanged): change `spec/03` first, implement on the server, re-record with
`mvn verify && demo/scripts/update-transcripts.sh` (delete the recordings of renamed tests in
`demo/target/transcripts` first), then make the SDK pass the new transcripts; server and SDK can be
worked by different agents with the transcripts as the hand-off. Each phase gets a memo
(`spec/14-…` next) and is added to `spec/00`.

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
- [x] Push the repository and confirm both CI jobs pass on GitHub Actions
- [x] Q6 decided in Phase 3 (14 D9): no token exchange for public clients in Keycloak 26.8; the DPoP key is the device key

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
- [x] "Enrol on first login": `native-passkey` schedules `native-passkey-register` for the login when `enrol-on-first-login` is set (14 D4)
- [x] Optional: restrict `/passkey/register/*` to native-enabled clients (11 D5) — realm attribute, Phase 2b (14 D4)

**Phase 1b — iOS SDK core + example app** — **done on macOS** (plan in 05 and 06, decisions in `12-phase1b-decisions.md`):

Server prerequisites (small, Java, do first so the SDK has fixtures):
- [x] Record wire transcripts: make `NativeAuthIT`/`PasskeyIT` write every request/response pair (form fields with secrets masked, JSON bodies verbatim) to `keycloak-native-auth/demo/target/transcripts/*.json` and copy a curated, committed set to `keycloak-native-auth/demo/transcripts/` — these are the SDK's contract fixtures (05 §7, 03 §11)
- [x] Publish the realm's TOTP/passkey test material the SDK unit tests need (alice's TOTP secret is already in the README; the software authenticator's key is generated per run — fixtures must therefore carry full responses, not re-derive signatures)

iOS SDK (`KeycloakNative` Swift package at `ios/KeycloakNative/`, Swift 6, iOS 17+, zero third-party dependencies):
- [x] `KeycloakNativeCore`: configuration from `/native-auth/metadata` (`code_exchange`, `passkey.rp_id`, `challenge_types_supported`), challenge state machine `start() -> .challenges([...], context) -> respond(...) -> .authorized(credentials)`, PKCE S256, form-encoded transport (`Accept: application/json`, tolerate 400 and 403 for `insufficient_authorization`), typed errors with stable `code`s, unknown challenge types → `.unknown`, redacting logger
- [x] Wire mapping for the implemented types: `username`, `password`, `totp` (+ `credential_id`), `passkey` (§4.3), `passkey_registration` (§4.4, `challenge_id` = provider id, `error.code = invalid_attestation`), success body with `auth_session` (store it; do **not** send it to the challenge endpoint until step-up exists — the server answers `invalid_session`)
- [x] Passkey bridge over `ASAuthorizationPlatformPublicKeyCredentialProvider` (compiled, mock-tested; device-untested, 12) (assertion with `allowedCredentials`/discoverable, registration), base64url without padding, `passkey_cancelled` not a flow failure
- [x] Authenticated registration client for `/passkey/register/options|finish` (bearer; JSON `finish` body; handle `401 invalid_token`, `403 insufficient_authorization` = re-login)
- [x] `Tokens` (code exchange without `redirect_uri` unless metadata says so, refresh, revoke, logout) and `CredentialsManager` (Keychain, serialised refresh, clear)
- [x] DPoP: `DPoPKey` protocol with Secure Enclave + software (CryptoKit) keys (the token endpoint already binds, 12 D2), proof builder (`htm/htu/iat/jti/ath`); proofs are sent on challenge + token requests; the challenge endpoint ignores them (metadata advertises `[]`), the token endpoint binds (`token_type: DPoP`) and the SDK follows `token_type`
- [x] Unit tests: `MockTransport` replaying the recorded transcripts; JOSE/PKCE vectors; passkey bridge behind a `PasskeyPlatform` protocol mock
- [x] Decide and record in 12: dev-time RP ID / Associated Domains strategy (06 §3: tunnel with fixed hostname vs `?mode=developer`), and the `rp_id` ≠ issuer host rule (`allowRpIdMismatch`)

Example app (06):
- [~] Scenarios S1 (username → passkey), S2 (discoverable passkey, client `demo-ios-passkey`), S3 (password → TOTP), S11 (register a second passkey after login), S14 (brute force → `access_denied`), plus the `native-passkey-register` enrolment path (user `dave`) and the Diagnostics flow log — implemented and type-checked; the same paths pass as SDK live tests on macOS; **app not yet run on iOS** (12)
- [x] Local setup against the demo compose stack: document `KC_PORT`, hostnames, HTTPS/tunnel for passkeys, and the Passwordless policy's **extra origins** (`https://<rp_id>`, 11 D2) that a tunnel setup needs


### Phase 1c — Device pass (simulator half done, 13; hardware half needs a device + team)
- [x] Open `ios/KeycloakNativeDemo/KeycloakNativeDemo.xcodeproj` (XcodeGen output), run on an iOS 27 simulator against `KC_PORT=8089 docker compose up --wait`; S3 (alice, password + TOTP) and S14 (erin) pass — as XCUITests (`UITests/DemoAppUITests.swift`); the app must be code-signed (ad hoc) for the simulator Keychain
- [ ] Device behind a tunnel per `ios/KeycloakNativeDemo/README.md` §2 (fixed hostname, AASA via a Caddy front, policy RP ID = tunnel host, `webcredentials:<host>?mode=developer`): S11 (register), S1 (allow-list), S2 (discoverable, client `demo-ios-passkey`), dave enrolment; cancel the sheet once (must stay on the challenge set, `passkey_cancelled`) — **blocked: no device, no signing identity**
- [~] Verify on hardware: `DPoPMode.automatic` picks the Secure Enclave (Diagnostics shows `jkt`; `token_type` is `DPoP`) — simulator shows the software key's `jkt` and `token_type DPoP`; Secure Enclave needs hardware. The Keychain `CredentialsManager` survives a relaunch and `logout` clears — verified on the simulator
- [x] `swift test` with Xcode's toolchain (no `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE`); the `ios-sdk` CI job on GitHub Actions is still unexecuted (repo not pushed)
- [ ] Fix whatever the real `ASAuthorizationController` reveals (presentation anchor, `excludedCredentials` on 17.4+, transports reported by iOS); keep `PasskeyPlatform` as the seam
- [ ] Optional: a Settings bundle for issuer/client (06 §1) instead of editing `Config.plist`

### Phase 2 — Remaining factors, step-up, fallback, UI
Working rule (12): **change `spec/03` first**, implement on the server, re-record the fixtures
(`mvn verify && demo/scripts/update-transcripts.sh`), then make the SDK pass the new transcripts.
Server and SDK can be worked by different agents; the transcripts are the hand-off.

Server (`keycloak-native-auth`) — **done in Phase 2 (13)** unless marked:
- [x] Step-up (03 §5): `ChallengeFlowDriver.stepUp` accepts the post-login `auth_session`, resumes the user session, maps `acr_values` to the requested LoA, runs only what the LoA conditions need, issues a new code for the same session; `/passkey/register/*` answer a stale token with `insufficient_authorization` + `auth_session` + `max_age`; the step-up code and the post-login session are bound to the login's DPoP key (13 D1, D3)
- [ ] Refresh-triggered re-auth from the token endpoint — **not implementable without a custom grant**; left out (13 D1)
- [x] `RedirectToWebBuilder`: PAR `request_uri` for non-native required actions (03 §3.4), only with PKCE and a redirect URI; `RedirectToWebIT` with carol + transcript (13 D2)
- [x] Native variants of UPDATE_PASSWORD, VERIFY_EMAIL, TERMS as `NativeRequiredAction`s (08 Q7) — Phase 2b (14 D1)
- [x] `native-otp` (`email` via the realm SMTP settings, `sms-webhook` sender) in `native-auth-otp-sender`; `action=resend` with cooldown; mailpit in compose and in the ITs (13 D4)
- [x] IT for the `sms-webhook` sender (host-side sink through Testcontainers' `exposeHostPorts`) — Phase 2b (14 D5)
- [x] DPoP proof verification and binding of `auth_session` / code at the challenge endpoint (13 D3; was a Phase 4 item)
- [x] `native-recovery-code` (03 §4.8) — Phase 2b (14 D2); `native-select` (03 §4.9) stays optional and unimplemented
- [x] Username phantom challenge (03 §4.1) and `retry.remaining` — Phase 2b (14 D3)
- [x] "Enrol on first login" for `native-passkey` and the native-clients-only restriction — Phase 2b (14 D4)
- [ ] Well-known `authorization_challenge_endpoint` override (04 §2.3, optional)

iOS SDK (`ios/KeycloakNative`) — **done in Phase 2 (13 D5)** unless marked:
- [x] `Authentication.stepUp(acrValues:maxAge:)` / `stepUp(_:authSession:)` sending the stored post-login `auth_session`; `continueAfterTokenChallenge(_:)` from `insufficient_authorization` / `reauthentication_required` errors
- [x] `FlowStep.redirectToWeb` + `WebFallback` (`ASWebAuthenticationSession` behind a presenter seam, PAR `request_uri`, `state` check, PKCE of the original flow, exchange with `redirect_uri`)
- [x] `ChallengeAnswer` cases `otp`, `otpResend` plus `OTPParams` (`sent`, `resend_allowed_at`); `recoveryCode`, `select` wait for their authenticators
- [x] `KeycloakNativeUI` product: `NativeLoginView`, default screens per type, chooser, presenter override, accessibility identifiers; the example app's hand-rolled screens are the "full control" sample
- [x] Localisation catalogue for `KeycloakNativeUI` (05 §4); tests of the product itself — Phase 2b (14 D7)
- [ ] Completion-handler / Combine variants (05 §2) if UIKit consumers need them
- [x] Transcript replay: `Harness.replay(seqs:)` for non-contiguous exchanges; the strict field-set rule is kept

Example app — **done in Phase 2** (compiled for the simulator; S4/S6/S7 paths verified through the SDK's live tests, not through XCUITest):
- [x] S4 (email OTP + resend, mailpit), S5 (default UI with chooser), S6 (step-up with the compose resource server returning `401 insufficient_user_authentication`), S7 (redirect-to-web for carol), S8 (revoked session → `reauthentication_required`), S13 (custom presenter)
- [x] XCUITests for S4/S5/S6/S8/S13 — Phase 2b (14 D7); S7 needs Safari and stays manual

Spec:
- [x] Freeze protocol v1.0-rc for the implemented challenge types; conformance suite = the recorded transcripts (03 §10.1, 14 D8)
- [ ] Spec v1.0: `push`, §4.15 and §7 are implemented on both sides (Phase 3); a final editorial pass and the device run are what remain

### Phase 2b — Close-out of Phase 2 (no hardware needed)
Server:
- [x] Native required actions `native-update-password`, `native-verify-email`, `native-terms` as `NativeRequiredAction`s (08 Q7): 03 §4.11–§4.14; they **substitute** for Keycloak's `UPDATE_PASSWORD` / `VERIFY_EMAIL` / `TERMS_AND_CONDITIONS` when registered and enabled (14 D1); carol runs in-band, frank (`UPDATE_PROFILE`) is still redirected (`RequiredActionsIT`, `RedirectToWebIT`)
- [x] `native-recovery-code` (03 §4.8) on Keycloak's recovery-codes credential; user `ivy` with seeded codes, `RecoveryCodeIT` (14 D2)
- [x] Username phantom challenge (03 §4.1) and `retry.remaining` from the brute-force detector (14 D3; `NativeAuthIT`)
- [x] "Enrol on first login" for `native-passkey` behind the execution config `enrol-on-first-login`; `/passkey/register/*` restricted to native clients with `native-auth.passkey-registration-native-clients-only` (14 D4, `EnrolOnFirstLoginIT`)
- [x] IT for the `sms-webhook` sender (host-side sink via Testcontainers `exposeHostPorts`, `SmsOtpIT`, flow `native-sms`); themed email template for the OTP (08 Q10) shipped as theme resources (14 D5)
- [x] Step-up `auth_session` claim lifetime = SSO idle (08 Q11), keeping the `isSessionValid` check (14 D6, `StepUpIT`)
- [ ] Well-known `authorization_challenge_endpoint` override (04 §2.3, optional) — not done; clients use `/native-auth/metadata`
SDK / UI / app:
- [x] `ChallengeAnswer` + screens for the new types: `updatePassword`, `verifyEmail`, `terms`, `recoveryCode` (`Phase2bReplayTests`, default screens, demo scenarios carol/grace/hank/ivy); `retry.remaining` shown
- [x] `KeycloakNativeUI`: `Localizable.xcstrings` (en, de), `.nativeLoginStrings(bundle:)` with fallback to the package catalogue, model tests of the default screens (`KeycloakNativeUITests`, 14 D7); a VoiceOver pass on hardware is still open
- [x] XCUITests for S4 (mailpit code via its API), S5/S13, S6 (TOTP computed in the test), S8, carol/grace/hank; S7 stays manual (Safari) (14 D7)
- [ ] Completion-handler / Combine variants of the async API (05 §2) if UIKit consumers need them
- [x] Protocol v1.0-rc freeze for all implemented types (03 §10.1, 14 D8); `push`, §7, `select`, §9 stay draft

### Phase 3 — Push MFA ✅ (server, SDK, app on the simulator; 14 D9, D10)
- [x] ba-itsys `keycloak-push-mfa-extension` 2.3.7 in the demo compose and ITs: rebuilt for Java 21 from its sources jar (`push-mfa-extension-java21`; the published jars target Java 25 and the Keycloak image runs 21; `@RunOnVirtualThread` dropped), realm browser flow `browser-push` (scenario A, `PushMfaIT.scenarioA…`)
- [x] `native-auth-push-apns`: `apns` sender (HTTP/2, provider-token auth, no third-party client), unit tests, fake APNs sink in the ITs
- [x] `/native-auth/push/enroll/start`, `native-push-enroll` (substitutes for `push-mfa-register`), `native-push` authenticator (scenario B, `action=resend` / `action=poll`, number match), metadata `push` block (`PushMfaIT`, 6 tests, transcripts)
- [x] Q6: token exchange is impossible for public clients in Keycloak 26.8 → the DPoP key is the device key and the native token the device token (03 §7.1, 14 D9); `DeviceTokenProvider` stays abstract
- [x] SDK `KeycloakNativePush` (enrol in-app / mid-flow, approvals with number match, APNs token sync, key rotation, lockout, notification-service helper), `PushApprovalsView` + push screens in the UI product, example app S9 / S10 / S12 / judy, `PushUITests` on the simulator, `LivePushTests`
- [ ] Upstream to ba-itsys (listed in 14 D10): `--release 21` build, programmatic enrolment service, the `apns` sender, a reusable challenge issuer for non-HTML authenticators
- [ ] Real APNs delivery and the notification service extension on a device (needs an Apple team; 14 "Left out")

### Phase 4 — Hardening & release
- [~] DPoP: binding at the challenge endpoint and metadata advertisement are done (13 D3); remaining: `DPoP-Nonce` support, and whether to make binding mandatory for native clients (`dpop.bound.access.tokens`) or let operators disable it
- [ ] Attestation-based client auth + `client_attestation_required`
- [ ] Rate limiting (`slow_down`), `NativeRiskEvaluator` SPI hook
- [ ] Custom event types, metrics (04 §9)
- [x] CI matrix: one build against 26.8.1, ITs on stock 26.8.1 / 26.6.4 / 26.4.5 (spec/16)
- [ ] CI: Keycloak nightly (allowed to fail); spotless
- [ ] Security review against 07 §10; load test; docs; Maven Central / SwiftPM release

### v1.0-rc additions from integrator feedback (15)
- [x] Optional required actions: `skippable` + `action=skip`, `NativeRequiredAction.isSkippable` / `processSkip`, `native-passkey` `enrol-optional`, SDK `.skip` + "Not now" (15 D1)
- [x] SDK `ChallengeAnswer.custom(type:fields:)` (15 D2)
- [x] `x_*` extension parameters: limits, client-note persistence, `NativeRequestContext.extensionParameter`, SDK `additionalParameters` / `continuationParameters` / `respond(_:to:additionalFields:)` (15 D3)
- [x] `native-auth.non-native-execution=redirect_to_web`, provider-id length warning, providers-directory note (15 D4)
- [x] `KeychainStore` access control (`SecAccessControl`, `LAContext`) and `Options.credentialsStore`, so the DPoP key reference is not gated by biometry (#6)
- [x] Root-level `Package.swift`, package identity `native-apps` (#5)
- [x] Licenses: Apache-2.0 for the SDKs, `spec/`, `docs/` and the transcripts (`LICENSE`, `NOTICE`); ELv2 for `keycloak-native-auth/` (`keycloak-native-auth/COPYING`), like the other Phase Two extensions (README "License"). First pre-release tag `0.1.0` (README "Releases"). Public distribution (a separate SDK repository, Maven Central) is still open
- [x] Keycloak 26.4 / 26.6 compatibility (`KeycloakCompat`, attestation trust anchors from the truststore) and a CI version matrix (#7, 16)

### Phase 5 — Android (post-v1)
- [ ] Kotlin port: plan and order of work in 17; step A1 (`AndroidOriginIT`) done (#8)
