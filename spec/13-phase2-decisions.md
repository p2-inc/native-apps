# 13 — Phase 1c (device pass) and Phase 2 decisions (step-up, redirect-to-web, OTP, UI product)

**Date:** 14 October 2026
**Keycloak:** 26.8.1 (unchanged, 09 Q4)
**Code:** `keycloak-native-auth/` (endpoint, authenticators, new module `native-auth-otp-sender`, demo),
`ios/KeycloakNative/` (Core + new product `KeycloakNativeUI`), `ios/KeycloakNativeDemo/` (scenarios
S4–S8, S13, XCUITests), `keycloak-native-auth/demo/resource-server/`
**Evidence:** `StepUpIT` (5), `OtpIT` (3), `RedirectToWebIT` (1), `DPoPBindingIT` (4) plus the updated
`NativeAuthIT` (20) and `PasskeyIT` (8) — 41 integration tests, 15 unit tests; SDK: 80 tests
(`Phase2ReplayTests`, `TranscriptReplayTests`, …) in both toolchain modes plus 7 live tests;
`UITests/DemoAppUITests.swift` on the iOS 27 simulator (see "Phase 1c").

This memo records what was decided while implementing the Phase 1c and Phase 2 blocks of
`10-status-and-task-list.md`. Decisions of 09, 11 and 12 are not reopened.

## Phase 1c — device pass: what ran where

The build Mac gained **Xcode 27.0** (the 12 constraint "CLT only" no longer holds); the iOS 27.0
simulator runtime was downloaded (8 GB, `xcodebuild -downloadPlatform iOS`). There is still **no
physical iOS device and no signing identity / Apple team**, so the device-only items stay open
(below).

Verified on the **iPhone 18 Pro simulator (iOS 27.0)** with `UITests/DemoAppUITests.swift`
(XCUITest, real app, real compose stack on `:8089`): S3 (alice: password → TOTP computed from the
seeded secret), `token_type DPoP` with a software DPoP key (Diagnostics shows the `jkt`), the
Keychain `CredentialsManager` restoring the session across a relaunch, refresh, logout clearing the
Keychain (a second relaunch shows "not signed in"), and S14 (erin → `access_denied`). `swift test`
passes with Xcode's toolchain (and still in the from-source mode).

Findings that changed code:

- **The simulator Keychain needs a signed app.** With `CODE_SIGNING_ALLOWED=NO` every `SecItem` call
  answers `-34018` (missing entitlement); the SDK's `DPoPSigner` (key in the Keychain) then fails
  the very first request with `keychain_error`. Ad-hoc signing (`CODE_SIGN_IDENTITY="-"`, Xcode's
  "Sign to Run Locally") fixes it; `project.yml` generates an `Info.plist` for the UI test target so
  it can be signed too. The SDK keeps failing loudly rather than silently falling back to a memory
  key: an unsigned build is a build problem, not a runtime condition.
- The demo app did not restore stored credentials at launch; `DemoModel.restoreSession()` now runs
  from `RootView.task`, which is what the relaunch check needs.
- SwiftUI `Button`s with multi-line labels are not addressable by their title from XCUITest (the
  accessibility label concatenates the texts); the scenario rows, fields and status line carry
  explicit `accessibilityIdentifier`s.
- `project.yml` gained the `KeycloakNativeDemoUITests` target and an explicit scheme; the XcodeGen
  output opened and built without changes (no team is needed for the simulator).

Not verified (needs hardware or a tunnel + team): the real `ASAuthorizationController` ceremony
(S1, S2, S11, dave, the cancel path), the Secure Enclave key, Associated Domains behind a tunnel.
The passkey code path is still only exercised by the software authenticator (live tests) and the
mock platform (replay tests). Phase 1c's device items are carried in 10.

## Classes allowed to use Keycloak-internal APIs (08 R2)

In addition to 11's four: **`DPoPProofChecker`** (`DPoPUtil.Validator`,
`DPoPUtil.getDPoPSupportedAlgorithms`) and **`RedirectToWebBuilder`** (`ParEndpoint` constants and
`buildCacheKey`, `SessionExpiration.getAuthSessionLifespan`). `ChallengeFlowDriver` additionally
uses `AcrStore`, `AcrUtils`, `LoginProtocol.requireReauthentication` and
`AuthenticationManager.isSessionValid`. All signatures were checked against the 26.8.1 jars with
`javap` (the clone is nightly: e.g. `ParEndpoint.buildCacheKey(realmId, key)` exists in 26.8.1 and
is what `AuthzEndpointParParser` reads).

---

## D1 — Step-up re-enters the native flow the way `CookieAuthenticator` re-enters the browser flow

**Decision.** A §2.1 request carrying the **post-login** `auth_session` is a step-up
(`ChallengeFlowDriver.stepUp`). The driver resolves the user session named by the claims
(`invalid_session` when it has ended, the user is disabled, or the client differs), creates a new
authentication session with the §2.1 parameters, and pre-populates what Keycloak's
`CookieAuthenticator` would: `setAuthenticatedUser`, the `loa-map` auth note copied from the user
session, and the current level set to the highest still-valid level
(`AcrStore.getHighestAuthenticatedLevelFromPreviousAuthentication`), or `NO_LOA` plus
`FORCED_REAUTHENTICATION` when `LoginProtocol.requireReauthentication` says so (`prompt=login`,
`max_age` exceeded). `acr_values` is mapped to `requested-level-of-authentication` exactly as
`AuthorizationEndpoint` does (client/realm `acr.loa.map`, numeric fallback, minimum level for an
unknown non-numeric value) — for fresh logins too, which is new. The flow then runs from the top;
`native-username` calls `success()` when a user is already set, and the standard
`conditional-level-of-authentication` / `conditional-user-configured` conditions decide what is
asked. On completion `CodeIssuer.complete(authSession, existingUserSession)` attaches the existing
user session (same `sid`); when no factor ran (`factorAuthenticated` scans the execution statuses
for a successful native authenticator other than username) the auth note `SSO_AUTH` is set so
`AUTH_TIME` stays untouched, like the cookie-only branch. The success body carries a fresh post-login
`auth_session`.

**Why not a dedicated "SSO" authenticator.** The cookie authenticator works because it is an
ALTERNATIVE to the forms sub-flow; our flows put factors under REQUIRED/CONDITIONAL sub-flows, so
skipping has to come from the LoA conditions, not from an alternative. Pre-populating the session
and letting the engine run keeps every Keycloak rule (LoA, max-age, kc_action, forced re-auth)
intact and needs no engine wrapper (09 Q2 spirit).

**Consequences.**
- A flow without LoA conditions (`native`) re-runs every factor on a step-up and `acr` stays `1`
  (`stepUpOnAFlowWithoutLevelsRerunsEveryFactor`) — the same as Keycloak's browser behaviour. The
  demo therefore gained `native-step-up` (level 1 = primary factor, 10 h; level 2 = TOTP, max age
  0) bound to `demo-ios-stepup`, mirroring the step-up flow from Keycloak's documentation. A plain
  login on it yields `acr=1`, which is what makes S6 demonstrable (`acr_values=2` → only TOTP, same
  `sid`, `acr=2`; `acr_values=1` afterwards → immediate code, `auth_time` untouched; `max_age=0` →
  full re-authentication, `auth_time` moves). Evidence: `StepUpIT`.
- The §6 registration endpoints answer a stale token with `403 insufficient_authorization` **plus**
  a post-login `auth_session` (for the token's user session and client, bound to the token's
  `cnf.jkt`) and `max_age` = the realm limit; the client steps up with `max_age` and retries
  (`staleAuthenticationIsRefusedForRegistrationUntilAStepUpWithMaxAge`).
- A post-login `auth_session` sent as a continuation (with `challenge_type` / without
  `response_type`) is `invalid_request` with a message naming the step-up parameters.
- 03 §5 says a refresh MAY answer `insufficient_authorization` + `auth_session`; Keycloak's token
  endpoint has no hook for that and it was **not** implemented (it would need a custom grant). The
  SDK maps it anyway; S8 demonstrates the `invalid_grant` → `reauthentication_required` path.

## D2 — `redirect_to_web` is a server-stored PAR for the client, completed by a normal browser login

**Decision.** When `CodeIssuer.complete` finds a pending required action that is not a
`NativeRequiredActionFactory`, `RedirectToWebBuilder` stores a pushed authorization request under
the key Keycloak's own `ParEndpoint` uses (`par:<realmId>:<key>`, with `par.created.time`,
`par.client.id` and, for a DPoP-bound session, `par.dpop.proof.jkt`): the native flow's
`code_challenge`/method, `scope`, `nonce`, `acr_values`, `ui_locales`, `login_hint` = the
identified username, `redirect_uri` = the client attribute `native-auth.web-fallback-redirect-uri`
or its first registered redirect URI without a wildcard, and a 32-char `state`. The answer is `403
{error: redirect_to_web, request_uri, expires_in (= realm PAR lifespan, 60 s), redirect_uri, state,
reason: required_action:<alias>}`; the native authentication session is removed. The browser
performs a **full login** (the user re-enters credentials), completes the action on Keycloak's
pages, and is redirected to `redirect_uri` with `code` + `state`; the app exchanges the code with
its original `code_verifier` **and** `redirect_uri` (the code was issued by the browser flow, so
Keycloak checks it). Without PKCE or a usable redirect URI the answer stays `access_denied`.

**Why a full browser login rather than a hand-off of the native session.** Keycloak has no public
way to turn an authentication session into a browser session without a cookie, and the only
password-less alternatives (action tokens) would make the `request_uri` a bearer login link.
Requiring the browser login keeps the fallback exactly as strong as the browser flow and ties the
browser's code to the app through PKCE; the PAR also carries the DPoP thumbprint so a bound session
stays bound through the browser.

**Evidence.** `RedirectToWebIT` drives Keycloak's HTML forms with the JDK `HttpClient` (RestAssured's
and the JDK `CookieManager`'s cookie jars both mangle Keycloak's `Version=1` cookies into RFC 2965
form, so the test keeps a hand-rolled jar), checks `login_hint`, the required-action page, the
callback `state`/`code`, the exchange with the native verifier, single use of the `request_uri`
(second use: HTTP 400), and that carol's next native login succeeds; carol is restored afterwards.
`TranscriptRecorder` now records HTML responses as `body_omitted` (browser pages are not part of the
contract).

## D3 — DPoP: verify at the challenge endpoint and bind session, code and post-login session

**Decision.** `DPoPProofChecker.thumbprint` runs Keycloak's `DPoPUtil.Validator` on every challenge
request that carries a `DPoP` header (`typ`, `alg`, `jwk`, `htm`, `htu`, `iat` window, `jti`
replay; no `ath`, no nonce); an unverifiable proof is `400 invalid_dpop_proof` before anything else.
A proof on the **first** request is stored as the client note `dpop_jkt` of the authentication
session, which (a) `ChallengeFlowDriver.mint` puts into the in-flow `auth_session` claims — a
continuation with no proof or another key is `invalid_session` ("bound to a different DPoP key",
the wording 03 §3.5 already had) —, (b) `CodeIssuer` passes as `OAuth2Code.dpopJkt`, so Keycloak's
token endpoint refuses an exchange without the same key (`validateDPoPJkt`; note that a failed
exchange consumes the code), (c) `PostLoginAuthSession.mint` puts into the post-login claims, so a
step-up requires the same key, and (d) `RedirectToWebBuilder` forwards as `par.dpop.proof.jkt`. A
session started **without** a proof stays unbound (a later proof is verified but ignored);
`dpop_signing_alg_values_supported` now lists the realm's asymmetric algorithms. The task asked for
a decision on "step-up code vs DPoP-bound tokens": this is it — the post-login `auth_session` is
only usable with the key the tokens are bound to, and the step-up code is bound to it as well, so a
leaked `auth_session` cannot mint tokens.

**Consequences.** This closes most of the Phase 4 item "DPoP binding at the challenge endpoint";
what remains there is the policy switch (make bound tokens mandatory for native clients) and
nonces. The SDK was already sending proofs on every request with one key per instance (12 D2), so
nothing changed on the wire for it; `DPoPBindingIT` proves the binding with a test-side ES256
signer and the SDK replays its positive path. The recorded `NativeAuthIT`/`PasskeyIT` transcripts
stay unbound (RestAssured sends no proofs).

## D4 — OTP: `native-otp` with a `native-otp-sender` SPI, sent only when it is the single option

**Decision.** New module `native-auth-otp-sender` with the authenticator `native-otp` (config:
`channel`, `digits`, `ttl`, `resend-cooldown`, `max-attempts`), the SPI `native-otp-sender`
(`channel()`, `canSend`, `destinationMasked`, `send`) and two providers: `email` (realm SMTP through
`EmailSenderProvider`, no theme template needed) and `sms-webhook` (JDK `HttpClient` POST of
`{"to","message"}` to `--spi-native-otp-sender--sms-webhook--url`, optional bearer token, number from
a user attribute). The outstanding code lives salted-and-SHA-256-hashed in the auth note
`native-auth.otp.<executionId>` with `sentAt` and `attempts`.

**Side-effect rule (03 §4.6, 09 Q2).** `describe()` must be idempotent and is called for siblings,
so sending cannot happen there. `NativeAuthenticator` gained `prepare(context, execution,
descriptor, required)`, called by `NativeAuthenticatorBase.buildChallengeSet` once the set is
assembled: `native-otp` sends a code there only when `required` (single option) and nothing was
sent before in this session; otherwise the descriptor says `sent: false` and the client asks with
`action=resend` (also the "first send" verb — one verb keeps the protocol small). `resend` before
`resend_allowed_at` → `resend_too_soon` (no failure counted); a wrong code → `invalid_credential`
(brute-force failure); after `max-attempts` the code is invalidated → `expired_code` with
`sent: false`, and no code is sent unasked after that (only an explicit resend after the cooldown),
so an attacker cannot make the server burn SMS by failing. `configuredFor` (used by
`conditional-user-configured`) consults the realm-default channel because authenticator config is
not available there.

**Demo.** Flow `native-otp` (client `demo-ios-otp`): `[totp, otp]` for alice (nothing sent until she
picks), `[otp]` sent at once for bob; config 10 s cooldown / 3 attempts so the ITs stay short;
mailpit as the SMTP sink in compose and as a Testcontainers sibling on a shared network; `OtpIT`
reads codes from mailpit's API. The SMS webhook has no IT (it would need a host-side sink); it is
unit-level code only.

## D5 — SDK and UI product shape (deviations from 05)

- `Authentication.stepUp(_ parameters:authSession:)` is **async** (it reads the Keychain actor for
  the stored post-login session); `stepUp(acrValues:maxAge:scope:deviceName:)` is the convenience.
  `continueAfterTokenChallenge(_ error:)` builds the same flow from an error that carries
  `authSession` (+ `maxAge` from the §6 body). A step-up flow is an ordinary `NativeLoginFlow` with
  `stepUpSession` set; `start()` appends `auth_session` to the §2.1 fields. `NativeLoginFlow`'s
  constants are `nonisolated` so other modules can read `pkce` and `parameters`.
- `FlowStep.redirectToWeb(RedirectToWebRequest)` exists now (12 D4 had deferred it); the flow is
  finished after it. `WebFallback.complete(_:flow:)` (or `complete(_:codeVerifier:)`) opens
  `authorization_endpoint?client_id&request_uri` through a `WebAuthenticationPresenter` seam
  (`ASWebAuthenticationSessionPresenter` in production, a mock in tests), checks `state`, maps the
  callback `error`, and exchanges with the flow's verifier plus the request's `redirect_uri`
  (`Tokens.exchange` gained `redirectUri`). Cancelling the browser is `web_fallback_cancelled`,
  not a flow failure.
- `ChallengeAnswer.otp` / `.otpResend`, `OTPParams` (`sent`, `resendAllowedAt`,
  `resendWait(at:)`), descriptor codes `expired_code` / `resend_too_soon`; `ChallengeType.otp` is
  supported. `Redactor` masks `request_uri` as well.
- `KeycloakNative.resourceRequestHeaders(for:method:url:)` gives apps `Authorization: DPoP …` plus
  a proof with `ath` for bound tokens (S6 needs it against the resource server).
- `KeycloakNativeUI`: `NativeLoginView(kc:flow:theme:autoSelectPasskey:onResult:)` with a
  `NativeLoginModel` that starts the flow, shows the entry that just failed, else the previously
  shown type, else the first supported entry; `ChallengePresentationContext` (`submit`,
  `usePasskey`, `registerPasskey`, `switchTo`, `cancel`, `alternatives`); default screens for every
  supported type plus the browser fallback; `.challengePresenter(for:)` and `.challengeChooser`
  as SwiftUI environment overrides. No localisation catalogue yet (strings are English literals);
  no UI tests of the product itself beyond the demo app's S5/S13 screens.
- Replay fixtures: `Harness.replay(seqs:)` picks non-contiguous exchanges (the DPoP transcript's
  negative cases use other keys the SDK cannot reproduce); the step-up transcripts replay with the
  real post-login `auth_session` values, so the matcher stays strict.

## Other decisions

| Topic | Decision |
|---|---|
| `acr_values` on a fresh login | now mapped to the requested level too (`acrValuesOnAFreshLoginRequestsLevel2Directly`); before it was stored verbatim only |
| Resource server | `demo/resource-server/server.mjs` (Node 22, no deps, compose service on `:8091`): JWKS validation, DPoP proof check for bound tokens, `/transfer` → RFC 9470 `401 insufficient_user_authentication, acr_values="2"`, `/me` |
| Transcript curation | `update-transcripts.sh` copies everything in `target/transcripts`; stale files from renamed tests must be deleted by hand (done here for the carol and stale-registration tests) |
| CI | `ios-sdk` job also runs `xcodebuild build-for-testing` for the app + XCUITests on the simulator SDK (compile only; no Keycloak on the runner) |
| Not done (carried in 10) | refresh-triggered `insufficient_authorization`, native UPDATE_PASSWORD/VERIFY_EMAIL/TERMS, `native-recovery-code`, `native-select`, username phantom challenge / `retry.remaining`, "enrol on first login", well-known override, SMS webhook IT, localisation of the UI product, Combine/completion variants |

## Spec edits made in this phase

- `03-protocol-spec.md`: §1.1, §2.1, §3.1, §3.2, §3.4, §3.5, §4.6, §5, §6, §8, §11 (see the
  Phase 2 commit for the exact wording).
- `05-ios-sdk-plan.md`, `06-example-ios-app.md`: status lines (UI product exists; resource server done).
- `10-status-and-task-list.md`: Phase 1c and Phase 2 items ticked, limitations added, carried items.
- `00-README.md`: this document.

## Verified (how)

| What | How |
|---|---|
| 41 integration tests, 15 unit tests (Java) | `mvn verify` (Docker; Keycloak + mailpit containers), final run green |
| compose stack + `walkthrough.sh` | `KC_PORT=8089 docker compose up --wait && KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh` → exit 0 (with mailpit and the resource server up) |
| 80 SDK tests | `swift test` (Xcode 27 toolchain) and `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` |
| 7 live SDK tests (S3 + lifecycle, S11→S1→S2, dave, S14, **S6 against the resource server with a DPoP-bound token, S4 via mailpit, S7 redirect step**) | same with `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089` |
| Example app on the iOS 27 simulator | `xcodebuild test … CODE_SIGN_IDENTITY="-"`: S3, relaunch/refresh/logout, DPoP `jkt`, S14 (see "Phase 1c") |
| Example app package + UI product | `swift build` (macOS) of both packages; `xcodebuild build-for-testing` for the simulator SDK |

## Left out (honest list)

- No physical device: passkey ceremonies, Secure Enclave, Associated Domains, `excludedCredentials`
  on 17.4+ and the cancel path of the real sheet remain unverified (Phase 1c device items stay open).
- S4–S8 and S13 were exercised through the SDK's live tests and compiled into the app; the app
  screens for them were not driven by XCUITest (S7 needs Safari and a user; S6 needs the TOTP
  within the simulator UI — both are manual steps documented in the app README).
- Refresh-triggered re-authentication from the token endpoint is not emitted by Keycloak.
- The SMS webhook sender has no integration test.
- Protocol v1.0-rc freeze not done; the fixtures remain the conformance evidence.
