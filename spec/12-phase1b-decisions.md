# 12 — Phase 1b decisions (iOS SDK core + example app)

**Date:** 14 October 2026
**Keycloak:** 26.8.1 (unchanged)
**Code:** `ios/KeycloakNative/` (Swift package, product `KeycloakNativeCore`), `ios/KeycloakNativeDemo/`
(example app), `keycloak-native-auth/demo/` (transcript recorder, new ITs, user `erin`, fixtures)
**Evidence:** `ios/KeycloakNative/Tests/KeycloakNativeCoreTests/*` (65 unit tests replaying the
recorded transcripts, plus 4 live tests), `keycloak-native-auth/demo/src/test/java/.../NativeAuthIT.java`
(21) and `PasskeyIT.java` (8).

This memo records what was decided while implementing the Phase 1b block of
`10-status-and-task-list.md`. Phase 0/1a decisions (09, 11) are not reopened.

## Development environment constraint (read first)

The Mac used for this phase has only the Command Line Tools: no Xcode, hence **no iOS SDK, no
simulator, no XCTest/Testing module** in the toolchain. Consequences, all recorded so nobody wastes
time rediscovering them:

- The package declares `platforms: [.iOS(.v17), .macOS(.v14)]` and Core compiles on macOS
  (`AuthenticationServices`, CryptoKit and the Secure Enclave API exist there). **Everything was
  verified on macOS**, including real logins against the compose stack; nothing was run on an iOS
  simulator or device (see "Left out").
- `swift test` uses Swift Testing (`import Testing`). On an Xcode-equipped Mac or CI runner the
  toolchain's module is used. On a CLT-only Mac, `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1` makes
  `Package.swift` add Apple's `swift-testing` **6.2.4** as a test-only dependency (6.4.1 links
  against a toolchain-private library and fails) and `--build-system native` is required because the
  CLT's default build system fails with "Unknown error parsing property list". The library product
  stays dependency-free.
- SwiftUI's `@State` is a macro in the current SDK whose plugin ships only with Xcode; the example
  app's root view keeps a plain reference to the `@Observable` model instead so the app package
  type-checks with `swift build` here.
- The Xcode project is generated with XcodeGen from `project.yml` and committed; it could not be
  built or launched here.

## D1 — Fixture format: one JSON transcript per integration test, masked form fields, verbatim bodies

`TranscriptRecorder` (a RestAssured `Filter` + JUnit 5 extension) records every request/response
with the native-auth and OIDC token endpoints into `demo/target/transcripts/<Test>.<method>.json`;
`scripts/update-transcripts.sh` copies them to the committed `demo/transcripts/` (format documented
in its `README.md`). Decisions:

- **Masked**: form fields `password`, `totp`, `otp`, `recovery_code`, `code_verifier`,
  `client_secret`, `refresh_token`, `token`; the `Authorization` and `DPoP` request headers
  (scheme kept: `Bearer ***`). **Verbatim**: JSON request/response bodies, so `auth_session`, codes
  and tokens appear — they are JWE/JWT values under a test container's keys and are inert. A secret
  scanner may still flag the JWTs; if that becomes a problem the curation script is the place to
  strip `access_token`/`id_token` values.
- Admin API calls the tests make are not recorded; they are not part of the contract.
- Per-run values (`code_challenge`, challenge ids, WebAuthn material) differ between recordings. The
  SDK's `MockTransport` compares method, path, the exact form field **set**, and values except for
  masked fields and `code_challenge`/`device_id`; WebAuthn fields match exactly because the tests
  replay the recorded assertion/attestation through `MockPasskeyPlatform`. The matcher is strict on
  extra fields: the SDK must send exactly what the integration test sent (it does, including
  `device_name`).
- `PasskeyIT` registers alice's passkey in `@BeforeAll` under its own transcript
  (`PasskeyIT.setupAlicePasskey`) so no test's transcript depends on ordering, and sends the bearer
  token as an explicit header so the transcript shows it.
- New server-side material for the SDK: `NativeAuthIT.tokensCanBeRefreshedLoggedOutAndRevoked`
  (refresh, RP-initiated logout, RFC 7009 revocation) and
  `bruteForceLockEndsWithAccessDenied` (S14). The demo realm gained user **`erin`** (brute-force
  demo) and `failureFactor` **5** (was 30) so S14 is reachable by hand; the integration tests' single
  deliberate failures per test are unaffected because every one is followed by a successful login,
  which resets Keycloak's counter.

## D2 — DPoP: Keycloak 26.8.1 binds tokens as soon as the SDK sends a proof

The task said "send proofs on challenge and token requests from day one; the server ignores them
until Phase 4". That is true for the **challenge endpoint** (no `auth_session`/code binding;
metadata advertises `dpop_signing_alg_values_supported: []`). It is **not** true for the **token
endpoint**: Keycloak's built-in DPoP support (feature `dpop`, enabled by default in 26.x) validates
an unsolicited `DPoP` header on `grant_type=authorization_code` and `refresh_token` and binds the
tokens — the live test prints `token_type=DPoP dpop_bound=true` against the compose stack. The SDK
therefore:

- reads `token_type` from the token response; `Credentials.authorizationScheme` is `DPoP` when
  bound, else `Bearer`;
- sends `Authorization: DPoP <token>` **plus** a proof with `ath` on the registration endpoints when
  the token is bound (`PasskeyRegistrationDriver` uses `AppAuthManager.BearerTokenAuthenticator`,
  which enforces the `cnf.jkt` binding; verified live: options/finish accept it), and plain `Bearer`
  otherwise;
- sends a proof on every token request (exchange, refresh) with the same key, keeps the key in the
  Keychain (`SecureEnclave.P256` data representation or the software key's raw bytes) under
  `<issuer>|<client>|dpop-key`, and retries once with the server's `DPoP-Nonce` on `use_dpop_nonce`;
- `revoke` and `logout` are sent without a proof (Keycloak does not require one there; verified).

`DPoPMode.automatic` (default) uses the Secure Enclave when available and a CryptoKit software key
otherwise (simulators, CI); `.disabled` sends nothing. spec/03 §8 gained a note that token binding
happens today while session/code binding is Phase 4; spec/10's Phase 4 item is narrowed to the
challenge endpoint.

Consequence for the SDK's own transcripts: the recorded token responses are `Bearer` (RestAssured
sends no proof), so the replay tests prove the `Bearer` path and the live tests prove the `DPoP` path.

## D3 — RP ID rule and the development-time strategy

- **Rule (`Passkeys.checkRpId`)**: the descriptor's `rp_id` must equal the issuer host or be a
  registrable parent of it (`example.com` for `idp.example.com`). Anything else throws
  `rp_id_mismatch` before the platform sheet is shown, unless `Options.allowRpIdMismatch` is set
  (logged as a warning). Rationale: the OS only honours an Associated Domain that the app declares,
  and a policy RP ID unrelated to the issuer is almost always a misconfiguration; the override exists
  for the one legitimate case (issuer on `localhost`, policy RP ID on a tunnel host while developing).
- **Dev-time strategy (06 §3)**: a tunnel with a **fixed hostname** (`ngrok --domain`,
  `cloudflared tunnel --hostname`) plus `webcredentials:<host>?mode=developer` in the entitlements.
  The AASA file must be served by the RP ID host, which Keycloak does not do; the example app README
  documents a Caddy front that answers `/.well-known/apple-app-site-association` and proxies the rest.
  The Passwordless policy's RP ID is set to the tunnel host; extra origins are only needed when the
  tunnel host is not Keycloak's public base URL. `?mode=developer` with a local HTTPS host was
  rejected: `localhost` cannot carry an AASA file for the simulator without a certificate dance, and
  the tunnel setup is the same one a QA device needs anyway.
- The demo realm keeps RP ID `localhost`; the SDK's live tests sign `origin = http://localhost:8089`
  with the software authenticator, exactly as `PasskeyIT` does.

## D4 — Public API shape (deviations from 05)

- `FlowStep` has two cases, `.challenges([Challenge], FlowContext)` and `.authorized(Credentials)`.
  `.redirectToWeb` is **not** declared: `WebFallback` is Phase 2 and a case nobody can handle would be
  a stub. A `redirect_to_web` answer surfaces as `NativeAuthError(code: "redirect_to_web")` with the
  body in `details`.
- `ChallengeAnswer` covers `username`, `password`, `totp(credentialId:)`, `passkey`,
  `passkeyRegistration(label:)`; `otp`, `push`, `recoveryCode`, `select` are marked extension points.
  Unknown types decode as `ChallengeType.unknown(String)` and stay in the set
  (`FlowStep.supportedChallenges` filters).
- `Authentication.stepUp` / `continueAfterTokenChallenge` are not offered (the server answers
  `invalid_session`, 11 D4). The post-login `auth_session` is stored in `Credentials.authSession`
  and survives refreshes; the SDK never sends it.
- One error type everywhere, `NativeAuthError`, with server codes passed through and SDK codes
  `network_error`, `invalid_response`, `metadata_unavailable`, `unsupported_challenge`, `flow_state`,
  `passkey_cancelled`, `passkey_failed`, `passkey_unavailable`, `rp_id_mismatch`,
  `credentials_not_found`, `reauthentication_required`, `keychain_error`, `dpop_key_error`.
  `CredentialsManager.credentials()` maps a refused refresh to `reauthentication_required`
  (clearing storage on `invalid_grant`, keeping it and carrying `authSession` on
  `insufficient_authorization` for the Phase 2 step-up).
- `NativeLoginFlow` is an actor; after `invalid_session`, `access_denied`, `invalid_client`,
  `server_error` or `redirect_to_web` it is finished (the server removed the authentication session);
  after `invalid_request` it keeps going with the fresh `auth_session` from the error body.
  `cancel()` sends `action=cancel` and treats the server's `invalid_session` answer as success.
- `passkey_cancelled` never changes the flow state: the pending set stays and the app can answer
  another alternative (tested).
- The passkey bridge resolves credentials to `Sendable` value types inside the delegate callback and
  resumes a lock-protected continuation, so no assumption about the delegate's thread is made;
  `presentationAnchor` defaults to the key window on iOS and the key window on macOS.
- `FlowObserver`/`FlowLogEntry`: the SDK hands apps a redacted record of every exchange (the
  Diagnostics log). Redaction (`Redactor`) masks `auth_session`, codes, verifiers, tokens, passwords,
  OTPs, recovery codes, WebAuthn assertion/attestation material and the `Authorization`/`DPoP`
  headers; a test asserts the log never contains the secrets of a round trip.
- Form encoding uses the RFC 3986 unreserved set (`%20` for spaces); Keycloak decodes both forms.

## D5 — Example app without the UI product

Scope was Core only, so the app renders `FlowStep` itself (05 §4 "full control"): one section per
challenge in server order, errors from the descriptor, a passkey button, the mid-flow registration
form, and an "unsupported type" notice. `DemoModel` (`@MainActor @Observable`) owns one
`KeycloakNative` per client (`demo-ios`, `demo-ios-passkey`), the flow log and the stored
credentials; S14 is automated (wrong passwords until `access_denied`). No Settings bundle, no
`DemoAPIClient`/resource server (S6 is Phase 2).

## Spec edits made in this phase

- `03-protocol-spec.md` §8: note that the token endpoint already binds tokens to a presented DPoP
  key (Keycloak's own support), while `auth_session`/code binding stays future work.
- `05-ios-sdk-plan.md`: §7 testing now names Swift Testing and the transcript fixtures; macOS 14 is a
  supported platform of Core.
- `10-status-and-task-list.md`: Phase 1b items ticked, limitations added.
- `00-README.md`: this document.

## Verified (how)

| What | How |
|---|---|
| 29 integration tests, 15 unit tests (Java) | `mvn verify` (Docker), 4 runs during the phase |
| compose stack + `walkthrough.sh` | `KC_PORT=8089 docker compose up --wait && KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh` → exit 0 |
| 65 SDK unit tests | `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` on macOS 26.6 / Swift 6.4 |
| 4 live SDK tests (S3 + refresh/revoke, S11 → S1 → S2 + wrong key, dave enrolment, S14) | same command with `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089`, real `URLSessionTransport`, software DPoP key, software WebAuthn authenticator |
| Example app package | `swift build` (macOS) of `ios/KeycloakNativeDemo`; `xcodegen generate` |

## Left out (honest list)

- **Nothing was run on an iOS simulator or device**: no Xcode on this machine. Untested paths are the
  real `ASAuthorizationController` ceremony (assertion with allow-list/discoverable, registration,
  cancellation mapping), the Secure Enclave key on hardware (the software fallback ran), the Keychain
  store on iOS (the in-memory store ran; the `SecItem` code compiled only), and the app's UI.
- The Xcode project has not been opened; `project.yml` may need small adjustments on first open.
- Completion-handler and Combine variants of the async API (05 §2) were not generated.
- `KeycloakNativeUI`, `KeycloakNativePush`, `WebFallback`, step-up, `otp`/`push`/`recovery_code`/
  `select` answers: later phases, marked in code.
- Protocol v1.0-rc freeze (10 "Spec") not done: the fixtures are the conformance evidence, the
  version string is unchanged.
