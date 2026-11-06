# 11 — Phase 1a decisions (passkeys on the server)

**Date:** 14 October 2026
**Keycloak:** 26.8.1 (unchanged, see 09 Q4)
**Code:** `keycloak-native-auth/` — new module `native-auth-required-actions`; changes in `native-auth-core`, `native-auth-authenticators`, `native-auth-endpoint`, `demo`
**Evidence:** test names refer to `demo/src/test/java/io/phasetwo/keycloak/nativeauth/demo/PasskeyIT.java` and `NativeAuthIT.java` (run with `mvn verify`); 27 integration tests, 15 unit tests.

This memo records the decisions taken while implementing the "Phase 1 — Server" block of
`10-status-and-task-list.md`: the `native-passkey` authenticator, the `native-passkey-register`
required action, the authenticated registration endpoints, the metadata block and the post-login
`auth_session`. Phase 0 decisions (09) are not reopened; where a consequence of one changed, it is
called out below.

## Classes allowed to use Keycloak-internal APIs (08 R2)

| Class (module `native-auth-endpoint`) | Internal API used | Why |
|---|---|---|
| `ChallengeFlowDriver` (existing) | `AuthenticationProcessor`, `DefaultAuthenticationFlow`, `ClientSessionCode`, `AuthenticationSessionManager` | drives the flow; now also loops over native required actions and mints the post-login `auth_session` |
| `CodeIssuer` (existing) | `AuthenticationManager.nextRequiredAction/attachSession/logSuccess`, `OAuth2CodeParser`, `AcrStore` | issues the code; now returns the user session id |
| **`RequiredActionDriver`** (new) | `RequiredActionContextResult`, `AuthenticationManager.createRequiredAction/setKcActionStatus`, `AuthenticationProcessor.CURRENT_*` notes, `LoginActionsService.REQUIRED_ACTION` | runs a native required action's `requiredActionChallenge`/`processAction` without a browser (D1) |
| **`PasskeyRegistrationDriver`** (new) | `AppAuthManager.BearerTokenAuthenticator`, `AuthenticationManager.AUTH_TIME`, `SingleUseObjectProvider` | the bearer-authenticated `/passkey/register/*` endpoints (D5) |

Outside these four, the WebAuthn code (`NativePasskeyAuthenticator`, `PasskeyRegistrationOptions`,
`PasskeyRegistrationVerifier`, `NativePasskeyRegisterRequiredAction`) uses only what Keycloak's own
authenticators use: `WebAuthnCredentialProvider`/`WebAuthnCredentialModelInput`, `WebAuthnPolicy`,
`KeycloakTrustAnchorRepository` and webauthn4j 0.30.3 (the version `keycloak-services` 26.8.1 ships).

---

## D1 — Native required actions run in-band; `challenge_id` is the provider id

**Problem.** After the flow succeeds, `AuthenticationManager.nextRequiredAction` names the next
required action by alias. Keycloak's browser flow then redirects to `/login-actions/required-action`
with a session code; the native endpoint has no redirect and no session code, and the client must be
able to answer the action's challenge through the same `POST /native-auth/challenge`.

**Decision.**
- A native required action implements `NativeRequiredAction` (`RequiredActionProvider` + `challengeType()`)
  and its factory `NativeRequiredActionFactory` (marker, also feeds `challenge_types_supported`). Its
  `requiredActionChallenge` fills the per-request `ChallengeEnvelope` with exactly one descriptor and
  hands the marker response to `context.challenge()`, like the authenticators do.
- `ChallengeFlowDriver.complete` loops: `CodeIssuer.complete` → alias pending? → if the alias' provider
  is a `NativeRequiredActionFactory`, `RequiredActionDriver.challenge()` runs it; `CHALLENGE` → the
  403 envelope is returned, `SUCCESS` (nothing to ask) → re-evaluate, `FAILURE` → `403 access_denied`.
  Non-native actions keep the Phase 0 behaviour (`403 access_denied`, `required_action:<alias>`),
  which is where `redirect_to_web` plugs in later (03 §3.4).
- **Routing.** The descriptor's `id` (= `challenge_id`) is the required action's **provider id**
  (e.g. `native-passkey-register`); there is no execution id for a required action and provider ids
  cannot collide with execution UUIDs. The endpoint records it in the auth notes
  `native-auth.pending` (`{providerId: type}`, same validation as execution ids) and
  `native-auth.required-action`. While an action is pending the authentication session is in
  `Action.REQUIRED_ACTIONS` with `CURRENT_FLOW_PATH=required-action` and
  `CURRENT_AUTHENTICATION_EXECUTION=<providerId>`, exactly what
  `AuthenticationManager.redirectToRequiredActions` sets for the browser; `resume()` accepts that
  state (in addition to `AUTHENTICATE`) and dispatches to `RequiredActionDriver.processAction`,
  reproducing the state changes of `LoginActionsService.processRequireAction` (`LAST_PROCESSED_EXECUTION`,
  removal from user + session on success, `KcActionStatus`).
- Timeouts follow `SessionCodeChecks`: login timeout while authenticating, **user-action timeout**
  (`accessCodeLifespanUserAction`) while a required action is pending; `expires_in` reflects it.
- A native required action that calls `ignore()` is treated as a failure (logged). Reason:
  `nextRequiredAction` has no "ignored actions" parameter, so the same action would be returned
  again; Keycloak's own loop carries that set privately. None of our actions ignore in a native
  session; outside one (browser login) `native-passkey-register` ignores itself with a warning so it
  never renders a page there, and stays on the user.
- Required actions are addressed by **alias** in the realm (`RequiredActionProviderModel`), dispatched
  by **provider id**; `ChallengeFlowDriver.providerIdOf` resolves one to the other.

**Realm import caveat.** `RealmManager.setupRequiredActions` seeds Keycloak's default required actions
only when the realm has none, so an export that lists `requiredActions` must list them all. The demo
export now carries the 26.8 defaults (same aliases and priorities as `DefaultRequiredActions`) plus
`native-passkey-register` (priority 140, enabled, not default).

**Evidence.** `requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks` (user `dave`:
password → `passkey_registration` with `id=native-passkey-register`, bad attestation →
re-challenge with `error.code=invalid_attestation`, good one → `200` code + `auth_session`, action
removed, next login offers the passkey), `pendingRequiredActionIsReportedAsAccessDenied` (carol,
`UPDATE_PASSWORD` still `access_denied`).

## D2 — `native-passkey`: discoverable when no user, offered only when configured otherwise

- `requiresUser()` is `false` and the authenticator implements `CredentialValidator` for
  `webauthn-passwordless`. Consequences in the engine: `DefaultAuthenticationFlow` never consults
  `configuredFor` for it (so it can run before a user is known), and `AuthenticationSelectionResolver`
  lists it for a known user only if that user has a `webauthn-passwordless` credential, and for an
  unknown user because it does not require one (the "userless credential-based" branch).
- `authenticate()`: when a user is already identified and has no passkey, the execution is marked
  `attempted` so the engine goes on to the next ALTERNATIVE (password). Otherwise the challenge set is
  built as usual. `NativeAuthenticatorBase.buildChallengeSet` was changed accordingly: a sibling is
  eligible when `user == null ? !requiresUser() : configuredFor(user)` (the previous rule only looked
  at `requiresUser()`); username/password are unaffected (`configuredFor` is `true`).
- Descriptor (03 §4.3): `challenge`, `rp_id` (policy RP ID, else the base URI host), `timeout`
  (policy create timeout × 1000, default 60000 ms), `user_verification` (policy, `preferred` when
  "not specified"), `allow_credentials` (`{type, id, transports}` from the user's passwordless
  credentials; `id` converted from Keycloak's standard-base64 storage to base64url), `discoverable`
  = `allow_credentials` empty. `extensions` is omitted.
- Per-execution challenge: generated once per request (KeycloakSession attribute) and stored in the
  auth note `native-auth.passkey.challenge.<executionId>`, so `describe()` stays idempotent within one
  request (09 Q2 requirement) while every new challenge set gets a fresh value; `action()` consumes
  the note single-use. A replay of a previous challenge value fails
  (`wrongSignatureRechallengesWithInvalidCredential`).
- `action()`: missing/undecodable fields → re-challenge `missing_credential` (no failure counted);
  `user_handle` selects the user (`base64url(userId)` as Keycloak registers it) and must match an
  already identified user (`USER_CONFLICT` → `access_denied` otherwise); validation through
  `user.credentialManager().isValid(WebAuthnCredentialModelInput)` → `WebAuthnPasswordlessCredentialProvider`
  (origin incl. policy extra origins, RP ID hash, UV flag per policy, signature, counter); any failure
  → `failAndRechallenge("invalid_credential")` which counts as a brute-force failure.
- **Origin.** Keycloak derives the expected origin from the request base URI
  (`http(s)://host[:port]`), plus the policy's *extra origins*. An iOS client signs
  `clientDataJSON.origin = https://<rp_id>`; when Keycloak's public base URI differs from that (port,
  proxy host), add `https://<rp_id>` to the Passwordless policy's extra origins. Documented in the README.
- Demo flow `native-passkey-first` (client `demo-native-passkey`) shows the username-less case: a
  REQUIRED subflow with `native-passkey` ALTERNATIVE and a `username → password` subflow ALTERNATIVE,
  then the conditional second factor. The first set is `[passkey (discoverable), username]`; either
  can be answered.

**Evidence.** `allowListLoginAfterUsernameOffersPasskeyAndPassword` (alice after registration:
`[passkey, password]`, `allow_credentials` carries her credential ids with transports, assertion →
totp → code), `discoverableLoginWithUserHandle` (no user: `discoverable=true`, empty
`allow_credentials`, `user_handle` resolves alice; bob still logs in with username+password in the
same flow), `missingAssertionFieldsRechallengeWithoutCountingAFailure`,
`wrongSignatureRechallengesWithInvalidCredential`.

## D3 — Challenge sets are ordered by the flow layout, not by the engine's pick

09 Q2 said: "the current execution first (the engine's choice: … the first selection, which follows
the user's credential preference order), then the remaining selections". With passkeys that puts a
newly registered passkey *after* the password for every existing user (the engine orders alternatives
by the user's stored-credential priority), which defeats the purpose of putting `native-passkey` first
in the flow. `NativeAuthenticatorBase.buildChallengeSet` now sorts the set by the depth-first
execution order of the top-level flow (executions by priority, sub-flows expanded in place); the
descriptor with `error` stays wherever the flow puts it. Routing is unaffected (any pending id can be
answered, 09 Q2). Operators therefore control the order through the flow; a user's credential
priority no longer changes it.

Consequence for the Phase 0 test: after a wrong TOTP in the `native-alternatives` flow the set is
`[password, totp (error)]` instead of `[totp (error), password]`
(`q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered` updated). 03 §3.2 "ordered by server
preference" now means flow order.

## D4 — Post-login `auth_session` (03 §5) is minted; `resume()` rejects it until step-up exists

- The success body carries `auth_session` again: a JWE with the **post-login shape**
  `{typ, ver, user_session_id, client_id, iat, exp}` where `exp = iat + ssoSessionMaxLifespan`
  (36 000 s in the demo). `AuthSessionClaims`/`AuthSessionCodec` accept either the in-flow shape
  (`root_session_id` + `tab_id`, lifetime enforced by the authentication session) or this one
  (`exp` enforced in `decode`); `isPostLogin()` distinguishes them
  (`postLoginShapeRoundTripsAndIsDistinguishable`, `expiredPostLoginTokenIsRejected`,
  `payloadWithNeitherShapeIsRejected`).
- `ChallengeFlowDriver.resume` answers `400 invalid_session` with
  `error_description = "auth_session belongs to a completed login; step-up … is not supported yet, start a new login"`
  when it decodes the post-login shape. This is the marked extension point for Phase 2 step-up
  (resume the user session, LoA conditions, new code); nothing pretends to work. Evidence:
  the end of `allowListLoginAfterUsernameOffersPasskeyAndPassword`.
- The SDK can therefore persist the value from day one (10 task "so the SDK can persist it now").

## D5 — Authenticated registration endpoints (03 §6)

- `POST /native-auth/passkey/register/options` and `/finish` live in `NativeAuthResource` and are
  driven by `PasskeyRegistrationDriver`. Authentication: `AppAuthManager.BearerTokenAuthenticator`
  (bearer or DPoP-bound access token of this realm; any client). Missing/invalid token →
  `401 {"error":"invalid_token"}` with `WWW-Authenticate: Bearer realm="…", error="invalid_token"`
  (`registrationEndpointsRequireABearerToken`).
- **Freshness rule (07 §5).** The age that matters is the *authentication*, not the token: the
  endpoint reads `AUTH_TIME` from the user session behind the token (set by `CodeIssuer`, falls back
  to the session start) and refuses when `now − auth_time > native-auth.passkey-registration-max-age`
  (realm attribute, default **300 s**, `0` disables). Access tokens in 26.8 do not carry `auth_time`
  unless a mapper adds it, and a refreshed token's `iat` says nothing about when the user proved
  anything, which is why the user session is used. Refusal: `403 {"error":"insufficient_authorization"}`
  with a description naming the limit, deliberately **without** `auth_session`/`challenges` — the
  re-authentication it asks for is a new login until step-up lands
  (`staleAuthenticationIsRefusedForRegistration`).
- `/options` → `200` with the §4.4 `params` plus `registration_id` (32-char random). The challenge and
  the user id are stored under `SingleUseObjectProvider` key
  `native-auth.passkey-registration-id:<registration_id>` for `accessCodeLifespanUserAction`.
  `/finish` takes a JSON body (`registration_id`, `credential_id`, `client_data_json`,
  `attestation_object`, `transports` as comma-separated string **or** JSON array, `label`), consumes
  the entry atomically (`remove`), checks it belongs to the calling user, verifies and stores through
  `PasskeyRegistrationVerifier`, and answers `201 {credential_id, label}`. Reuse of a
  `registration_id`, an unknown one, or a failed attestation → `400 invalid_request` with a
  user-safe description. Events: `UPDATE_CREDENTIAL` with `credential_type`, `credential_id`,
  `native_protocol=1`.
- Not restricted to native-enabled clients: a web client's fresh token may add a passkey too. If
  product wants to limit this, `PasskeyRegistrationDriver.authenticate` is the single place to
  check `auth.getClient()`.

**Evidence.** `registerThroughAuthenticatedEndpointsAfterPasswordTotpLogin` (options content,
`201`, credential visible in the admin API with its label, `registration_id` single use).

## D6 — Software authenticator for the tests: hand-written, no extra dependency

Choice recorded as the task asked. Neither `com.webauthn4j:webauthn4j-test` nor Yubico's test
utilities were adopted: webauthn4j's emulator package is not published as a separate artifact for
0.30.x, and `webauthn-server-core` would pull a second WebAuthn stack (plus Jackson/CBOR versions to
align) into the test classpath. A WebAuthn ceremony needs only an EC P-256 key pair, SHA-256,
DER-encoded ECDSA signatures and a handful of CBOR structures, all available in the JDK, so
`demo/src/test/.../SoftwareAuthenticator.java` (≈150 lines) plus `Cbor.java` (a 60-line RFC 8949
encoder for ints, strings, byte strings and maps) produce deterministic registrations (`fmt=none`,
AAGUID zero, UP+UV+AT flags, resident credential with the server-provided user handle, counter 0 like
Apple passkeys) and assertions (UP+UV, counter 0), including a "wrong key" variant. Origin is the
test's Keycloak base URL; RP ID is taken from the challenge params.

## D7 — Shared registration code lives in `native-auth-required-actions`

`PasskeyRegistrationOptions` (03 §4.4 params from the Passwordless policy: `rp`, `user` with
`id = base64url(userId)`, `pub_key_cred_params` via the same COSE mapping as Keycloak,
`authenticator_selection`, `attestation`, `exclude_credentials` when "avoid same authenticator" is on,
`timeout`) and `PasskeyRegistrationVerifier` (webauthn4j `WebAuthnRegistrationManager` with the same
verifier list, self-attestation rule, truststore-backed cert path verifier and AAGUID policy as
`WebAuthnRegister`; stores through `WebAuthnPasswordlessCredentialProvider`) are used by both the
required action and the endpoints. Rather than a fifth module, `native-auth-endpoint` depends on
`native-auth-required-actions` (module order in the parent POM: core → authenticators →
required-actions → endpoint → demo). `demo` copies all four provider JARs.

## Other decisions

| Topic | Decision |
|---|---|
| Descriptor error codes | `passkey`: `missing_credential`, `invalid_credential`. `passkey_registration`: `missing_credential`, **`invalid_attestation`** (new, 03 §4.4). |
| Metadata | `passkey` block always present (`rp_id` from the Passwordless policy or the base host, both registration endpoints); `challenge_types_supported` is the sorted union of native authenticator factories and native required-action factories → now `[passkey, passkey_registration, password, totp, username]`. |
| Demo realm policy | Passwordless: RP ID `localhost`, ES256+RS256, UV `required`, resident key `required`/`Yes`, attestation `none`, attachment not specified, extra origins empty. |
| Demo users | alice, bob, carol unchanged. **dave** (`dave-password`, required action `native-passkey-register`). The ITs register passkeys for alice (through §6) and dave (through the required action) inside the container; nothing is pre-registered in the export (a pre-registered credential would need its private key in the repo). |
| Phase 0 ITs | `NativeAuthIT` assertions on alice's primary-factor step became order-tolerant (`assertOffers`, `descriptor`, `errorCode`), because alice gains a passkey while `PasskeyIT` runs in the same container. |
| Keycloak 26.8.1 signatures | All used signatures were confirmed with `javap` against the 26.8.1 jars (`RequiredActionContextResult` 7-arg constructor, `AuthenticationManager.createRequiredAction/setKcActionStatus`, `AppAuthManager.BearerTokenAuthenticator`, `WebAuthnCredentialProvider.getCredentialModelFromCredentialInput/createCredential`, `WebAuthnRegistrationManager` 5-arg constructor, `KeycloakTrustAnchorRepository` public). |

## Spec edits made in this phase

- `03-protocol-spec.md`: §1.1 `passkey` block wording; §3.1 post-login `auth_session`; §3.2 ordering;
  §4.3 `discoverable`, error codes, origin note; §4.4 `challenge_id` = provider id, `invalid_attestation`;
  §6 statuses, freshness refusal, JSON body details.
- `04-keycloak-extensions-plan.md`: §2.1 required-action step resolved; §2.4 implemented details;
  §4 `native-passkey-register` behaviour outside native sessions.
- `10-status-and-task-list.md`: Phase 1 server items ticked, new limitations.
- `00-README.md`: this document added to the index.

## Left out (honest list)

- Step-up consumption of the post-login `auth_session` (Phase 2) — rejected with a clear message.
- `redirect_to_web` for non-native required actions (Phase 2) — still `403 access_denied`.
- `retry.remaining`, DPoP binding, rate limiting, attestation formats other than what the
  Passwordless policy allows (unchanged from Phase 0).
- A curl-only passkey walkthrough: a WebAuthn assertion cannot be produced with `openssl` one-liners;
  `demo/scripts/passkey-walkthrough.md` documents the HTTP sequence and points at the Java simulator.
