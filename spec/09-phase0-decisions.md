# 09 — Phase 0 decisions (spike results)

**Date:** 14 October 2026
**Keycloak:** 26.8.1 (`quay.io/keycloak/keycloak:26.8.1`), Java 21
**Code:** `keycloak-native-auth/` (modules `native-auth-core`, `native-auth-endpoint`, `native-auth-authenticators`, `demo`)
**Evidence:** test names refer to `keycloak-native-auth/demo/src/test/java/io/phasetwo/keycloak/nativeauth/demo/NativeAuthIT.java` (run with `mvn verify`), the curl transcript is `demo/scripts/walkthrough.sh`. Keycloak source references are to the 26.8.0 tag of `keycloak/keycloak` unless noted.

This document answers the four "decide before Phase 0" questions of `08-roadmap-and-open-questions.md`
by prototype, lists where the implementation deviates from the earlier spec documents (and the
corresponding spec edits), and records the extension points left for later phases.

## Exit criteria status

| Criterion (08 Phase 0) | Status |
|---|---|
| Tokens obtained without a browser | ✅ `walkthrough.sh` and `happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri` |
| Events show in the admin console | ✅ `LOGIN` event with details `native_protocol=1`, `challenge_type`, `username`, `code_id`; followed by the standard `CODE_TO_TOKEN`. Asserted through the admin REST API in the same test. |
| Integration test green in CI with testcontainers | ✅ `.github/workflows/ci.yml` (`mvn verify`), plus a second job doing `docker compose up` + `walkthrough.sh` |
| Decision memo Q1, Q2 | ✅ below |
| Q6 (push device client secret) investigated | Deferred to Phase 3 as 08 allows; nothing in Phase 0 depends on it. |

---

## Q1 — Authorization code without `redirect_uri`

**Decision: option (a).** The code is stored with `redirectUriParam = null` and the token request
omits `redirect_uri`. This is the default of the config switch
`native-auth.code-redirect-uri-mode` (`none` | `sentinel` | `client-fixed`, realm attribute).

**Why it works (Keycloak 26.8 source).** `AuthorizationCodeGrantType.process()`
(`services/src/main/java/org/keycloak/protocol/oidc/grants/AuthorizationCodeGrantType.java`):

```java
String redirectUri = codeData.getRedirectUriParam();
String redirectUriParam = formParams.getFirst(OAuth2Constants.REDIRECT_URI);
...
if (redirectUri != null && !redirectUri.equals(redirectUriParam)) {
    ... throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "Incorrect redirect_uri", ...);
}
```

The comparison is guarded by `redirectUri != null`, so a code persisted with a null redirect URI
is exchanged without any redirect-URI check. Nothing else in the grant (`OAuth2CodeParser.parseCode`,
PKCE, DPoP `jkt`, client-policy hooks) looks at the redirect URI. There is one wrinkle on the
`KEYCLOAK-4478` compatibility branch a few lines earlier: if the client *does* send a
`redirect_uri` containing `session_state=` while the stored value is null, `redirectUri.contains(...)`
would NPE; native clients never send that, and metadata tells them not to send `redirect_uri` at all.

**Evidence.**
- `happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri` — mode `none`, token request without
  `redirect_uri` → 200 with access/refresh/id tokens; code single-use.
- `q1_noneModeAlsoToleratesAnyRedirectUriParameter` — side effect of storing null: a
  `redirect_uri` parameter, if sent, is ignored (documented, not relied upon).
- `q1_sentinelModeRejectsTokenRequestWithoutRedirectUri` and
  `q1_sentinelModeRoundTrip` — mode `sentinel`: omitting `redirect_uri` → `400 invalid_grant`
  ("Incorrect redirect_uri"), sending `urn:keycloak:native-auth` → 200. This proves the comparison
  is really skipped only for null, i.e. option (b) also works if an operator prefers a non-null value.
- `walkthrough.sh` step 5 reads `code_exchange.redirect_uri_required` from metadata and sends
  `redirect_uri` only when required.

**Implementation.** `CodeIssuer` (endpoint module) builds the `OAuth2Code` exactly as
`OIDCLoginProtocol.authenticated()` does for `response_type=code` and persists it with
`OAuth2CodeParser.persistCode`. `GET /native-auth/metadata` advertises the requirement as

```json
"code_exchange": { "redirect_uri_required": false }                      // mode none (default)
"code_exchange": { "redirect_uri_required": true, "redirect_uri": "urn:keycloak:native-auth" }   // mode sentinel
```

(`03-protocol-spec.md` §1.1/§3.1 updated accordingly.) Note that the client must still have
**Standard flow enabled** (`AuthorizationCodeGrantType` checks `client.isStandardFlowEnabled()`);
the endpoint refuses clients that do not.

---

## Q2 — Several ALTERNATIVE executions as one `challenges[]` set

**Decision: option (a) — no flow-engine wrapper needed.** The engine already computes the set of
eligible alternatives; we only had to surface it.

**How.** `DefaultAuthenticationFlow.processSingleFlowExecutionModel` (and `processAction`) calls
`AuthenticationSelectionResolver.createAuthenticationSelectionList(processor, model)` and passes
the result to the authenticator via `context.setAuthenticationSelections(...)`. That list is what the
browser theme renders as *Try another way*; it walks up to the highest useful sub-flow, includes
alternatives from nested sub-flows, filters credential-based authenticators by the user's stored
credential types and drops already-processed executions. `NativeAuthenticatorBase.buildChallengeSet`
iterates `context.getAuthenticationSelections()`, asks every sibling that implements
`NativeAuthenticator` to `describe()` itself, and puts all descriptors into the per-request
`ChallengeEnvelope`. The engine itself still "stops at the first challenge", but the first
challenge now carries the whole set.

**Routing the answer.** `AuthenticationProcessor.authenticationAction(execution)` rejects any
execution id that differs from the auth note `CURRENT_AUTHENTICATION_EXECUTION` ("page expired").
`ChallengeFlowDriver` therefore does not call it; it validates `challenge_id` against the ids it
issued (auth note `native-auth.pending`) and then calls
`processor.createFlowExecution(topFlowId, execution).processAction(challengeId)` directly, followed
by the same completion checks `authenticationAction` performs. `DefaultAuthenticationFlow.processAction`
→ `continueAuthenticationAfterSuccessfulAction` → `checkAndValidateParentFlow` marks the enclosing
ALTERNATIVE sub-flow successful when any alternative succeeds, so answering the *second* entry works
without touching the first.

**Evidence.**
- `q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered` — flow `native-alternatives`
  (password and TOTP as ALTERNATIVE siblings), user `alice`: after `username` the response has
  `challenges = [password, totp]`, both `required: false`, distinct ids; answering `totp` yields a
  code and tokens; after a wrong `totp` the set is re-issued (`[totp (error), password]`) and
  answering `password` yields a code.
- `q2_alternativesAreFilteredByConfiguredCredentials` — user `bob` (no OTP credential) is offered
  `[password]` only, `required: true`.
- The demo `native` flow (04 §7 layout) exercises the single-alternative-in-subflow and the
  CONDITIONAL second-factor sub-flow: `passwordOnlyUserSkipsConditionalSecondFactor`.

**Consequences / spec changes.**
- 04 §2.1 implementation note rewritten: the envelope is filled from `AuthenticationSelectionOption`s,
  not by "letting the flow visit siblings"; no custom `AuthenticationFlow`.
- `native-select` (R1 fallback) is **not needed** for the chooser; it stays optional for the
  "avoid side effects before the user picks" case (e.g. SMS cost) as 03 §4.9 already says.
- `describe()` of a sibling runs in the same request as the current execution's challenge, so
  factors with per-challenge state (passkey `challenge`, OTP send) must put that state into auth
  notes keyed by execution id and must be idempotent — recorded in the `NativeAuthenticator` javadoc.
- Ordering: the current execution first (the engine's choice: `CURRENT_AUTHENTICATION_EXECUTION`,
  else the first selection, which follows the user's credential preference order), then the
  remaining selections. **Superseded in Phase 1a** by flow order (11 D3): the set is sorted by the
  flow's depth-first execution order so a passkey placed first in the sub-flow is offered first.

---

## Q3 — Endpoint path

**Confirmed:** `RealmResourceProviderFactory` with id `native-auth` is served at
`/realms/{realm}/native-auth/*` (`RealmsResource.resolveRealmExtension`, `@Path("{realm}/{extension}")`).
`GET /realms/demo/native-auth/metadata` and `POST /realms/demo/native-auth/challenge` work on the
Quarkus distribution with a plain JAX-RS sub-resource returned from `getResource()`; form parameters
are read through `session.getContext().getHttpRequest().getDecodedFormParameters()` (the same way
Keycloak's token endpoint does) so authenticators see the same map. Metadata records both URLs.
Evidence: `metadataIsServedUnderRealmNativeAuthPath`, every other IT. Keycloak logs the expected
`KC-SERVICES0047 ... implementing the internal SPI realm-restapi-extension` warning; the SPI is
internal but stable since Keycloak 3.

Well-known `authorization_challenge_endpoint` override: not done in Phase 0 (optional per 03 §1).

---

## Q4 — Keycloak version

**Pinned: 26.8.1** (`keycloak.version` in the parent POM; same tag in `demo/docker-compose.yml`
and the Testcontainers image). Rationale:
- 08 set the floor at 26.8.x; 26.8.1 is the latest 26.8 patch on Maven Central / quay.io on
  2026-10-14 (26.8.0 → 26.8.1).
- The code compiles against the published 26.8.1 artifacts, not against the git checkout: the
  repository's `main` already differs (e.g. `LoginProtocol.authenticationComplete(authSession)`
  added for PAR single-use exists on `main`/nightly but **not** in 26.8.1). Keep CI on the released
  artifacts and add a `nightly` job later (04 §10) to catch such SPI drift early.
- Everything used is in `keycloak-services`/`server-spi-private` and is marked internal
  (`AuthenticationProcessor`, `DefaultAuthenticationFlow`, `OAuth2CodeParser`,
  `AuthenticationManager`, `ClientSessionCode`); all of it is confined to `ChallengeFlowDriver`
  and `CodeIssuer` (R2).

---

## Other decisions taken while building

| Topic | Decision | Where |
|---|---|---|
| `auth_session` encryption | `dir` + `A128GCM` under the realm's `aes-generated` key (`KeyUse.ENC`, `Algorithm.AES`), `kid` in the header; this is byte-for-byte the construction Keycloak uses for `KC_RESTART` (`RestartLoginCookie.encodeAndEncrypt` → `TokenUtil.jweDirectEncode`). `A256GCM` applies automatically when the key provider is configured with `secretSize=32`. 07 §3 said "A256GCM"; corrected to "AES-GCM with the realm key". | `AuthSessionCodec`, `RealmAuthSessionKeys`, unit tests `AuthSessionCodecTest` |
| `auth_session` lifetime | Login timeout (`accessCodeLifespanLogin`) enforced through `ClientSessionCode.isActionActive(LOGIN)` like the browser flow; every valid continuation refreshes the root session timestamp (`AuthenticationProcessor.checkClientSession` parity). `expires_in` is the remaining login timeout. | `expiredAuthSessionIsRejectedWithInvalidSession` (sets the realm's login timeout to 1 s via admin API) |
| Re-minting | A fresh `auth_session` (new `iat`) is returned on every challenge and on `invalid_request`; the client must replace its copy (03 §5). The post-login re-mint for step-up is **not** done in Phase 0 because nothing consumes it yet; the success body therefore omits `auth_session`. | `ChallengeFlowDriver.complete` |
| Invalid / tampered / cancelled `auth_session` | `400 invalid_session` without `auth_session`; `action=cancel` removes the authentication session and later use of the same value is rejected. | `invalidAuthSessionValuesAreRejectedWithInvalidSession`, `cancelledAuthSessionCannotBeReused` |
| Brute-force integration | Observed while writing the ITs: two deliberate failures for `alice` within Keycloak's `quickLoginCheckMilliSeconds` (1 s) locked the account for `minimumQuickLoginWaitSeconds` (60 s) and the username step then answered the generic error — i.e. `processor.logFailure` is reached through `FAILURE_CHALLENGE` exactly as for the browser flow. The tests pause 1.1 s before each deliberate failure instead of weakening the realm's brute-force settings. | `pauseForQuickLoginWindow` in `NativeAuthIT` |
| Unknown `challenge_id` / mismatched `challenge_type` | `400 invalid_request` with `auth_session` echoed; the session survives. Validation is done before touching the engine (the engine would throw `INTERNAL_ERROR`). | `unknownChallengeIdIsInvalidRequestAndSessionSurvives` |
| Terminal failures | `AuthenticationFlowException` → `403 access_denied` (`USER_DISABLED`, `USER_TEMPORARILY_DISABLED` = brute force, `CREDENTIAL_SETUP_REQUIRED`, `UNKNOWN_USER`), `EXPIRED_CODE`/`INVALID_CLIENT_SESSION` → `400 invalid_session`, `INTERNAL_ERROR` → `500 server_error`. The auth session is removed. | `ChallengeFlowDriver.failed` |
| Wrong credential | `FAILURE_CHALLENGE` with the same set re-issued and `error: {code: "invalid_credential"}` on the failed descriptor → counts as a brute-force failure via `processor.logFailure`. Empty input → `CHALLENGE` with `error.code=missing_credential`, no failure counted. | `wrongPasswordRechallengesWithErrorDescriptorThenSucceeds`, `wrongTotpRechallengesThenSucceeds`, `emptyPasswordRechallengesWithoutCountingAFailure` |
| Unknown username | Re-challenges `username` with the generic `invalid_credential` by default (`reveal-user-not-found=true` → `invalid_user`), after `AuthenticatorUtils.dummyHash`. Disabled or locked accounts behave the same at this step. **Limitation:** a valid username still advances to `password` while an unknown one does not, so existence is still observable; the "phantom password challenge" of 03 §4.1 is Phase 2 work. | `unknownUsernameRechallengesWithGenericError` |
| Required actions after the flow | `AuthenticationManager.nextRequiredAction` is consulted; if an action is pending the request ends with `403 access_denied` and `error_description=required_action:<alias> ...` and the session is removed. This is the marked extension point for native required actions (04 §4) and `RedirectToWebBuilder` (03 §3.4); neither is stubbed. | `pendingRequiredActionIsReportedAsAccessDenied` (user `carol`) |
| Non-native execution in the flow | If the processor returns anything but our marker response (e.g. a FreeMarker form), the endpoint answers `500 server_error` naming the problem in the log and removes the session (R8). | `ChallengeFlowDriver.challengeResponse` |
| Client checks | Client must exist, be enabled, be public, have standard flow enabled and carry `native-auth.enabled=true`; PKCE is enforced according to the client's `pkce.code.challenge.method`. | `missingOrUnknownClientIsRejected`, `pkceVerifierIsEnforced` |
| Events | `LOGIN` / `LOGIN_ERROR` with `native_protocol=1` and `challenge_type`; `CODE_TO_TOKEN` is Keycloak's. Custom event types (04 §9) later. | admin API check in the happy-path test |
| `challenge_types_supported` | Derived from installed `NativeAuthenticatorFactory`s (`username`, `password`, `totp` today), sorted. `dpop_signing_alg_values_supported` is `[]` until DPoP binding is enforced; `client_attestation.required=false`. | `NativeAuthResource` |
| TOTP descriptor | In addition to `credential_labels`, `params.credentials = [{id,label}]` so a client can send `credential_id`; 03 §4.5 updated. | `NativeTotpAuthenticator.describe` |
| Demo realm | `otpPolicyCodeReusable=true` only so tests/walkthrough can log in repeatedly within one TOTP period; documented in the README. | `demo/realm-export/demo-realm.json` |

## Spec edits made in this phase

- `03-protocol-spec.md`: §1.1 metadata gains `code_exchange`; §3.1 implementation note resolved
  (points here); §4.5 adds `params.credentials`.
- `04-keycloak-extensions-plan.md`: §2.1 implementation note replaced with the selection-list
  mechanism; §2.2 records the default `none` and the metadata field.
- `07-security-considerations.md`: §3 AES-GCM wording.
- `08-roadmap-and-open-questions.md`: Q1–Q4 marked answered with pointers here.
- `00-README.md`: this document added to the index.

## Extension points left for later phases (not stubs)

| Spec item | Where it plugs in |
|---|---|
| Passkey (`native-passkey`), recovery codes, OTP, push authenticators | implement `NativeAuthenticator` (`describe` + `action`), register the factory; the endpoint and base class need no change |
| Native required actions / `redirect_to_web` | `CodeIssuer.complete` returns `pendingRequiredAction`; replace the `access_denied` branch in `ChallengeFlowDriver.complete` |
| Step-up / `auth_session` after login | `ChallengeFlowDriver.complete` (post-login re-mint) and `resume` (claims pointing at a user session); `acr_values` is already stored as a client note |
| DPoP binding | `AuthSessionClaims.jkt` and `OAuth2Code.dpopJkt` are plumbed but always null; validate the proof in `ChallengeFlowDriver.handle` |
| Well-known `authorization_challenge_endpoint` | optional `OIDCWellKnownProviderFactory` override (04 §2.3) |
| Rate limiting / risk hooks | `ChallengeFlowDriver.start`/`resume` before the processor runs |
