# 04 — Keycloak Extensions Plan (`keycloak-native-auth`)

Target: Keycloak **26.x** (confirm exact minor at kickoff; 26.4 is current in the Red Hat build). Java 21, Maven, Quarkus distribution, deployed as JARs in `providers/`.

## 1. Repository / module layout

```
keycloak-native-auth/
├── pom.xml                              (parent; keycloak.version property; spotless; failsafe)
├── native-auth-core/                    Protocol model + utilities (no Keycloak runtime deps beyond server-spi)
│   ├── model/      ChallengeDescriptor, ChallengeResponse, ChallengeType enum, ErrorRepresentation, Metadata
│   ├── session/    AuthSessionCodec (JWE encode/decode of {rootSessionId, tabId, clientId, iat, jkt})
│   └── json/       Jackson mixins; snake_case naming strategy
├── native-auth-endpoint/                RealmResourceProvider
│   ├── NativeAuthResourceProviderFactory  (id = "native-auth")
│   ├── NativeAuthResource                 JAX-RS: /metadata, /challenge, /passkey/register/*, /push/enroll/start
│   ├── ChallengeFlowDriver                creates/loads auth session, runs AuthenticationProcessor, maps outcomes
│   ├── CodeIssuer                         OAuth2Code minting (PKCE, nonce, scope, dpop_jkt)
│   ├── RedirectToWebBuilder               PAR request_uri creation for fallback
│   └── WellKnownOverride (optional)       OIDCWellKnownProviderFactory subclass adding authorization_challenge_endpoint
├── native-auth-authenticators/          One AuthenticatorFactory per challenge type
│   ├── NativeAuthenticatorBase            helpers: emitChallenge(ctx, descriptor), readForm(ctx), fail(ctx, code)
│   ├── NativeUsernameAuthenticator
│   ├── NativePasswordAuthenticator
│   ├── NativePasskeyAuthenticator         wraps WebAuthnCredentialProvider / webauthn4j
│   ├── NativeTotpAuthenticator            wraps OTPCredentialProvider
│   ├── NativeOtpAuthenticator             email/SMS code; uses NativeOtpSender SPI
│   ├── NativePushAuthenticator            bridges ba-itsys challenge store (scenario B)
│   ├── NativeRecoveryCodeAuthenticator
│   ├── NativeSelectAuthenticator (optional)
│   └── NativeRedirectToWebAuthenticator   terminal: raise redirect_to_web (used for unsupported cases)
├── native-auth-required-actions/
│   ├── NativePasskeyRegisterRequiredAction (JSON variant of webauthn-register-passwordless)
│   └── NativePushEnrollRequiredAction      (JSON variant of ba-itsys enrolment)
├── native-auth-otp-sender/              NativeOtpSender SPI + EmailOtpSender + LogOtpSender (+ SmsOtpSender adapters later)
├── native-auth-push-apns/               ba-itsys PushNotificationSender implementation for APNs (token-based auth, http/2)
├── native-auth-events/                  Event types + optional EventListener for audit enrichment
├── conformance/                         HTTP-level test-suite (JUnit 5 + REST Assured + webauthn4j test authenticator)
├── demo/
│   ├── docker-compose.yml               Keycloak + Postgres + mailpit + extensions + ba-itsys JAR
│   ├── realm-export/demo-realm.json     native flow pre-wired, demo-ios client, test users
│   └── scripts/                         curl walkthrough; passkey simulator; push simulator
└── docs/                                copies of 03-protocol-spec.md, admin setup guide
```

ba-itsys is a **dependency** (Maven Central artifact placed in `providers/`), not vendored.

## 2. `native-auth-endpoint` — the challenge endpoint

### 2.1 Request lifecycle (`ChallengeFlowDriver`)

```
POST /native-auth/challenge
  ├─ parse form; validate client (exists, public, attribute native-auth.enabled=true)
  ├─ optional DPoP: validate proof (Keycloak DPoP utils), compute jkt
  ├─ if auth_session present:
  │     decode JWE → (rootId, tabId, clientId, jkt) ; verify client/jkt match ; load AuthenticationSessionModel
  │     if not found/expired → invalid_session
  │   else:
  │     new RootAuthenticationSession + AuthenticationSession for client, protocol "openid-connect"
  │     copy OIDC params into client notes (scope, nonce, acr_values, max_age, code_challenge*, login_hint)
  │     clientNote NATIVE_AUTH=true ; authNote NATIVE_PROTOCOL_VERSION=1
  ├─ select flow: realm attribute native-auth.flow-alias (fallback: client override, then "native")
  ├─ build AuthenticationProcessor (session, realm, client, connection, uriInfo, headers, event, flowId)
  ├─ if challenge_type/challenge_id present: processor.setExecution(challenge_id); response = processor.action(...)
  │   else: response = processor.authenticate()
  ├─ outcome mapping:
  │     • Response with entity ChallengeEnvelope (set by our authenticators) → 403 insufficient_authorization + re-minted auth_session
  │     • processor finished (authSession has authenticated user, no pending required actions we can't serve)
  │         → AuthenticationManager.finishedRequiredActions / attach user session
  │         → CodeIssuer.issue() → 200 { authorization_code, auth_session(long-lived) }
  │     • required action pending:
  │         - native RequiredActionProvider (NativeRequiredActionFactory) → RequiredActionDriver runs it;
  │           challenge_id = provider id; session in Action.REQUIRED_ACTIONS (spec/11 D1)   [Phase 1 ✅]
  │         - else → RedirectToWebBuilder → 403 redirect_to_web (reason = required_action:<alias>)  [Phase 2; today 403 access_denied]
  │     • AuthenticationFlowException / FAILURE → 403 access_denied or re-challenge with error (depending on error code)
  └─ events: LOGIN / LOGIN_ERROR with detail native=true, challenge_type
```

Implementation notes
- Reuse `AuthenticationProcessor` and `DefaultAuthenticationFlow` as-is (resolved in Phase 0, see 09 Q2). The engine hands every authenticator the list of currently eligible ALTERNATIVE executions through `AuthenticationFlowContext.getAuthenticationSelections()` (the "Try another way" list, computed by `AuthenticationSelectionResolver` across sub-flows and filtered by the user's credentials). `NativeAuthenticatorBase` asks each sibling that implements `NativeAuthenticator` to `describe()` itself and puts all descriptors into the per-request `ChallengeEnvelope` (a `KeycloakSession` attribute); the authenticator then returns the marker response via `context.challenge()`. No custom `AuthenticationFlow` is needed. Continuations are routed with `processor.createFlowExecution(topFlowId, execution).processAction(challengeId)` rather than `processor.authenticationAction()`, because the latter only accepts the engine's single "current" execution. The ids offered are recorded in the auth note `native-auth.pending` and validated before the engine is invoked (unknown → `invalid_request`).
- `auth_session` re-minting: short TTL (login timeout) during the flow; after success re-mint with `root_session_id` of the **user session** (not the auth session) and the SSO max lifetime.
- Step-up: when `auth_session` points at a user session and `acr_values` is present, create a fresh auth session with `AuthenticationManager` already-authenticated context (`AUTHENTICATED` user set, `LoAUtil` notes) so conditional LoA executions skip what is satisfied.

### 2.2 `CodeIssuer`
- Build `OAuth2Code(id, exp, nonce, scope, redirectUriParam=null|sentinel, codeChallenge, codeChallengeMethod, userSessionId, dpopJkt)` and persist with `OAuth2CodeParser.persistCode`.
- Q1 (08) covers the `redirect_uri` question; implemented behind the realm attribute `native-auth.code-redirect-uri-mode = none|sentinel|client-fixed`, **default `none`** (verified on 26.8.1, see 09 Q1). The effective requirement is advertised in metadata as `code_exchange`.

### 2.3 Metadata & well-known
- `/native-auth/metadata` built from realm attributes + installed factories (`challenge_types_supported` = factories present and enabled).
- Optional `WellKnownOverride` registered with a higher priority than the default `openid-configuration` provider.

### 2.4 Passkey registration endpoints (Phase 1 ✅, `PasskeyRegistrationDriver`, spec/11 D5)
- Authenticate caller with Keycloak's `AppAuthManager.BearerTokenAuthenticator` (works for DPoP tokens too); enforce the 07 §5 freshness rule from the user session's `AUTH_TIME` (realm attribute `native-auth.passkey-registration-max-age`, default 300 s).
- `/options`: create `PublicKeyCredentialCreationOptions` using the realm's WebAuthn Passwordless policy (`WebAuthnPolicy`), store challenge + `registration_id` in a short-lived single-use entry (`SingleUseObjectProvider`, key `native-auth.passkey-registration-id:<id>`).
- `/finish`: validate with webauthn4j (`WebAuthnRegistrationManager`) exactly as `WebAuthnRegister` does (`PasskeyRegistrationVerifier`, shared with the required action), then `WebAuthnCredentialProvider.createCredential`.

### 2.5 Push enrolment start
- Requires bearer token from a native login.
- Creates a ba-itsys enrolment challenge for the user using its internal `PushChallengeStore` / token issuer (verify these are accessible; if only reachable via the RequiredAction, call the same package-level helper or contribute a small API upstream — 08 Q5).
- Returns the realm-signed enrolment JWT as JSON. The device then follows the normal `/push-mfa/enroll/complete` path.

## 3. `native-auth-authenticators`

### 3.1 Base class contract
```java
abstract class NativeAuthenticatorBase implements Authenticator {
  protected ChallengeDescriptor describe(AuthenticationFlowContext ctx);          // build params
  protected void emitChallenge(AuthenticationFlowContext ctx, ChallengeDescriptor d) {
     NativeRequestContext.of(ctx).envelope().add(d.withId(ctx.getExecution().getId()));
     ctx.challenge(Response.status(403).entity(NativeRequestContext.MARKER).build());
  }
  protected MultivaluedMap<String,String> form(AuthenticationFlowContext ctx);     // decoded form params
  protected void failAndRechallenge(ctx, String code, String msg) { … sets d.error, AuthenticationFlowError.INVALID_CREDENTIALS → re-emit }
}
```
Every authenticator guards `if (!NativeRequestContext.isNative(ctx)) { ctx.attempted(); return; }` so the same factories are harmless if accidentally placed in a browser flow (and vice versa, browser authenticators are never placed in the native flow).

### 3.2 Per-type specifics

| Authenticator | `authenticate()` | `action()` | Reuses |
|---------------|------------------|------------|--------|
| `native-username` | emit `username` (hint from `login_hint`) | lookup user by username/email per realm settings; `ctx.setUser`; generic error on miss | `UserModel` lookup, `AbstractUsernameFormAuthenticator` error semantics |
| `native-password` | emit `password` | `PasswordCredentialProvider.isValid`; brute-force via `BruteForceProtector` | |
| `native-passkey` (Phase 1 ✅) | create assertion options via the **Passwordless** `WebAuthnPolicy` + user's credentials (`allow_credentials`) or discoverable (empty); store challenge in an authNote keyed by execution id; `attempted()` for an identified user without passkeys (spec/11 D2) | parse 4 fields; `WebAuthnCredentialProvider.isValid(WebAuthnCredentialModelInput)`; set user from `user_handle` if discoverable | webauthn4j, `WebAuthnPasswordlessAuthenticator`'s validation portion |
| `native-totp` | emit `totp` with policy digits/period; `configuredFor` → user has OTP cred | `OTPCredentialProvider.isValid` | |
| `native-otp` | pick channel (config: email/sms); generate code (`SecretGenerator`), hash+store in authNote with ttl; send via `NativeOtpSender`; emit `otp` | compare, enforce attempts & ttl; `action=resend` with cooldown | Keycloak `EmailSenderProvider` |
| `native-push` (Phase 3 ✅, 14 D9) | emit `push` with the user's devices; create the ba-itsys challenge (sender delivers the confirm token) only when `push` is the single option or on `action=resend`; number-match number in `params.user_verification` | `action=poll` → read challenge status; approved → success; denied → `denied` failure; expired → `expired`; `action=cancel` ends the session | ba-itsys `ChallengeIssuer`, `PushChallengeStore`, sender SPI |
| `native-recovery-code` | emit | `RecoveryAuthnCodesCredentialProvider.isValid` | |
| `native-redirect-to-web` | always raises redirect (terminal) — placed as last ALTERNATIVE when operators want a guaranteed fallback | n/a | |

Config properties exposed in the admin console (via `getConfigProperties()`): OTP channel/ttl/length/resend cooldown; passkey `user_verification`; push number-match on/off; whether `username` reveals non-existence.

## 4. Required actions (JSON variants)

- `native-passkey-register` (Phase 1 ✅, module `native-auth-required-actions`): `requiredActionChallenge()` emits `passkey_registration`; `processAction()` validates attestation and stores credential. Operators enable it as the default action for new users in the native realm (the demo export registers it; note that an export listing `requiredActions` must list Keycloak's defaults too, spec/11 D1). Outside a native session (browser login) it ignores itself with a warning and stays on the user. "Enrol on first login" exists since Phase 2b (spec/14 D4): with `enrol-on-first-login=true` on an ALTERNATIVE `native-passkey` execution, a user without a passkey authenticates with the other alternative and `native-passkey-register` is added to the authentication session, so the passkey is created in-band before the code is issued.
- `native-push-enroll`: same shape wrapping ba-itsys enrolment.
- `native-update-password`, `native-verify-email`, `native-terms` (Phase 2b, spec/03 §4.11–§4.14, spec/14 D1): JSON variants that substitute for Keycloak's `UPDATE_PASSWORD`, `VERIFY_EMAIL`, `TERMS_AND_CONDITIONS` when registered and enabled in the realm.
- Any other required action (update profile, configure OTP, configure recovery codes, …) → endpoint emits `redirect_to_web` (reason = alias).

## 5. OTP sender SPI

```java
public interface NativeOtpSender extends Provider {
  String channel();                       // "email" | "sms"
  void send(UserModel user, String code, Duration ttl, Locale locale) throws IOException;
  String maskedDestination(UserModel user);
}
```
Implementations: `email` (Keycloak templates `native-otp.ftl` + i18n), `log` (dev), `sms-webhook` (POST to a configured URL — lets operators plug Twilio/MessageBird without us depending on their SDKs).

## 6. APNs sender for ba-itsys

**Built in Phase 3** as module `native-auth-push-apns` (14 D10): JDK `HttpClient` HTTP/2, ES256
provider token reused for 50 minutes, headers and payload as below; unconfigured it is installed but
idle; tested against a fake APNs in the ITs (no Apple team available for the real endpoint). The
ba-itsys extension itself is deployed from `push-mfa-extension-java21`, a Java 21 rebuild of the
published sources (the published jars target Java 25; `@RunOnVirtualThread` dropped, 14 D9).

`PushNotificationSender` implementation `apns`:
- Config: team id, key id, `.p8` key (path or env), bundle id/topic, environment (sandbox/prod), optional `apns-push-type: background|alert`.
- Send a notification with `aps` (alert title/body localized keys) + `confirmToken` in custom data; `apns-collapse-id = cid`; `apns-expiration` = challenge expiry.
- Use a tiny HTTP/2 client with JWT provider-token auth (no third-party APNs libs if avoidable; Java 21 `HttpClient` supports HTTP/2).
- Failure handling: `BadDeviceToken`/`Unregistered` → emit event so the app can re-register; do not fail the login — the user can still open the app and poll `/login/pending`.

## 7. Realm configuration (shipped in `demo-realm.json` and documented for operators)

1. Create flow **`native`** (top-level, type basic):
   ```
   native
   ├─ native-username                     REQUIRED
   ├─ Primary factor                      REQUIRED (subflow)
   │   ├─ native-passkey                  ALTERNATIVE
   │   └─ native-password                 ALTERNATIVE
   ├─ Second factor (conditional)         CONDITIONAL
   │   ├─ Condition - user configured     REQUIRED
   │   ├─ Condition - LoA (level 2)       REQUIRED (optional, for step-up)
   │   ├─ native-totp                     ALTERNATIVE
   │   ├─ native-otp (email)              ALTERNATIVE
   │   ├─ native-push                     ALTERNATIVE
   │   └─ native-recovery-code            ALTERNATIVE
   └─ native-redirect-to-web              ALTERNATIVE (fallback; only reached if nothing above can run)
   ```
   Realm attribute `native-auth.flow-alias=native` (or per-client override attribute).
2. Client `demo-ios`: public, PKCE S256 required, `native-auth.enabled=true`, DPoP bound tokens optional, `oauth2.device.authorization.grant.enabled=false`, no redirect URIs except the fallback web callback (`demoapp://auth/callback`) for `redirect_to_web`.
3. WebAuthn Passwordless policy: RP ID = IdP host, UV required, resident key required, attestation `none`, algorithms ES256/RS256.
4. ba-itsys config: `push-device-client` (confidential, client-credentials, DPoP), `pushProviderType` default `apns`, number-match enabled, enrolment via `request_uri`.
5. Browser flow: add ba-itsys `push-mfa` authenticator as an ALTERNATIVE second factor (scenario A).
6. Required actions enabled: `native-passkey-register` (not default), `native-push-enroll` (not default).

## 8. Testing strategy

| Layer | Tooling | Scope |
|-------|---------|-------|
| Unit | JUnit 5, Mockito | codec, descriptor builders, OTP generation/hash, APNs payload |
| Integration | Keycloak test containers (`quay.io/keycloak/keycloak:26.x`) + extensions mounted; REST Assured | whole flow per factor; failure branches; step-up; session expiry; redirect_to_web |
| Passkey in CI | webauthn4j's software authenticator (or `com.yubico.webauthn` test helpers) to produce assertions/attestations | no device needed |
| Push in CI | ba-itsys `log` sender + its simulator scripts; our conformance client signs login JWTs with a generated EC key | end-to-end approve/deny/number-match |
| Conformance suite | Same integration tests packaged as a runnable JAR: `java -jar conformance.jar --base https://idp/realms/x --client demo-ios` | published for third-party server and client authors |
| Load | k6 script hitting `/challenge` with username+password+totp; reuse ba-itsys loadtest for push | before Phase 4 exit |

## 9. Observability
- Events: `LOGIN`/`LOGIN_ERROR`/`CODE_TO_TOKEN` with details `native_protocol=1`, `challenge_type`, `device_id`, `dpop=true|false`. New custom event types `NATIVE_CHALLENGE_ISSUED`, `NATIVE_REDIRECT_TO_WEB`, `PUSH_ENROLLED_IN_APP`.
- Micrometer metrics via Keycloak's metrics: counters per challenge type/outcome, histogram for flow duration.
- Structured logging with `auth_session` **hash** (never the value).

## 10. Packaging & release
- GitHub Actions: build, spotless, unit + integration (testcontainers), publish `-SNAPSHOT` to GitHub Packages, tags → Maven Central (`io.yourorg.keycloak:native-auth-*`).
- Compatibility matrix in README (Keycloak minor × extension version); run integration tests against `26.x` latest two minors + `nightly` (allowed to fail) to see breaking SPI changes early.
