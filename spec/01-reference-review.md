# 01 — Reference Review

Each reference is summarised in terms of *what it does*, *what we should borrow*, and *what we should avoid or watch out for*.

---

## 1. OAuth 2.0 for First-Party Applications (FiPA) — `draft-ietf-oauth-first-party-apps-04`

**Source:** IETF OAuth WG, July 2026 (expires Jan 2027). Authors: Parecki (Okta), Fletcher, Kasselman. Adopted by the WG in Oct 2024; now on revision -04.

**What it defines**
- A new **Authorization Challenge Endpoint** (`authorization_challenge_endpoint` in AS metadata) accepting `application/x-www-form-urlencoded` POSTs with the usual authorization-request parameters (`client_id`, `scope`, `response_type=code`, PKCE `code_challenge`, OIDC params such as `acr_values`, `max_age`, `login_hint`).
- Two outcomes: `200 {"authorization_code": "..."}` or an error. Key error codes:
  - `insufficient_authorization` (HTTP **403** in -04; the article's implementation used 400 from an earlier draft) — the client must collect more from the user and call again.
  - `redirect_to_web` (403) — fall back to a browser flow, optionally with a PAR `request_uri`.
  - `invalid_session` — the `auth_session` is bad.
- `auth_session`: opaque, server-issued, analogous to a cookie; the client MUST echo it on subsequent requests and MUST be prepared for it to change on every response. SHOULD be device-bound (DPoP binding described in §9.6.1).
- Intermediate requests are **explicitly out of scope** — the AS defines its own profile for what the client sends and what the error carries. The draft even says "it is expected that service providers will wrap the implementation of this specification in an SDK".
- Token endpoint is unchanged except that `redirect_uri` is absent and the response MAY carry `auth_session`. A refresh-token request may return `insufficient_authorization` to force re-auth; resource servers use RFC 9470 (`insufficient_user_authentication` + `acr_values`/`max_age`) to trigger step-up, which the client satisfies by re-entering the challenge endpoint.
- Security §9: first-partyness MUST be verified (attestation recommended), tokens SHOULD be sender-constrained (DPoP), DPoP SHOULD bind the authorization code by sending a `DPoP` header on challenge requests, rate-limit per `auth_session`, NOT RECOMMENDED for SPAs.

**Borrow**
- The whole envelope: endpoint, `auth_session`, `authorization_code`, the three error codes, HTTP status semantics, PKCE, RFC 9470 step-up integration.
- The "profile" concept — our challenge descriptors are our profile.
- DPoP for both auth_session binding and token binding.

**Watch out for**
- It is still a draft. Pin the version we implement (`-04`) in the protocol spec and keep the envelope code isolated so a bump is cheap.
- `insufficient_authorization` moved from 400 → 403 between early drafts and -04. Our SDK should treat both as "challenge" for tolerance.

---

## 2. Martin Besozzi — "Native Authentication and Passkeys in Keycloak" (Medium, Jul 2024)

**What it shows**
- A working FiPA implementation in Keycloak via custom SPIs: a `RealmResourceProvider` serving `/realms/{realm}/authorization-challenge`, a custom `OAuth2ChallengeErrorRepresentation`, and a `PasskeysAutofill`-style authenticator placed in a dedicated "first party login" flow.
- The error response carries a `metadata` array with one entry per pending authenticator: `{ "type": "passkeys", "config": { challenge, rpId, userVerification, ... } }`. The client runs `navigator.credentials.get()` (or the native equivalent) and POSTs `clientDataJSON`, `signature`, `credentialId` + `auth_session` back to the same endpoint.
- Step-up via RFC 9470 is demonstrated end-to-end without leaving the app.
- Explicitly defers app attestation / attestation-based client auth to "a later article".

**Follow-ups found**
- Keycloak discussion **#25014** (Nov 2023 → Jun 2026): still open, high interest, no upstream work. The extension was never published; people are still asking for it in 2026.
- Keycloak discussion **#36924** (Jan 2025): the author proposes decoupling authenticators from `LoginFormsProvider` so one authenticator can emit either a form or a JSON challenge. Thomas Darimont (Keycloak collaborator) notes an authenticator can already throw/return any pre-built JAX-RS `Response` — i.e. **JSON challenges are possible today without core changes**, at the cost of writing native-specific authenticators.

**Borrow**
- The architecture: `RealmResourceProvider` endpoint → `AuthenticationProcessor` over a dedicated flow → authenticators that return JSON.
- The shape of the passkey challenge/response (it maps 1:1 to WebAuthn `PublicKeyCredentialRequestOptions` and the assertion result).
- The pattern of one `metadata`/`challenges` entry per authenticator so the client can offer a choice.

**Avoid / improve**
- Closed-source, so nothing to reuse directly.
- Ad-hoc field naming (`isUserIdentified: "false"` as a string). Our profile should use proper JSON types and a versioned schema.
- Only passkeys were implemented; TOTP/OTP/push and registration flows are new ground.

---

## 3. `ba-itsys/keycloak-push-mfa-extension` (Apache-2.0, Maven Central `de.arbeitsagentur.opdt:keycloak-push-mfa-extension` v1.11.0)

**What it is**
A production-grade push second factor from the German Federal Employment Agency's IT team. Standard Keycloak SPIs (authenticator + required action + credential provider) plus a JAX-RS resource under `/realms/{realm}/push-mfa`.

**Design highlights**
- **Enrolment:** a `RequiredAction` renders a QR / deep link (`my-secure://enroll?token=…` or a short-lived `request_uri`). The token is a realm-signed JWT (`typ: push-enroll-challenge`, `sub`, `enrollmentId`, `nonce`). The device verifies it against the realm JWKS, generates a key pair (RSA or EC), and POSTs a device-signed JWT with `cnf.jwk`, `credentialId`, `deviceId`, `deviceType`, `pushProviderId/Type`, `deviceLabel` to `/enroll/complete`. The browser waits via **SSE**, not polling.
- **Pseudonymous handle:** the device chooses its own `credentialId`; push payloads carry only `credId` + `cid`, so the push provider never sees the user identity.
- **Login:** authenticator creates a challenge + `confirmToken` (realm-signed, `cid`, `credId`, `typ`, `ver`), sends it via a `PushNotificationSender` provider (bundled: `log`, `none`, FCM). The device calls `GET /login/pending` to fetch username/client metadata (and optional **number-match** or **PIN** user-verification data), then `POST /login/challenges/{cid}/respond` with a device-signed login JWT (`cid`, `credId`, `deviceId`, `action: approve|deny`, `userVerification`).
- **Device API auth = DPoP (RFC 9449):** the app obtains a DPoP-bound access token with client-credentials on a `push-device-client`, then every call carries `Authorization: DPoP …` plus a fresh proof (`htm`, `htu`, `ath`, `iat`, `jti`, custom `sub` and `deviceId`) signed by the device key. Server checks `cnf.jkt`, freshness ±120 s, ownership of `deviceId`.
- Extra endpoints: lockout "panic button", update push provider token, rotate device key.
- Multi-node safe (challenge state in shared storage), heartbeat + bounded SSE lifetimes, rate-limiting SPI, load-test harness, simulator scripts, FCM provider, documentation for mobile implementers and a security model doc.
- Cross-document uses `PushNotificationSender` SPI → we can add **APNs**.

**Borrow — adopt wholesale**
- Use it as the push-MFA server implementation. Re-implementing would cost months and produce something less tested.
- Its DPoP-based device-API auth pattern is also the right pattern for *our* device-bound endpoints (and aligns with FiPA §9.5/9.6).

**Gaps relative to our goals**
- Enrolment assumes a browser session showing a QR. We need an **in-app enrolment** path for a user already logged in natively (see 04-keycloak-extensions-plan §Push bridge).
- No APNs sender shipped (FCM can relay to APNs, but a direct APNs provider is cleaner for an iOS-first project).
- Its deep-link scheme and client ID are examples (`my-secure://`, `push-device-client`) — we parameterise them.
- Uses RS256 in examples; we will use **ES256 with Secure Enclave keys** on iOS (EC is supported).

---

## 4. `netzbegruenung/keycloak-mfa-plugins` → `app-authenticator`

**What it is**
An older (2023–) Keycloak "accept/reject on your phone" authenticator with a companion Flutter package (`flutter_keycloak_authenticator`) and a reference app (verdigado/autentigo).

**Design**
- Enrolment via a Keycloak **action token** URL shown as QR; the app calls `GET /login-actions/action-token` with `public_key`, `key_algorithm`, `authenticator_id`, `device_os`, `device_push_id` as query params.
- Request auth via an RFC 9421-style `Signature` header (`keyId`, `created`, optional `secret`+`granted`, `signature`).
- Challenges fetched by polling `/realms/{realm}/challenges` (or via push); reply is another action-token GET. Challenge DTO includes IP, browser, OS of the login attempt and an optional `loginId` correlation value supplied by the client in the original `/auth` request.
- Limitation they document: action-token endpoints always return HTML on success and empty bodies on error.

**Borrow**
- Showing **login context** (IP, device, browser, client name) in the approval prompt — important anti-push-fatigue UX.
- The `loginId` correlation idea (client-chosen value echoed back) for same-device flows.
- Proof that a Flutter/Dart client can implement a Keycloak push protocol; useful cross-check for our Android port.

**Avoid**
- Action-token-based transport (HTML responses, GET with secrets in query strings).
- Custom signature header when DPoP is the standards-track equivalent.

---

## 5. Auth0.swift (v2.16+, Swift 6, iOS 16.6+ for passkeys)

**Structure (what good looks like)**
- Three clients behind factory functions: `Auth0.webAuth()`, `Auth0.authentication()`, `Auth0.mfa()`, plus `Auth0.myAccount()` and a `CredentialsManager`.
- Every public API is a **protocol**; results via completion handler, `async/await`, or Combine.
- `CredentialsManager`: Keychain storage, automatic renewal, biometric gating, clear.
- **MFA pattern:** a login attempt fails with `AuthenticationError.isMultifactorRequired`; the error payload carries an `mfaToken` plus `enroll`/`challenge` lists of factor types. The client then calls `getAuthenticators`, `challenge(with:)`, `enroll(...)`, and `verify(otp:|oobCode:|recoveryCode:)`.
- **Passkey login:** three steps — `passkeyLoginChallenge()` returns `relyingPartyId` + `challengeData`; the app uses `ASAuthorizationPlatformPublicKeyCredentialProvider` to get an assertion; `login(passkey:challenge:)` finishes. Registration is the same shape via `passkeySignupChallenge` / My Account API.
- **Errors:** typed per client (`MfaEnrollmentError`, `MFAVerifyError`…), each exposing `code`, `statusCode`, `info`, `isNetworkError`, `isRetryable`; docs warn never to parse messages, only `code`.
- DPoP support in both Web Auth and Authentication API; automatic token redaction in logs.

**Borrow**
- Factory + protocol layering, three concurrency styles, `CredentialsManager`, error model with stable `code`s and `isRetryable`.
- The passkey three-step shape (challenge → platform API → finish) — our challenge/response fits it exactly.
- Keep passkey/WebAuthn platform calls *inside* the SDK but overridable.

**Differences we need**
- Auth0's MFA is a bolt-on after a password login; ours is a single challenge-driven state machine from the first request (FiPA). We model "which factor next" as part of the challenge list rather than separate `enroll`/`challenge` calls.
- Auth0 is one vendor's fixed backend; ours must be **documented so non-SDK clients can implement it**.

---

## 6. Auth0.Android

- Mirrors Auth0.swift: `AuthenticationAPIClient`, a newer `MfaApiClient` (older `loginWithOTP`/`loginWithOOB`/`multifactorChallenge` are deprecated in favour of it), `PasskeyChallenge` result type, `CredentialsManager` with EncryptedSharedPreferences/Keystore, Kotlin coroutines + callbacks.
- Native passkeys on Android use the Credential Manager API with the same server endpoints (`/passkey/challenge`, `/passkey/register`) as iOS.
- Newer "Universal Components" (Compose) for self-service factor management on top of the My Account API.

**Borrow**
- Confirms the **same protocol, two thin platform layers** approach is viable; the Android SDK should be a port of the iOS state machine with Credential Manager + Keystore + FCM substituted.

---

## 7. Keycloak extension points we will rely on (Keycloak 26.x)

| SPI / API | Use in this project |
|-----------|---------------------|
| `RealmResourceProviderFactory` / `RealmResourceProvider` | Hosts `/realms/{realm}/native-auth/...` (challenge endpoint, metadata, passkey registration). JAX-RS; full access to `KeycloakSession`. |
| `AuthenticatorFactory` / `Authenticator` | One native-aware authenticator per challenge type. `authenticate()` emits a JSON challenge via `context.challenge(Response)`; `action()` validates the submitted response. `requiresUser()`/`configuredFor()`/`setRequiredActions()` drive enrolment. |
| `AuthenticationProcessor` + `AuthenticationSessionModel` | We run the realm's dedicated *native* flow exactly as the browser flow is run, but from our endpoint rather than `/protocol/openid-connect/auth`. Execution status, `authNote`s, and `clientNote`s carry state across requests. |
| `CredentialProvider`s: `WebAuthnCredentialProvider`, `OTPCredentialProvider`, `RecoveryAuthnCodesCredentialProvider` | Reuse validation logic; do not reimplement WebAuthn or TOTP verification. Keycloak uses webauthn4j under the hood. |
| `RequiredActionFactory` / `RequiredActionProvider` | Passkey registration and push enrolment when the server requires them mid-flow. Native variants return JSON instead of forms. |
| `OAuth2CodeParser` / `OAuth2Code` + `OIDCLoginProtocol` | Mint the authorization code after the flow succeeds, bound to the client, PKCE challenge, nonce, scope. |
| Token endpoint (unchanged) | Code exchange, refresh, DPoP (`dpop` feature) — Keycloak has native DPoP support. |
| `OIDCWellKnownProviderFactory` (well-known SPI) | Optional: publish `authorization_challenge_endpoint` in discovery. |
| ba-itsys `PushNotificationSender` SPI | Add an APNs implementation. |
| Event SPI | Emit `LOGIN`, `LOGIN_ERROR`, custom `NATIVE_CHALLENGE_*` events for audit. |

**Known friction points to validate early (see 08-roadmap, Phase 0)**
1. Keycloak's `authorization_code` grant may require `redirect_uri` to match the stored value; our codes have none. Options: store a sentinel, or register a fixed `redirect_uri` for native clients and send it on the token request.
2. `AuthenticationSessionManager` normally locates the auth session from the `AUTH_SESSION_ID` cookie; we must look it up by id from our opaque `auth_session` and set it on the context manually.
3. Some built-in authenticators (`UsernamePasswordForm`, `OTPFormAuthenticator`, `WebAuthnAuthenticator`) hard-code `LoginFormsProvider`; we wrap their *credential validation* but not their `authenticate()`.
4. The "Passkeys Conditional UI Authenticator" is feature-flagged and being replaced in 26.x — we target the WebAuthn credential provider directly, not that authenticator.

---

## Source list

- FiPA draft -04: https://www.ietf.org/archive/id/draft-ietf-oauth-first-party-apps-04.txt
- Besozzi article: https://embesozzi.medium.com/deep-dive-into-enhancing-user-experience-with-native-authentication-and-passkeys-in-keycloak-86fb72c64278
- Keycloak discussion #25014: https://github.com/keycloak/keycloak/discussions/25014
- Keycloak discussion #36924: https://github.com/keycloak/keycloak/discussions/36924
- ba-itsys push MFA: https://github.com/ba-itsys/keycloak-push-mfa-extension (README, docs/api-reference.md, docs/flow-details.md)
- netzbegruenung app-authenticator: https://github.com/netzbegruenung/keycloak-mfa-plugins/blob/main/app-authenticator/README.md
- Auth0.swift: https://github.com/auth0/Auth0.swift (EXAMPLES.md, examples/mfa-api.md, examples/authentication-api/login-passkey.md)
- Auth0.Android: https://github.com/auth0/Auth0.Android ; Auth0 Native Passkeys API docs
- RFC 9449 (DPoP), RFC 9470 (Step-up), RFC 7636 (PKCE), RFC 8252 (Native apps), RFC 9700 (OAuth security BCP)
- Attestation-based client auth: draft-ietf-oauth-attestation-based-client-auth-09 (May 2026)
