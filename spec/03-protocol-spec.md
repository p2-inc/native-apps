# 03 — Keycloak Native Authentication Profile (protocol specification)

**Profile version:** `1` — **v1.0-rc** (frozen 15 October 2026 for the implemented challenge types, see §10; the wire value stays `"1"`)
**Base specification:** OAuth 2.0 for First-Party Applications, `draft-ietf-oauth-first-party-apps-04`
**Push MFA device API:** ba-itsys `keycloak-push-mfa-extension` v1.11 API, unchanged
**Audience:** implementers of the Keycloak extensions, the iOS/Android SDKs, and any third-party client

This document is the contract. The SDK is one implementation of it; a developer with an HTTP client and a WebAuthn library should be able to implement a conforming client from this document alone.

Conventions: `MUST`/`SHOULD`/`MAY` per BCP 14. All binary values are **base64url without padding** (RFC 4648 §5). All timestamps are Unix seconds. JSON field names are `snake_case`.

---

## 1. Endpoints

All paths are relative to the realm base `https://{host}/realms/{realm}`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/native-auth/metadata` | none | Discovery: protocol version, supported challenge types, endpoint URLs, RP ID (`passkey.rp_id`). |
| POST | `/native-auth/challenge` | none (client is public; optional DPoP header) | The FiPA authorization challenge endpoint. Starts/continues a login or step-up. |
| POST | `/protocol/openid-connect/token` | standard | Unchanged Keycloak token endpoint. Code exchange, refresh. |
| POST | `/native-auth/passkey/register/options` | Bearer/DPoP access token | Begin passkey registration for the authenticated user. |
| POST | `/native-auth/passkey/register/finish` | Bearer/DPoP access token | Complete passkey registration. |
| POST | `/native-auth/push/enroll/start` | Bearer/DPoP access token | In-app push-MFA enrolment: returns the ba-itsys enrolment JWT. |
| * | `/push-mfa/**` | DPoP (device key) | ba-itsys device API (enrol/complete, login/pending, respond, lockout, device/*). See §7. |

The server SHOULD also advertise `authorization_challenge_endpoint` in `/.well-known/openid-configuration` when the well-known override is installed; clients MUST NOT rely on it and SHOULD use `/native-auth/metadata`.

### 1.1 Metadata response

```json
{
  "protocol_version": "1",
  "fipa_draft": "draft-ietf-oauth-first-party-apps-04",
  "authorization_challenge_endpoint": "https://idp.example.com/realms/demo/native-auth/challenge",
  "token_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/token",
  "authorization_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/auth",
  "code_exchange": { "redirect_uri_required": false },
  "passkey": { "rp_id": "idp.example.com", "register_options_endpoint": "…", "register_finish_endpoint": "…" },
  "push": { "enabled": true, "enroll_start_endpoint": "…/native-auth/push/enroll/start", "device_api_base": "https://idp.example.com/realms/demo/push-mfa", "device_token": "native", "push_provider_types": ["apns", "none"] },
  "challenge_types_supported": ["username", "password", "passkey", "passkey_registration", "totp", "otp", "push", "recovery_code", "select", "update_password", "verify_email", "terms", "redirect_to_web"],
  "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
  "client_attestation": { "required": false, "methods": [] }
}
```

`authorization_endpoint` is the realm's standard OIDC authorization endpoint; clients need it only for §3.4. `dpop_signing_alg_values_supported` lists the proof algorithms the challenge endpoint verifies (§8); it is empty when the server does not verify proofs at all. The `push` block is present only when the push-MFA extension is installed (§7): `device_token` says how the device API is authenticated — `native` (the user's DPoP-bound native access token with the DPoP key as device key, §7.1) or `client_credentials` (ba-itsys' stock `push-device-client`, then `device_client_id` is present); `push_provider_types` lists the installed senders (`apns`, `fcm`, `log`, `none`).

---

## 2. Authorization challenge request

`POST /native-auth/challenge`, `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`.

### 2.1 Initial request parameters

| Param | Req | Notes |
|-------|-----|-------|
| `client_id` | yes | A Keycloak **public** client with the attribute `native-auth.enabled=true` and no redirect URIs required. |
| `response_type` | yes | MUST be `code`. |
| `scope` | opt | e.g. `openid profile offline_access`. |
| `code_challenge`, `code_challenge_method` | SHOULD | PKCE S256. Required if the client wants `redirect_to_web` to carry a `request_uri`. |
| `acr_values`, `max_age`, `login_hint`, `prompt`, `nonce`, `ui_locales` | opt | Standard OIDC semantics. `acr_values` drives step-up. `login_hint` pre-fills the `username` challenge. |
| `auth_session` | opt | A **post-login** value (§3.1, §5) when the client wants to step up or re-authenticate inside an existing user session; the other §2.1 parameters are sent as for a fresh login (a new PKCE pair, `acr_values`, `max_age`, `prompt`, `scope`). Sending an **in-flow** value here is a §2.2 continuation instead. |
| `device_name`, `device_id` | opt | Free-text label + stable app-generated UUID; used in events and push prompts. |

Optional headers: `DPoP: <proof>` (see §8). If present on the first request, the server binds `auth_session` and the eventual authorization code to the key (FiPA §9.5.1/9.6.1) and rejects later requests of the same session that present a different key or no key (`invalid_session`); an unverifiable proof is `invalid_dpop_proof`.

### 2.2 Continuation request parameters

| Param | Req | Notes |
|-------|-----|-------|
| `auth_session` | yes | Exactly as last received. |
| `challenge_type` | yes | The `type` of the challenge being answered. |
| `challenge_id` | yes | The `id` of the challenge being answered (opaque; it is the Keycloak execution id). |
| *type-specific fields* | | See §4. |
| `action` | opt | `cancel` aborts the session (server responds `invalid_session`); `resend` for `otp`; `select` for choosing among alternatives without answering. |

Clients MUST NOT send `client_id`/`scope`/PKCE again on continuation requests unless the server returned a new session; if sent they MUST match.

---

## 3. Authorization challenge responses

### 3.1 Success — authorization code

`200 OK`

```json
{ "authorization_code": "…", "auth_session": "…" }
```

`auth_session` MAY be present; if so the client MUST store it and replace any earlier copy. The Keycloak implementation always returns it: a **post-login** value bound to the user session (lifetime = the realm's SSO **idle** timeout from the moment it was issued, never beyond the SSO session max, 14 D6; a successful step-up and a §6 refusal issue a fresh one) that the client presents in a §2.1 request to step up or re-authenticate without typing the username again (§5, 13 D1). It is also bound to the DPoP key when the login used one (§8). Exchange the code at the token endpoint with `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, and **no** `redirect_uri` — unless metadata says otherwise: `code_exchange.redirect_uri_required` is `false` by default (Keycloak accepts a code stored without a redirect URI when the token request omits the parameter; verified in 09 Q1). When it is `true` the client MUST send exactly `code_exchange.redirect_uri` (operator-chosen `sentinel` or `client-fixed` mode).

### 3.2 Challenge — more input required

`403 Forbidden` (clients SHOULD also accept `400` for tolerance with pre-04 servers)

```json
{
  "error": "insufficient_authorization",
  "error_description": "Authentication required",
  "auth_session": "eyJ…",
  "protocol_version": "1",
  "expires_in": 540,
  "challenges": [ { …challenge descriptor… }, { … } ],
  "context": {
    "username": "alice",
    "display_name": "Alice Example",
    "client_name": "Demo App",
    "acr_requested": "2",
    "step_up": true
  }
}
```

- `challenges` is ordered by server preference — in the Keycloak implementation the operator's flow layout (depth-first execution order, 11 D3). Entries are the **ALTERNATIVE** executions currently eligible; the client MAY present a chooser or auto-pick the first it supports.
- `context` is informational, present once the user is identified. Never include secrets. During a step-up (§5) `step_up` is `true` and `acr_requested` echoes the requested `acr_values`.
- `expires_in` is the remaining lifetime of the authentication session.

### 3.3 Challenge descriptor (common fields)

```json
{
  "type": "passkey",
  "id": "4f2e…",            // execution id, echo as challenge_id
  "label": "Sign in with a passkey",
  "required": true,          // false when it is one of several alternatives
  "retry": { "remaining": 3 },      // optional; on the descriptor that just failed: attempts left before the account is locked (realm brute-force protection)
  "error": { "code": "invalid_credential", "message": "…" },  // optional; the previous attempt failed
  "params": { …type-specific… }
}
```

### 3.4 Redirect to web

`403 Forbidden`

```json
{ "error": "redirect_to_web", "error_description": "Complete the login in a browser",
  "request_uri": "urn:ietf:params:oauth:request_uri:…", "expires_in": 60,
  "redirect_uri": "demoapp://auth/callback", "state": "…",
  "reason": "required_action:UPDATE_PASSWORD" }
```

The server has stored a pushed authorization request (PAR, RFC 9126) for the client: the §2.1 parameters of the native flow (`scope`, PKCE `code_challenge`/`code_challenge_method`, `nonce`, `acr_values`, `ui_locales`), `redirect_uri`, a server-generated `state`, and `login_hint` = the identified username. The client MUST open the system browser (`ASWebAuthenticationSession`) on `authorization_endpoint` (§1.1) with exactly `client_id=<client_id>&request_uri=<request_uri>` and complete a normal code flow there: the user signs in again in the browser flow, completes whatever the native flow could not serve (e.g. the required action named in `reason`), and the browser is redirected to `redirect_uri` with `code` and `state`. The client MUST check `state`, then exchanges the code at the token endpoint with the **native flow's** `code_verifier` and the same `redirect_uri` (this exchange always sends `redirect_uri`, whatever `code_exchange` says, because the code was issued by the browser flow). `request_uri` is single use and expires after `expires_in` seconds (the realm's PAR request URI lifespan). `redirect_uri` is the client's `native-auth.web-fallback-redirect-uri` attribute or, when unset, its first registered redirect URI; it MUST be a registered redirect URI of the client. `reason` is informational (e.g. `required_action:<alias>`, risk decision, account locked). The Keycloak implementation emits it for a pending required action that has no native variant (§4.12–§4.14 list the ones that do): e.g. `UPDATE_PROFILE`, `CONFIGURE_TOTP`.

The answer is only possible when the initial request carried a PKCE challenge **and** the client has a usable `redirect_uri`; otherwise the server answers `403 access_denied` with the same `reason` in `error_description`. The native authentication session is removed in both cases; the browser flow is a new login, the native `auth_session` is no longer valid.

### 3.5 Other errors

| HTTP | `error` | Meaning |
|------|---------|---------|
| 400 | `invalid_request` | Malformed / missing parameter, unknown `challenge_type`, `challenge_id` not pending. |
| 400 | `invalid_session` | `auth_session` missing, expired, revoked, cancelled, bound to a different client, bound to a DPoP key the request did not prove, or (post-login shape) pointing at a user session that has ended. Client restarts from §2.1 without `auth_session`. |
| 400 | `invalid_dpop_proof` | The `DPoP` header is present but does not verify (RFC 9449 §4.3: `typ`, `alg`, `jwk`, `htm`, `htu`, `iat` window, `jti` replay). |
| 401 | `invalid_client` | Client not found or not enabled for native auth. |
| 403 | `access_denied` | Flow failed terminally (e.g. user disabled, too many attempts). `error_description` is user-safe. |
| 429 | `slow_down` | Rate limited; `Retry-After` header. |
| 403 | `client_attestation_required` | Server policy requires attestation (Phase 4); `error_description` names the method. |

Error bodies MAY include `auth_session` if the session remains valid (e.g. after `invalid_request`).

---

## 4. Challenge types

Each subsection gives the **descriptor `params`** (server → client) and the **continuation parameters** (client → server).

### 4.1 `username` — identify the user

params:
```json
{ "allow_email": true, "hint": "alice" }
```
response: `username=<string>`
Failure: the server MUST NOT reveal whether the user exists. The Keycloak implementation answers an unknown (or disabled / locked) username with a **phantom** `password` challenge that looks like a real user's: the set is `[password]` with `params.username_known = true`, every answer fails with `error.code = "invalid_credential"` and a decreasing `retry.remaining`, and after the realm's `failureFactor` attempts the flow ends with `403 access_denied` ("Account temporarily locked"), exactly as for an existing user with wrong passwords. Only the `native-username` setting `reveal-user-not-found=true` changes this into an immediate re-challenge of `username` with `error.code = "invalid_user"`. A phantom session can never be authenticated through the password; a discoverable `passkey` alternative in the same set still identifies a real user through `user_handle` as usual.

### 4.2 `password`

params: `{ "username_known": true }`
response: `password=<string>`
Notes: supports realm brute-force detection via the processor; after a wrong password the descriptor carries `retry.remaining` (§3.3) when the realm's brute-force protection is on. The SDK MUST send over TLS only and never log the value.

### 4.3 `passkey` — WebAuthn assertion (login)

params mirror `PublicKeyCredentialRequestOptions`:
```json
{
  "challenge": "b64url",
  "rp_id": "idp.example.com",
  "timeout": 60000,
  "user_verification": "required",
  "allow_credentials": [ { "type": "public-key", "id": "b64url", "transports": ["internal","hybrid"] } ],
  "discoverable": true,          // true when allow_credentials is empty (passkey autofill / username-less)
  "extensions": {}
}
```
response:
```
credential_id=<b64url>
client_data_json=<b64url>
authenticator_data=<b64url>
signature=<b64url>
user_handle=<b64url, optional>
```
The server verifies via `WebAuthnCredentialProvider` using the stored challenge from the auth session (single use; a fresh `challenge` is issued with every challenge set). `rp_id` MUST equal the realm's configured WebAuthn **Passwordless** RP ID, and the app MUST have an Associated Domains `webcredentials:` entry for it. The `origin` inside `client_data_json` must be the server's base origin or one of the policy's *extra origins* (add `https://<rp_id>` there when they differ).
Error codes on the descriptor: `missing_credential` (field missing or not base64url; not counted as a failure), `invalid_credential` (signature, challenge, origin, RP ID, UV or counter check failed, unknown credential or user; counted as a failure). A `user_handle` naming a different user than the one already identified ends the flow with `access_denied`.
Eligibility (11 D2): offered to an identified user only when that user has at least one passkey; always offered before a user is identified (then `discoverable: true`).

### 4.4 `passkey_registration` — WebAuthn attestation mid-flow (required action)

Used when the flow requires passkey enrolment (`webauthn-register`-style required action) and the client supports it. params mirror `PublicKeyCredentialCreationOptions`:
```json
{ "challenge": "…", "rp": { "id": "…", "name": "…" }, "user": { "id": "b64url", "name": "alice", "display_name": "Alice" },
  "pub_key_cred_params": [ { "type": "public-key", "alg": -7 } ], "authenticator_selection": { "resident_key": "required", "user_verification": "required", "authenticator_attachment": "platform" },
  "attestation": "none", "exclude_credentials": [ … ], "timeout": 60000 }
```
response: `credential_id`, `client_data_json`, `attestation_object`, `transports` (comma-separated), `label` (optional user-visible name).
The same payloads are used by the standalone `/native-auth/passkey/register/*` endpoints (§6).
The descriptor's `id` (echoed as `challenge_id`) is the required action's provider id (`native-passkey-register`), not an execution id (11 D1); `required` is always `true`. `authenticator_selection` MAY also carry `require_resident_key: true`. Error codes: `missing_credential`, `invalid_attestation` (attestation did not parse/verify, policy violation, duplicate credential; a fresh `challenge` is issued with the re-challenge).

### 4.5 `totp` — authenticator-app code

params: `{ "digits": 6, "period": 30, "algorithm": "HmacSHA1", "credential_labels": ["Phone"], "credentials": [ { "id": "…", "label": "Phone" } ] }`
response: `totp=<digits>` and optionally `credential_id` (one of `params.credentials[].id`) when the user has several OTP credentials; omitted → the user's default OTP credential.

### 4.6 `otp` — code delivered out of band (email / SMS)

params:
```json
{ "channel": "email", "destination_masked": "a***@example.com", "digits": 6, "ttl": 300,
  "resend_allowed_at": 1760000000, "sent": true }
```
`sent` says whether a code is currently outstanding. The server sends a code without being asked only when `otp` is the **only** entry of the challenge set (`required: true`); when it is one of several alternatives the descriptor arrives with `sent: false` and the client requests the first code with `action=resend` (no side effect before the user picks the factor, cf. §4.9). `resend_allowed_at` (absent while `sent` is `false`) is the earliest time another `action=resend` is accepted; `ttl` is the code lifetime in seconds from sending.
response: `otp=<digits>`; or `action=resend` (no code) to (re)send a code.
Error codes on the descriptor: `missing_credential` (empty `otp`), `invalid_credential` (wrong code; counted as a failure), `expired_code` (the code's `ttl` passed or too many wrong attempts consumed it: `sent` is `false`, the client must resend), `resend_too_soon` (`action=resend` before `resend_allowed_at`; not a failure). After five wrong attempts the outstanding code is invalidated.
Delivery goes through the `native-otp-sender` SPI (13 D4): `email` uses the realm's SMTP settings, `sms-webhook` POSTs JSON to a configured URL. `channel` and `destination_masked` come from the sender.

### 4.7 `push` — approve on an enrolled device (cross-device)

params:
```json
{ "sent": true, "cid": "1a6d…", "expires_at": 1760000300, "poll_interval": 3, "status": "pending",
  "user_verification": { "type": "number_match", "number": "42" },   // optional; the number to show on THIS client
  "devices": [ { "label": "Alice's iPhone" } ] }
```
A push challenge is created (and the notification sent through the server's push provider) only when `push` is the **single** entry of the set, or when the client asks for it with `action=resend` (the §4.6 rule: no cost before the user picks the factor); until then the descriptor arrives with `sent: false` and only `devices`. Once sent, the client shows "Approve the sign-in on *Alice's iPhone*" (plus `user_verification.number` for number match — the device shows three numbers and the user picks this one) and polls by re-POSTing `challenge_type=push&challenge_id=…&action=poll` every `poll_interval` seconds. Each poll answers the same challenge with `params.status` ∈ `pending|approved|denied|expired`: on `approved` the processor advances automatically (the poll response is then the next challenge or the code); `denied` comes with `error.code = "denied"` (a failed attempt, the device user refused) and `expired` with `error.code = "expired"`, both with `sent: false` so the client may `action=resend`. `action=cancel` ends the native session (§2.2); the pending push challenge then expires on its own. The Keycloak implementation issues the challenge through the ba-itsys challenge store, so the approving device uses the §7 API unchanged.

### 4.8 `recovery_code`

params: `{ "remaining": 7, "warning_threshold": 4 }` · response: `recovery_code=<string>`
A code is a single-use string from the user's recovery-codes credential (Keycloak's *Recovery Authentication Codes*, `recovery-authn-codes`); the server accepts it with or without the `-` separators and case-insensitively. `remaining` is the number of unused codes **before** this attempt; `warning_threshold` is the realm's `recoveryCodesWarningThreshold` password-policy value (clients SHOULD tell the user to generate new codes once `remaining` is at or below it). Error codes on the descriptor: `missing_credential` (empty), `invalid_credential` (wrong or already used code; counted as a failure). Eligibility: offered only to an identified user who has a recovery-codes credential with at least one unused code. Enrolment of new codes is not part of this profile (the account console or `CONFIGURE_RECOVERY_AUTHN_CODES` in a browser).

### 4.9 `select` — explicit factor chooser (optional)

Issued only when the server prefers the client to choose before any factor-specific setup cost is incurred (e.g. to avoid sending an SMS). params: `{ "options": [ { "type": "passkey", "id": "…", "label": "…" }, { "type": "otp", "id": "…", "label": "Text me a code" } ] }` · response: `action=select&challenge_type=select&selected_id=<id>`. Most deployments will instead rely on §3.2's multi-entry `challenges[]`.

### 4.10 `redirect_to_web`

Not a challenge descriptor — it is the §3.4 error. Listed in `challenge_types_supported` so clients know the server may emit it.

### 4.11 Required-action challenge types (common rules)

Besides `passkey_registration` (§4.4), the Keycloak implementation serves three of Keycloak's built-in required actions in-band: `update_password`, `verify_email` and `terms` (08 Q7). They share the §4.4 rules: the descriptor's `id` (echoed as `challenge_id`) is the native required action's **provider id** (`native-update-password`, `native-verify-email`, `native-terms`), `required` is always `true`, the descriptor is the only entry of the set, and the authentication session is bound to the realm's *user action* timeout while one is pending. A native required action is used in two ways: assigned to the user directly under its own alias, or **substituted** for the corresponding Keycloak action (`UPDATE_PASSWORD`, `VERIFY_EMAIL`, `TERMS_AND_CONDITIONS`) when that one is pending and the native variant is registered and enabled in the realm; on success the pending Keycloak action is removed from the user, so the browser flow and the admin console keep using Keycloak's own pages. Any other pending required action (and a substituted one whose native variant cannot serve the user, e.g. `VERIFY_EMAIL` for a user without an e-mail address) ends with §3.4 `redirect_to_web`. `action=cancel` aborts the login as usual.

### 4.12 `update_password` — set a new password (required action)

params:
```json
{ "username": "carol",
  "policy": { "length": 8, "digits": 1, "upperCase": 1, "lowerCase": 1, "specialChars": 1, "notUsername": true, "notEmail": true, "maxLength": 64, "passwordHistory": 3, "regexPattern": "^[a-z]+$" } }
```
`policy` lists the realm's password-policy entries by Keycloak policy id with their configured value (`true` for entries without a value); hashing-related entries (`hashAlgorithm`, `hashIterations`, `passwordBlacklist`, `forceExpiredPasswordChange`, `passwordAge`, `recoveryCodesWarningThreshold`, `maxAuthAge`) are omitted. Clients MAY pre-validate; the server always validates.
response: `password=<new password>`, `password_confirm=<the same value>`.
Error codes on the descriptor (none counts as a brute-force failure): `missing_credential` (`password` empty), `password_mismatch` (`password_confirm` differs), `invalid_password` (the realm's password policy rejected it; `error.message` is the policy's message in the request's locale, e.g. *Invalid password: minimum length 8.*).
On success the password is replaced (Keycloak's `PasswordCredentialProvider`, so history/expiry policies apply) and the flow continues (next required action, else the code). Other sessions are not logged out (Keycloak's "sign out other devices" checkbox has no equivalent here).

### 4.13 `verify_email` — confirm the e-mail address with a code (required action)

params:
```json
{ "email_masked": "g***@example.com", "digits": 6, "ttl": 300, "sent": true, "resend_allowed_at": 1760000000 }
```
The server sends a code to the user's e-mail address through the `native-otp-sender` `email` provider (§4.6) **as soon as the challenge is issued** (a required action is always the single entry); `sent` is `false` only when delivery failed or the previous code expired / was exhausted. `ttl`, `resend_allowed_at` and the error codes follow §4.6: response `code=<digits>`, or `action=resend` to request another code. Error codes: `missing_credential`, `invalid_credential` (wrong code; after the configured number of wrong codes the code is invalidated → `expired_code` with `sent: false`), `expired_code`, `resend_too_soon`. On success the user's e-mail is marked verified (Keycloak event `VERIFY_EMAIL`) and the flow continues. Note that this differs from Keycloak's browser action, which sends a *link*; the native variant never asks the user to leave the app.

### 4.14 `terms` — accept terms and conditions (required action)

params:
```json
{ "text": "By continuing you agree …", "url": "https://example.com/terms", "version": "2026-10" }
```
At least one of `text` / `url` is present (they come from the native required action's configuration in the realm: `terms-text`, `terms-url`, `terms-version`; the client renders `text` and/or offers `url`). response: `accepted=true` to accept; `accepted=false` to decline, which ends the login with `403 access_denied` (`error_description` = `required_action:… declined`) exactly like declining Keycloak's own page. Any other value re-issues the challenge with `error.code = "missing_credential"`. On acceptance the user attribute `terms_and_conditions` is set to the acceptance time (the attribute Keycloak's `TERMS_AND_CONDITIONS` action uses) and the flow continues.

### 4.15 `push_enrollment` — enrol this device for push MFA mid-flow (required action)

Served by `native-push-enroll`, which substitutes for ba-itsys' `push-mfa-register` (§4.11 rules: `id` = `native-push-enroll`, `required: true`). params:
```json
{ "enrollment_token": "<realm-signed JWT, typ push-enroll-challenge>", "expires_in": 240,
  "device_api_base": "https://idp.example.com/realms/demo/push-mfa", "user_id": "<sub>" }
```
The client builds the same device-signed enrolment JWT it would POST to `/push-mfa/enroll/complete` (§7: `sub`, `enrollmentId`, `nonce`, `cnf.jwk`, `credentialId`, `deviceId`, `deviceType`, `deviceLabel`, `pushProviderType`, `pushProviderId`) and answers with `token=<that JWT>`; the server verifies it exactly as `/push-mfa/enroll/complete` would and creates the credential — no device access token is needed mid-flow. When the native session is DPoP-bound (§8) the JWT's `cnf.jwk` MUST be the session's DPoP key (`invalid_credential` otherwise), which is also what §7.1 requires later. A client that enrolled through `/push-mfa/enroll/complete` instead answers `action=check`. Error codes: `missing_credential` (no `token`), `invalid_credential` (signature, nonce, `enrollmentId`, expiry or key mismatch; a fresh enrolment token is issued with the re-challenge), `expired_code` (the enrolment challenge expired; re-challenge carries a new one).

### 4.16 Extension types

Types not understood by a client MUST be ignored unless they are the only `required` challenge, in which case the client MUST surface an "unsupported authentication method, update the app or use the web" error and MAY retry with `action=cancel`. New types MUST be namespaced (`x-vendor-foo`) until added to this profile.

---

## 5. Session semantics

- `auth_session` is opaque (a JWE). Encodes `{ root_session_id, tab_id, client_id, issued_at, dpop_jkt? }`. Lifetime = realm *login timeout* (default 30 min) while a flow is in progress; after code issuance it is re-minted (post-login shape, pointing at the user session) with lifetime = the realm's SSO *idle* timeout, capped by the SSO session max, so it can be used for step-up while the session is in use; an expired or ended-session value is `invalid_session` and the client logs in again (14 D6).
- A new `auth_session` value MAY be returned on **any** response; the client MUST always replace its stored copy.
- Step-up / re-authentication (13 D1): send the **post-login** `auth_session` together with a complete §2.1 request (new PKCE pair, `scope`, and `acr_values` and/or `max_age`/`prompt=login`). The server checks that the client matches, that the user session behind the value is still valid and the user enabled (else `invalid_session`: start a fresh login), and the DPoP binding (§8). It then runs the native flow as an SSO re-authentication: the user is already identified (the `username` challenge is skipped and `context.username` is set from the first response), the levels already authenticated in the user session are carried over, and only the "Condition - Level of Authentication" sub-flows whose level the request needs produce challenges. `acr_values` is mapped to a level through the client/realm ACR-to-LoA map, or taken literally when numeric (Keycloak semantics). `max_age` (when the authentication is older) and `prompt=login` force every level to be authenticated again. When nothing has to be asked the server answers `200` with a code at once. On success a new code is issued for the **same** user session (same `sid`), the tokens carry the new `acr` and, when a factor was run, a new `auth_time`; the success body carries a fresh post-login `auth_session`. A flow without LoA conditions re-runs all its factors.
- Freshness for §6: `/passkey/register/*` answer a stale authentication with `403 insufficient_authorization` **plus** `auth_session` (post-login) and `max_age` (the realm's limit); the client steps up with that `auth_session` and `max_age`, then retries.
- Re-authentication triggered by the token endpoint: a refresh request MAY answer `400 {"error":"insufficient_authorization","auth_session":"…"}`; the client then enters §2.1 with that `auth_session`. (Not emitted by the Keycloak implementation today; the SDK handles it.)
- Logout: client discards `auth_session` and calls the standard logout/revocation endpoints.

---

## 6. Passkey registration (authenticated)

For enrolling a passkey from inside the app after login (not mid-flow):

1. `POST /native-auth/passkey/register/options` with `Authorization: Bearer|DPoP <access_token>` (no body) → `200` with §4.4 `params` plus `registration_id`.
2. App performs `ASAuthorizationPlatformPublicKeyCredentialProvider.createCredentialRegistrationRequest`.
3. `POST /native-auth/passkey/register/finish` (JSON body: `registration_id`, `credential_id`, `client_data_json`, `attestation_object`, `transports` — comma-separated string or array —, `label`) → `201 { "credential_id": "…", "label": "…" }`.

Policy (attestation conveyance, UV requirement, allowed algorithms, exclude-credentials) comes from the realm's WebAuthn Passwordless policy.

Errors: `401 invalid_token` (+ `WWW-Authenticate: Bearer …`) when the token is missing, invalid, expired or has no user session; `403 insufficient_authorization` when the authentication behind the token is older than the realm's `native-auth.passkey-registration-max-age` (default 300 s; 07 §5) — the body carries `auth_session` (post-login, for the token's user session and client) and `max_age` so the client can step up (§5) and retry; `400 invalid_request` for a malformed body, an unknown/expired/already used `registration_id`, or an attestation that does not verify (`error_description` is user-safe). `registration_id` is single use and valid for the realm's user-action timeout.

---

## 7. Push MFA device API

The device-facing API is **exactly** ba-itsys' documented API (`docs/api-reference.md`, `docs/flow-details.md`). Summary for completeness; the upstream docs are normative:

| Step | Endpoint | Notes |
|------|----------|-------|
| Obtain enrolment token | (a) scan QR / open deep link from the browser required action, (b) **`POST /native-auth/push/enroll/start`** (this profile's addition; `Authorization: Bearer|DPoP <access token>` from a native login, subject to the §6 freshness rule) → `{ "enrollment_token": "<realm-signed JWT>", "expires_in": 240, "device_api_base": "…", "user_id": "<sub>" }`, or (c) the mid-flow §4.15 challenge | The token has `typ: push-enroll-challenge`, `iss`, `aud` (realm), `sub`, `username`, `enrollmentId`, `nonce`, `exp`. Verify against realm JWKS. |
| Generate device key | ES256 in Secure Enclave; pick `credentialId` (random, app-local handle) and `deviceId` (stable UUID). With `device_token: native` (§7.1) the device key **is** the client's DPoP key (§8). | |
| Get DPoP-bound access token | `device_token: native`: none to get — the user's native access token is DPoP-bound to the same key. `client_credentials`: `POST /protocol/openid-connect/token` `grant_type=client_credentials&client_id={device_client_id}&client_secret=…` with a `DPoP` header | §7.1 |
| Complete enrolment | `POST /push-mfa/enroll/complete` (DPoP) body `{ "token": "<device-signed JWT with cnf.jwk, credentialId, deviceId, deviceType:"ios", pushProviderType:"apns", pushProviderId:<APNs token>, deviceLabel>" }` → `{ "status": "enrolled" }` | |
| Receive push | APNs payload contains `confirmToken` (realm-signed; `credId`, `cid`, `typ`, `ver`, `exp`). Verify, resolve `credId` locally. | Silent/background push + visible notification; see 05. |
| Fetch context | `GET /push-mfa/login/pending?userId=<sub>` (DPoP) → challenges with `username`, `clientId`, `clientName`, `expiresAt`, optional `userVerification` (`number-match` with 3 numbers, or `pin`). | Show client name, time, and (if available via ba-itsys events/extensions) IP/location. |
| Respond | `POST /push-mfa/login/challenges/{cid}/respond` (DPoP) body `{ "token": "<device-signed JWT: cid, credId, deviceId, action:approve|deny, userVerification?, exp>" }` → `{ "status": "approved" }` | 409 = concurrent resolution; re-read state. |
| Maintenance | `PUT /push-mfa/device/push-provider` on APNs token change; `PUT /push-mfa/device/rotate-key`; `POST /push-mfa/login/lockout` panic button. | |

Keycloak-side, scenario B (§02 Architecture §3) exposes the same challenge through the native flow as a §4.7 `push` challenge; the approving device uses this API unchanged.

### 7.1 Device token (08 Q6, 14 D9)

ba-itsys' device API accepts any access token of the realm that is active and DPoP-bound to the key presented in the `DPoP` proof (`cnf.jkt` = thumbprint of the enrolled `cnf.jwk`), with the proof additionally carrying `sub` (the Keycloak user id) and `deviceId`. Keycloak 26.8's standard token exchange refuses public clients, so the 08 Q6 (b) exchange from the app's native token is not possible; instead the Keycloak Native profile makes the **DPoP key the device key**: the app enrols `cnf.jwk` = its DPoP public key and then calls the device API with `Authorization: DPoP <its own native access token>` (token endpoint binding, §8) plus a proof signed by that key with `htm`, `htu`, `ath`, `iat`, `jti`, `sub`, `deviceId`. No client secret ships and no second client is needed (`push.device_token = "native"`). The SDK keeps `DeviceTokenProvider` abstract so a deployment with a stock ba-itsys install can plug in `client_credentials` on a device client.

---

## 8. DPoP profile

- Algorithms: `ES256` (preferred), `RS256`.
- Proof JWT header `typ: dpop+jwt`, `jwk` = device public key; payload `htm`, `htu` (no query/fragment), `iat`, `jti`, `ath` when an access token is presented, `nonce` if the server issued one.
- Native login flow: the client MAY send `DPoP` on every `/native-auth/challenge` request and MUST then send it on every later request of that session and on the token request, with the same key. The server verifies the proof (`htm` = `POST`, `htu` = the challenge endpoint URL without query, `iat` within the proof lifetime, `jti` single use; no `ath`, no nonce) and binds the in-flow `auth_session`, the post-login `auth_session` and the authorization code (`dpop_jkt`) to the key's thumbprint (`jkt`): a continuation or step-up with another key or without a proof is `invalid_session`, a code exchange with another key is refused by the token endpoint. A session started without a proof stays unbound; a proof on a later request of such a session is verified but does not bind.
- Push device API: required by ba-itsys; additionally carries `sub` and `deviceId` claims in the proof as that extension specifies.
- Implementation note (12 D2, 13 D3): Keycloak's own DPoP support binds **tokens** when the token request carries a `DPoP` header (`token_type: "DPoP"`, `cnf.jkt`), and the bearer-authenticated endpoints of §6 then require `Authorization: DPoP <token>` plus a proof with `ath`. Since Phase 2 the challenge endpoint verifies proofs and binds `auth_session` and the code as described above; `dpop_signing_alg_values_supported` lists the verified algorithms. Clients MUST still read `token_type` to learn whether their tokens are bound (an operator may disable the feature).

---

## 9. Client attestation (reserved, Phase 4)

Requests MAY carry `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers per `draft-ietf-oauth-attestation-based-client-auth`. The attestation JWT is issued by a backend attestation service that validates Apple App Attest / Google Play Integrity. When `metadata.client_attestation.required` is true, the challenge endpoint returns `client_attestation_required` without them. Nothing else in this profile changes.

---

## 10. Versioning & compatibility rules

- `protocol_version` is a string; clients compare major numbers only. Servers MUST keep `1.x` responses backward compatible: new optional fields and new challenge types may be added; existing fields may not change type or meaning.
- Clients MUST ignore unknown fields.
- Servers MUST reject unknown continuation parameters with `invalid_request` only when they conflict with known ones; otherwise ignore.

### 10.1 v1.0-rc freeze (15 October 2026, 04 §8, 14 D8)

The following is frozen as **v1.0-rc**: §1.1 metadata (except the `push` block), §2, §3.1–§3.5, §4.1–§4.6, §4.8, §4.10–§4.14, §5, §6 and §8. Changes to these sections before v1.0 are limited to additive optional fields and clarifications; a field rename or a changed status code would be a 2.x. Still **draft** in this document: §4.7 `push`, §7 (the push device API), §1.1's `push` block and `/push/enroll/start` (Phase 3), §4.9 `select` (unimplemented, optional) and §9 attestation (Phase 4). The conformance suite for the frozen parts is the recorded transcript set `keycloak-native-auth/demo/transcripts/` (one file per integration test, 12 D1): a server is conformant when the same integration tests pass against it, a client when it replays the transcripts as the iOS SDK does.

## 11. Example end-to-end transcript (curl)

```bash
B=https://idp.example.com/realms/demo
# 1. start
curl -s -X POST $B/native-auth/challenge -H 'Accept: application/json' \
  -d client_id=demo-ios -d response_type=code -d scope='openid profile' \
  -d code_challenge=$CC -d code_challenge_method=S256
# -> 403 insufficient_authorization, auth_session=S1, challenges=[{type:username,id:E1}]

# 2. username
curl -s -X POST $B/native-auth/challenge -d auth_session=$S1 -d challenge_type=username -d challenge_id=E1 -d username=alice
# -> 403, auth_session=S2, challenges=[{type:passkey,id:E2,params:{challenge,rp_id,allow_credentials}}, {type:password,id:E3,required:false}]

# 3. passkey assertion (done with the platform API)
curl -s -X POST $B/native-auth/challenge -d auth_session=$S2 -d challenge_type=passkey -d challenge_id=E2 \
  -d credential_id=… -d client_data_json=… -d authenticator_data=… -d signature=…
# -> 403, auth_session=S3, challenges=[{type:totp,id:E4}]

# 4. totp
curl -s -X POST $B/native-auth/challenge -d auth_session=$S3 -d challenge_type=totp -d challenge_id=E4 -d totp=123456
# -> 200 {"authorization_code":"C","auth_session":"S4"}

# 5. tokens
curl -s -X POST $B/protocol/openid-connect/token -d grant_type=authorization_code -d client_id=demo-ios -d code=C -d code_verifier=$CV

# 6. later: step up to acr "2" inside the same user session (§5), with a new PKCE pair
curl -s -X POST $B/native-auth/challenge -d client_id=demo-ios -d response_type=code -d scope=openid \
  -d code_challenge=$CC2 -d code_challenge_method=S256 -d acr_values=2 -d auth_session=$S4
# -> 403, context.step_up=true, context.username=alice, challenges=[{type:totp,id:E5}]  (no username step)
curl -s -X POST $B/native-auth/challenge -d auth_session=$S5 -d challenge_type=totp -d challenge_id=E5 -d totp=123456
# -> 200 {"authorization_code":"C2","auth_session":"S6"}; tokens from C2 carry acr=2 and the same sid
```
