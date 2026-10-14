# 03 — Keycloak Native Authentication Profile (protocol specification)

**Profile version:** `1` (draft for review)
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
| GET | `/native-auth/metadata` | none | Discovery: protocol version, supported challenge types, endpoint URLs, RP ID. |
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
  "code_exchange": { "redirect_uri_required": false },
  "passkey": { "rp_id": "idp.example.com", "register_options_endpoint": "…", "register_finish_endpoint": "…" },
  "push": { "enabled": true, "enroll_start_endpoint": "…", "device_api_base": "https://idp.example.com/realms/demo/push-mfa", "device_client_id": "push-device-client" },
  "challenge_types_supported": ["username", "password", "passkey", "totp", "otp", "push", "recovery_code", "select", "redirect_to_web"],
  "dpop_signing_alg_values_supported": ["ES256", "RS256"],
  "client_attestation": { "required": false, "methods": [] }
}
```

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
| `auth_session` | opt | Present when continuing a previous session (step-up, re-auth after `insufficient_authorization` from the token endpoint). |
| `device_name`, `device_id` | opt | Free-text label + stable app-generated UUID; used in events and push prompts. |

Optional headers: `DPoP: <proof>` (see §8). If present on the first request, the server binds `auth_session` and the eventual authorization code to the key (FiPA §9.5.1/9.6.1) and MUST reject later requests presenting a different key.

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

`auth_session` MAY be present; if so the client MUST store it (needed for step-up). Exchange the code at the token endpoint with `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, and **no** `redirect_uri` — unless metadata says otherwise: `code_exchange.redirect_uri_required` is `false` by default (Keycloak accepts a code stored without a redirect URI when the token request omits the parameter; verified in 09 Q1). When it is `true` the client MUST send exactly `code_exchange.redirect_uri` (operator-chosen `sentinel` or `client-fixed` mode).

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

- `challenges` is ordered by server preference. Entries are the **ALTERNATIVE** executions currently eligible; the client MAY present a chooser or auto-pick the first it supports.
- `context` is informational, present once the user is identified. Never include secrets.
- `expires_in` is the remaining lifetime of the authentication session.

### 3.3 Challenge descriptor (common fields)

```json
{
  "type": "passkey",
  "id": "4f2e…",            // execution id, echo as challenge_id
  "label": "Sign in with a passkey",
  "required": true,          // false when it is one of several alternatives
  "retry": { "remaining": 3 },      // optional; present after a failed attempt
  "error": { "code": "invalid_credential", "message": "…" },  // optional; the previous attempt failed
  "params": { …type-specific… }
}
```

### 3.4 Redirect to web

`403 Forbidden`

```json
{ "error": "redirect_to_web", "request_uri": "urn:ietf:params:oauth:request_uri:…", "expires_in": 90, "reason": "required_action:TERMS_AND_CONDITIONS" }
```

The client MUST open the system browser (`ASWebAuthenticationSession`) on the realm's authorization endpoint with `client_id` and `request_uri` (PAR, RFC 9126) and complete a normal code flow. `request_uri` is only returned if the initial request carried a PKCE challenge. `reason` is informational (e.g. an unsupported required action, risk decision, account locked).

### 3.5 Other errors

| HTTP | `error` | Meaning |
|------|---------|---------|
| 400 | `invalid_request` | Malformed / missing parameter, unknown `challenge_type`, `challenge_id` not pending. |
| 400 | `invalid_session` | `auth_session` missing, expired, revoked, cancelled, or bound to a different DPoP key / client. Client restarts from §2.1. |
| 400 | `invalid_dpop_proof` | Per RFC 9449. |
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
Failure: the server MUST NOT reveal whether the user exists; it re-issues the challenge set as if the user existed, with `error.code = "invalid_user"` only when realm policy permits (configurable; default: generic).

### 4.2 `password`

params: `{ "username_known": true }`
response: `password=<string>`
Notes: supports realm brute-force detection via the processor. The SDK MUST send over TLS only and never log the value.

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
The server verifies via `WebAuthnCredentialProvider` using the stored challenge from the auth session. `rp_id` MUST equal the realm's configured WebAuthn RP ID, and the app MUST have an Associated Domains `webcredentials:` entry for it.

### 4.4 `passkey_registration` — WebAuthn attestation mid-flow (required action)

Used when the flow requires passkey enrolment (`webauthn-register`-style required action) and the client supports it. params mirror `PublicKeyCredentialCreationOptions`:
```json
{ "challenge": "…", "rp": { "id": "…", "name": "…" }, "user": { "id": "b64url", "name": "alice", "display_name": "Alice" },
  "pub_key_cred_params": [ { "type": "public-key", "alg": -7 } ], "authenticator_selection": { "resident_key": "required", "user_verification": "required", "authenticator_attachment": "platform" },
  "attestation": "none", "exclude_credentials": [ … ], "timeout": 60000 }
```
response: `credential_id`, `client_data_json`, `attestation_object`, `transports` (comma-separated), `label` (optional user-visible name).
The same payloads are used by the standalone `/native-auth/passkey/register/*` endpoints (§6).

### 4.5 `totp` — authenticator-app code

params: `{ "digits": 6, "period": 30, "algorithm": "HmacSHA1", "credential_labels": ["Phone"], "credentials": [ { "id": "…", "label": "Phone" } ] }`
response: `totp=<digits>` and optionally `credential_id` (one of `params.credentials[].id`) when the user has several OTP credentials; omitted → the user's default OTP credential.

### 4.6 `otp` — code delivered out of band (email / SMS)

params:
```json
{ "channel": "email", "destination_masked": "a***@example.com", "digits": 6, "ttl": 300,
  "resend_allowed_at": 1760000000, "sent": true }
```
On first issue the server sends the code and sets `sent: true`. response: `otp=<digits>`; or `action=resend` (no code) to request a new one, subject to `resend_allowed_at`.
Delivery is via the `native-auth` email sender (Keycloak's `EmailSenderProvider`) or a pluggable SMS SPI (`NativeOtpSender`), see 04.

### 4.7 `push` — approve on an enrolled device (cross-device)

params:
```json
{ "cid": "1a6d…", "expires_at": 1760000300, "poll_interval": 3,
  "user_verification": { "type": "number_match", "number": "42" },   // optional; the number to show on THIS client
  "devices": [ { "label": "Alice's iPhone" } ] }
```
The client shows "Approve the sign-in on *Alice's iPhone*" (plus the number if `number_match`) and polls by re-POSTing with `challenge_type=push&challenge_id=…&action=poll` at `poll_interval`. Responses: the same challenge with `params.status` ∈ `pending|approved|denied|expired`; on `approved` the processor advances automatically (the poll response will then be the next challenge or the code). `action=cancel` denies.

### 4.8 `recovery_code`

params: `{ "remaining": 7 }` · response: `recovery_code=<string>`

### 4.9 `select` — explicit factor chooser (optional)

Issued only when the server prefers the client to choose before any factor-specific setup cost is incurred (e.g. to avoid sending an SMS). params: `{ "options": [ { "type": "passkey", "id": "…", "label": "…" }, { "type": "otp", "id": "…", "label": "Text me a code" } ] }` · response: `action=select&challenge_type=select&selected_id=<id>`. Most deployments will instead rely on §3.2's multi-entry `challenges[]`.

### 4.10 `redirect_to_web`

Not a challenge descriptor — it is the §3.4 error. Listed in `challenge_types_supported` so clients know the server may emit it.

### 4.11 Extension types

Types not understood by a client MUST be ignored unless they are the only `required` challenge, in which case the client MUST surface an "unsupported authentication method, update the app or use the web" error and MAY retry with `action=cancel`. New types MUST be namespaced (`x-vendor-foo`) until added to this profile.

---

## 5. Session semantics

- `auth_session` is opaque (a JWE). Encodes `{ root_session_id, tab_id, client_id, issued_at, dpop_jkt? }`. Lifetime = realm *login timeout* (default 30 min) while a flow is in progress; after code issuance it is re-minted with lifetime = SSO session max so it can be used for step-up.
- A new `auth_session` value MAY be returned on **any** response; the client MUST always replace its stored copy.
- Step-up: send `auth_session` + `acr_values` (+ `max_age`) in a §2.1 request. The server resumes the user's SSO session, runs the native flow with LoA conditions, and only the executions needed for the requested level produce challenges. On success a new code is issued; the resulting tokens carry the new `acr`.
- Re-authentication triggered by the token endpoint: a refresh request MAY answer `400 {"error":"insufficient_authorization","auth_session":"…"}`; the client then enters §2.1 with that `auth_session`.
- Logout: client discards `auth_session` and calls the standard logout/revocation endpoints.

---

## 6. Passkey registration (authenticated)

For enrolling a passkey from inside the app after login (not mid-flow):

1. `POST /native-auth/passkey/register/options` with `Authorization: Bearer|DPoP <access_token>` → `200` with §4.4 `params` plus `registration_id`.
2. App performs `ASAuthorizationPlatformPublicKeyCredentialProvider.createCredentialRegistrationRequest`.
3. `POST /native-auth/passkey/register/finish` (JSON body: `registration_id`, `credential_id`, `client_data_json`, `attestation_object`, `transports`, `label`) → `201 { "credential_id": "…", "label": "…" }`.

Policy (attestation conveyance, UV requirement, allowed algorithms, exclude-credentials) comes from the realm's WebAuthn Passwordless policy.

---

## 7. Push MFA device API

The device-facing API is **exactly** ba-itsys' documented API (`docs/api-reference.md`, `docs/flow-details.md`). Summary for completeness; the upstream docs are normative:

| Step | Endpoint | Notes |
|------|----------|-------|
| Obtain enrolment token | (a) scan QR / open deep link from the browser required action, or (b) **`POST /native-auth/push/enroll/start`** (this profile's addition; requires an access token from a native login) → `{ "enrollment_token": "<realm-signed JWT>", "device_client_id": "…" }` | The token has `typ: push-enroll-challenge`, `sub`, `username`, `enrollmentId`, `nonce`, `exp`. Verify against realm JWKS. |
| Generate device key | ES256 in Secure Enclave; pick `credentialId` (random, app-local handle) and `deviceId` (stable UUID). | |
| Get DPoP-bound access token | `POST /protocol/openid-connect/token` `grant_type=client_credentials&client_id={device_client_id}&client_secret=…` with `DPoP` header | See 08 Q6 regarding the client secret in a public app. |
| Complete enrolment | `POST /push-mfa/enroll/complete` (DPoP) body `{ "token": "<device-signed JWT with cnf.jwk, credentialId, deviceId, deviceType:"ios", pushProviderType:"apns", pushProviderId:<APNs token>, deviceLabel>" }` → `{ "status": "enrolled" }` | |
| Receive push | APNs payload contains `confirmToken` (realm-signed; `credId`, `cid`, `typ`, `ver`, `exp`). Verify, resolve `credId` locally. | Silent/background push + visible notification; see 05. |
| Fetch context | `GET /push-mfa/login/pending?userId=<sub>` (DPoP) → challenges with `username`, `clientId`, `clientName`, `expiresAt`, optional `userVerification` (`number-match` with 3 numbers, or `pin`). | Show client name, time, and (if available via ba-itsys events/extensions) IP/location. |
| Respond | `POST /push-mfa/login/challenges/{cid}/respond` (DPoP) body `{ "token": "<device-signed JWT: cid, credId, deviceId, action:approve|deny, userVerification?, exp>" }` → `{ "status": "approved" }` | 409 = concurrent resolution; re-read state. |
| Maintenance | `PUT /push-mfa/device/push-provider` on APNs token change; `PUT /push-mfa/device/rotate-key`; `POST /push-mfa/login/lockout` panic button. | |

Keycloak-side, scenario B (§02 Architecture §3) exposes the same challenge through the native flow as a §4.7 `push` challenge; the approving device uses this API unchanged.

---

## 8. DPoP profile

- Algorithms: `ES256` (preferred), `RS256`.
- Proof JWT header `typ: dpop+jwt`, `jwk` = device public key; payload `htm`, `htu` (no query/fragment), `iat`, `jti`, `ath` when an access token is presented, `nonce` if the server issued one.
- Native login flow: the client MAY send `DPoP` on every `/native-auth/challenge` request and MUST then send it on the token request with the same key; the server binds `auth_session` and the code to the key's thumbprint (`jkt`).
- Push device API: required by ba-itsys; additionally carries `sub` and `deviceId` claims in the proof as that extension specifies.

---

## 9. Client attestation (reserved, Phase 4)

Requests MAY carry `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers per `draft-ietf-oauth-attestation-based-client-auth`. The attestation JWT is issued by a backend attestation service that validates Apple App Attest / Google Play Integrity. When `metadata.client_attestation.required` is true, the challenge endpoint returns `client_attestation_required` without them. Nothing else in this profile changes.

---

## 10. Versioning & compatibility rules

- `protocol_version` is a string; clients compare major numbers only. Servers MUST keep `1.x` responses backward compatible: new optional fields and new challenge types may be added; existing fields may not change type or meaning.
- Clients MUST ignore unknown fields.
- Servers MUST reject unknown continuation parameters with `invalid_request` only when they conflict with known ones; otherwise ignore.

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
```
