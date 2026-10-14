# 02 — Architecture

## 1. Components

```
┌──────────────────────────────┐      ┌──────────────────────────────────────────────┐
│  iOS app (example)           │      │  Keycloak 26.x                               │
│  ┌────────────────────────┐  │      │  ┌────────────────────────────────────────┐  │
│  │ KeycloakNativeUI       │  │      │  │ native-auth-endpoint (RealmResource)   │  │
│  │  default SwiftUI       │  │      │  │  POST /native-auth/challenge           │  │
│  │  challenge screens     │  │      │  │  GET  /native-auth/metadata            │  │
│  ├────────────────────────┤  │ HTTPS│  │  POST /native-auth/passkey/register/*  │  │
│  │ KeycloakNativeCore     │◄─┼──────┼─►│  POST /native-auth/push/enroll/*       │  │
│  │  challenge state       │  │      │  ├────────────────────────────────────────┤  │
│  │  machine, DPoP, PKCE,  │  │      │  │ AuthenticationProcessor over the       │  │
│  │  CredentialsManager    │  │      │  │ realm's "native" flow                  │  │
│  ├────────────────────────┤  │      │  │  ┌──────────────┐ ┌──────────────────┐ │  │
│  │ KeycloakNativePush     │◄─┼──────┼─►│  │ native-auth- │ │ ba-itsys push-mfa│ │  │
│  │  APNs token, approve/  │  │      │  │  │ authenticators│ │ + APNs sender    │ │  │
│  │  deny, number-match    │  │      │  │  └──────────────┘ └──────────────────┘ │  │
│  └────────────────────────┘  │      │  ├────────────────────────────────────────┤  │
└──────────────────────────────┘      │  │ standard token endpoint (PKCE, DPoP)   │  │
                                      │  └────────────────────────────────────────┘  │
       ▲                              └──────────────────────────────────────────────┘
       │ APNs push (confirmToken)              ▲
       └───────────────── APNs ────────────────┘
```

Three deliverables, one contract:

1. **Keycloak extensions** (`keycloak-native-auth`, Java, Maven multi-module) — see `04-keycloak-extensions-plan.md`.
2. **iOS SDK** (`KeycloakNative`, Swift Package, three products) — see `05-ios-sdk-plan.md`.
3. **Example iOS app** — see `06-example-ios-app.md`.

All three implement `03-protocol-spec.md`. A fourth artefact, the **conformance suite** (HTTP-level tests runnable against any Keycloak with the extensions), is what makes the "stable protocol for non-SDK developers" promise real.

## 2. How a native login maps onto Keycloak

Keycloak already has everything needed to *decide* what a user must do: authentication flows, executions with REQUIRED/ALTERNATIVE/CONDITIONAL, credential providers, required actions, ACR/LoA mapping. What it lacks is a *transport* other than browser forms. The design keeps Keycloak as the brain and only swaps the transport:

```
App                       native-auth-endpoint                   AuthenticationProcessor / flow
 │  POST challenge          │                                         │
 │  (client_id, scope,      │  create RootAuthSession + tab,          │
 │   pkce, acr_values)      │  set client, protocol, notes            │
 │ ────────────────────────►│  processor.authenticate()  ─────────────►│ exec 1: native-username  → challenge(JSON)
 │ ◄──────────────────────  │  403 insufficient_authorization         │
 │   auth_session,          │   challenges:[{type:"username"}]        │
 │   challenges[]           │                                         │
 │  POST challenge          │  decode auth_session → load session,    │
 │  (auth_session,          │  set execution, processor.action()  ────►│ exec 1 action(): validate → SUCCESS
 │   challenge_type,        │  processor continues ───────────────────►│ exec 2: native-passkey   → challenge(JSON)
 │   username)              │                                         │
 │ ◄──────────────────────  │  403 insufficient_authorization         │
 │   challenges:[{type:"passkey", params:{challenge, rpId, allowCredentials…}}]
 │  (ASAuthorization)       │                                         │
 │  POST challenge          │                                         │
 │  (auth_session, passkey  │  processor.action() ────────────────────►│ exec 2 action(): WebAuthnCredentialProvider.isValid → SUCCESS
 │   assertion fields)      │                                         │ exec 3: conditional-OTP → user has TOTP → challenge(JSON)
 │ ◄──────────────────────  │  403 … challenges:[{type:"totp"}]       │
 │  POST (auth_session,     │  processor.action() ────────────────────►│ exec 3 action(): OTPCredentialProvider → SUCCESS
 │   totp)                  │  flow complete → attachUserSession,     │
 │                          │  required actions? → JSON or redirect   │
 │ ◄──────────────────────  │  200 { authorization_code }             │
 │  POST /token (code,      │                                         │
 │   code_verifier, DPoP)   │  standard Keycloak token endpoint        │
 │ ◄──────────────────────  │  access/refresh/id tokens (+auth_session)│
```

Important properties of this mapping:

- **Flow configuration stays in the admin console.** Which factors, in what order, required vs alternative, conditions on user role/ACR — all unchanged. Operators build a `native browser`-like flow from native-aware executions.
- **One execution = one challenge type.** ALTERNATIVE siblings become multiple entries in `challenges[]` so the app can offer a choice ("Use passkey" / "Use password"). The app answers with `challenge_type` (and `challenge_id` = execution id) so the endpoint routes `action()` to the right execution.
- **Credential validation is reused**, never reimplemented: WebAuthn via `WebAuthnCredentialProvider`/webauthn4j, TOTP via `OTPCredentialProvider`, recovery codes via `RecoveryAuthnCodesCredentialProvider`, password via `PasswordCredentialProvider`.
- **Brute-force protection, events, user sessions, SSO** all come for free because we go through the processor and `AuthenticationManager`.
- **Step-up** is just a new challenge request with `auth_session` + `acr_values`; Keycloak's existing LoA conditional logic decides which executions run.

## 3. Push MFA — two distinct scenarios

| Scenario | Who initiates | Who approves | Server piece |
|----------|---------------|--------------|--------------|
| **A. Push as second factor for a browser/other-client login** (the requirement in the brief) | Browser login hits ba-itsys `push-mfa` authenticator | Mobile app, already enrolled & authenticated | ba-itsys extension (as-is) + APNs sender |
| **B. Push as a challenge inside a native login** (e.g. desktop app or second phone authenticating; this phone approves) | Native challenge endpoint; `native-push` authenticator | Enrolled mobile app | `native-push` authenticator bridges to ba-itsys challenge store; app polls challenge status instead of browser SSE |
| **C. In-app push enrolment** | Mobile app after native login | n/a | `native-auth` endpoint `/push/enroll/start` creates the ba-itsys enrolment challenge and returns the enrolment JWT in JSON (no QR) |

Scenario A needs almost no new code. B and C are thin bridges that reuse ba-itsys' challenge storage, token formats and DPoP device API. The SDK's push module implements ba-itsys' device API exactly as documented (so it would also work against a stock ba-itsys install).

## 4. Key design decisions

| # | Decision | Alternatives considered | Rationale |
|---|----------|------------------------|-----------|
| D1 | **Adopt FiPA draft-04 envelope** | Custom REST API; CIBA; Device Grant; ROPC-style grant per factor | Standards-track, already prototyped on Keycloak, Auth0/Okta/Janssen converging on it, gives step-up + redirect-to-web fallback for free. ROPC is deprecated in OAuth 2.1; Device/CIBA are cross-device flows with worse UX. |
| D2 | **Run Keycloak's AuthenticationProcessor over a dedicated flow** rather than hand-rolling factor logic in the endpoint | Endpoint directly calls credential providers | Keeps admin-console configurability, conditions, brute-force, events, ACR. Matches the article's proven approach and the direction of discussion #36924. |
| D3 | **Separate native-aware authenticators** that *wrap* existing credential providers | Patch core authenticators to emit JSON (needs upstream change); subclass core authenticators | No fork of Keycloak; upstream may later add a response-type abstraction, at which point our authenticators collapse into thin adapters. |
| D4 | **Form-encoded requests, JSON responses** | JSON everywhere | Matches the draft (initial request MUST be form-encoded) and the article; trivial to curl. Binary WebAuthn fields are base64url strings either way. |
| D5 | **`auth_session` = JWE of {rootSessionId, tabId, clientId, dpopJkt?}** encrypted with a realm key | Plain auth-session id; server-side map | Opaque to client as the draft requires, stateless lookup, can carry the DPoP thumbprint for device binding (§9.6.1). |
| D6 | **Adopt ba-itsys for push MFA** | netzbegruenung plugin; build our own | See 01 §3. Dramatically less work and risk; Apache-2.0; active. |
| D7 | **DPoP from day one for push device API; optional (recommended) for the native login flow** | Bearer only; mTLS | ba-itsys already requires it; FiPA recommends it; Keycloak supports DPoP natively; Secure Enclave keys make it cheap on iOS. |
| D8 | **App Attest / attestation-based client auth in Phase 4**, not Phase 0 | Require from the start | It is orthogonal to the protocol; avoids blocking the spike. Spec'd as an extension point (`client_attestation` headers) so adding it later does not change the challenge contract. |
| D9 | **SDK = core state machine + optional default UI**, UI replaceable per challenge type | UI-only SDK (Auth0 Lock style); core-only | Satisfies "customise screens, protocol stays stable". |
| D10 | **Conformance suite is a first-class deliverable** | Rely on SDK tests | It is the only way to honour "developers not using the SDK can implement against the same authenticators". |
| D11 | **Versioned profile** (`protocol_version: "1"` in metadata and responses) | Unversioned | Draft will change; our challenge schema will grow (e.g. new factor types). |

## 5. Trust boundaries & where secrets live

| Secret | Location | Notes |
|--------|----------|-------|
| Realm signing/encryption keys | Keycloak | Sign enrolment/confirm tokens, encrypt `auth_session`. |
| Device key (ES256) | iOS Secure Enclave via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`; access control `biometryCurrentSet` optional | Used for DPoP proofs and push approval JWTs. Never leaves the device. |
| Passkey private keys | iCloud Keychain / platform authenticator | Managed by the OS; SDK only sees assertions. |
| Access/refresh tokens | Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) | Via `CredentialsManager`; DPoP-bound so theft is less useful. |
| `auth_session` | Memory during a flow; Keychain if persisted for step-up re-entry | Draft says keep it beyond code issuance; we persist it alongside credentials. |
| APNs device token | Sent to Keycloak at enrolment and on rotation | Treated as routing info, not a secret. |
| Push `credentialId` → user mapping | App Keychain | ba-itsys design: server-side payloads are pseudonymous. |

## 6. Non-goals (for this iteration)

- Android SDK (planned as Phase 5 port; protocol and conformance suite are platform-neutral).
- Native SSO between multiple first-party apps on one device (OpenID Native SSO is the right tool; FiPA §9.7 warns against duplicating login UX across apps).
- Replacing Keycloak's account console for credential management (we expose only what the app needs: passkey registration, push enrolment, push key rotation).
- SPA/web clients (FiPA says NOT RECOMMENDED; the existing redirect flow remains for web).
