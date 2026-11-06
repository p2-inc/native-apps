# 07 — Security Considerations

Organised as threat → mitigation → where it is implemented → phase. Sources: FiPA §9, RFC 9700 (OAuth security BCP), RFC 8252, RFC 9449, ba-itsys `docs/security.md`, Apple passkey/App Attest guidance.

## 1. Client impersonation / "first-partyness"

| Threat | A malicious app (or script) calls the challenge endpoint pretending to be `demo-native`, harvesting credentials or brute-forcing. |
|---|---|
| Mitigations | (a) Challenge endpoint only enabled per client (`native-auth.enabled`), never on confidential clients' secrets being shipped; (b) PKCE + DPoP so a captured code/token is useless without the key; (c) rate limiting per `auth_session`, per client, per IP (Keycloak brute-force + endpoint-level token bucket); (d) **App Attest** (iOS) / Play Integrity (Android) → attestation-based client authentication headers (Phase 4); (e) server MAY answer `redirect_to_web` for risky requests (new device, impossible travel) — a policy hook `NativeRiskEvaluator` SPI is reserved. |
| Residual risk | Until Phase 4, a determined attacker can drive the endpoint from a script. This is **equal to today's risk** on the browser login page; the endpoint does not reveal more than the forms do. Phishing risk (FiPA §9.2) is mitigated by passkeys being the primary factor. |

## 2. Credential and OTP brute force

- All factor validation goes through Keycloak's `AuthenticationProcessor`, so realm brute-force detection (temporary/permanent lockout) applies to password, TOTP, recovery codes.
- `native-otp`: 6 digits, 5-minute TTL, max 5 attempts per code, resend cooldown 30 s, max 3 resends per session, code stored as salted hash in the auth note.
- Generic errors for `username` by default (no account enumeration). Operators can opt into revealing non-existence for UX in closed user bases.

## 3. Session hijacking (`auth_session`)

- `auth_session` is a JWE (`dir` + AES-GCM under the realm's `aes-generated` key: A128GCM with Keycloak's default 128-bit key, A256GCM when the key provider is configured with `secretSize=32`; same construction as Keycloak's own `KC_RESTART` cookie) → opaque and tamper-proof; contains issuance time; TTL enforced server-side via the underlying auth session expiry (login timeout).
- When the client uses DPoP, the `jkt` is embedded and every continuation must present a proof for the same key (FiPA §9.6.1). Recommended default in the SDK (`dpop: .secureEnclave`).
- Bound to `client_id`; mismatch → `invalid_session`.
- Not logged (only a SHA-256 prefix).
- Discarded on logout; persisted in Keychain `ThisDeviceOnly` otherwise.

## 4. Authorization code & token theft

- Code is single-use, short-lived (realm "access code lifespan"), PKCE S256 bound, and DPoP-bound when the challenge request carried a proof (same mechanism as PAR+DPoP in RFC 9449 §10.1).
- Tokens: DPoP-bound (`cnf.jkt`) when enabled on the client; refresh-token rotation on; Keychain storage with `AfterFirstUnlockThisDeviceOnly`; optional biometric gate.
- Secure Enclave keys are non-exportable; the private key never exists in process memory.

## 5. Passkeys / WebAuthn

- RP ID = IdP host; app lists it in Associated Domains; the SDK refuses a server-supplied `rp_id` that is not the issuer host (configurable for staging).
- Server verifies `origin`/`rpIdHash`, signature counter (where present), UV flag against policy, challenge freshness (stored in the auth session, single use) — all via webauthn4j as Keycloak already does.
- Registration restricted to authenticated users with a fresh token (`max_age` policy, e.g. ≤ 5 min; else require step-up first) to prevent an attacker with a stolen token from adding a passkey.
- Attestation conveyance `none` by default (Apple passkeys are not enterprise-attested anyway); operators may require `direct` + MDS for hardware keys.

## 6. Push MFA

| Threat | Mitigation |
|---|---|
| Push fatigue / blind approval | Number matching (ba-itsys `userVerification: number-match`) on by default; approval sheet shows client name, time, and login context; deny is as prominent as approve; repeated denies trigger an event + optional auto-lockout. |
| Replay of approval | Approval is a device-signed JWT containing the unguessable `cid`; `cid` single use; server also verifies DPoP proof freshness (±120 s) and `jti`. |
| Device key theft | Secure Enclave ES256, optional biometry-gated use for approvals (`SecAccessControl` `biometryCurrentSet`). |
| Enrolment hijack | Enrolment JWT is realm-signed with short TTL and nonce; in-app enrolment requires a fresh native login token; QR path keeps ba-itsys' `request_uri` indirection so the token never sits in a QR image. |
| Push provider learns identities | ba-itsys design: payload contains only `credId` + `cid`. Keep it; our APNs sender MUST NOT add username/client name to the payload (the notification service extension fetches it over DPoP instead). |
| Device client secret in app (ba-itsys `push-device-client`) | Treat as non-secret. Mitigate with DPoP binding (already required) and move to a secret-less path in Phase 4 (08 Q6). |
| Lost device | `/login/lockout` panic button from another enrolled device or the account console; admin can delete the push credential. |

## 7. Redirect-to-web fallback

- Uses `ASWebAuthenticationSession` (system browser, no embedded WebView), PAR `request_uri` tied to the original PKCE verifier, `iss` check on the callback (RFC 9207), custom-scheme or Universal Link callback per RFC 8252.
- The server only issues a `request_uri` if PKCE was present in the initial challenge request (FiPA §5.2.2.1.1).

## 8. Transport & platform

- TLS 1.2+; the SDK optionally supports certificate pinning via `URLSessionDelegate` hook (off by default; operators decide).
- All form bodies and JSON logged only through the redacting logger.
- No `UIPasteboard` interactions except user-initiated OTP paste.
- Jailbreak detection is out of scope (unreliable); attestation is the real signal.

## 9. Privacy

- `device_name`/`device_id` are optional and user-visible in Keycloak sessions; `device_id` is app-scoped, not IDFV/IDFA.
- Push `credentialId` is generated by the app; the server never links push tokens to identities in logs.
- Events carry hashed `auth_session` and no OTP/passkey material.

## 10. Operational controls checklist (for the admin guide)

- [ ] Native auth enabled only on intended public clients; `native` flow reviewed.
- [ ] PKCE required on those clients; DPoP "bound tokens" on.
- [ ] Brute-force detection enabled realm-wide.
- [ ] WebAuthn passwordless policy: UV required, resident key required, RP ID correct.
- [ ] ba-itsys: number-match on, enrolment via `request_uri`, APNs sender configured, rate-limit SPI defaults reviewed.
- [ ] Short code lifespan (≤ 60 s) and login timeout (≤ 10 min for native).
- [ ] Alerting on `LOGIN_ERROR` spikes per client and on `NATIVE_REDIRECT_TO_WEB` volume.
- [ ] Phase 4: attestation required for production clients.
