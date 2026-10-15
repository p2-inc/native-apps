# 08 — Roadmap, Risks & Open Questions

Estimates assume one Keycloak/Java engineer and one iOS engineer, part-time product/security review. "w" = calendar weeks.

## Phase 0 — Spike (2–3 w) · *de-risk the two hard Keycloak questions*

Deliverables
- `native-auth-endpoint` + `native-username`, `native-password`, `native-totp` authenticators, `auth_session` codec, `CodeIssuer`.
- Hand-written curl walkthrough (03 §11) succeeds end to end, including code → token exchange.
- Decision memo on Q1 (redirect_uri) and Q2 (surfacing multiple ALTERNATIVE challenges).
- Decision on client secret approach for push device client (Q6) — can be deferred to Phase 3 but should be investigated here.

Exit criteria: tokens obtained without a browser; events show in the admin console; integration test green in CI with testcontainers.

> **Status (14 Oct 2026): done** — see `09-phase0-decisions.md`.

## Phase 1 — Passkeys + SDK core + example app (4–5 w)

- `native-passkey` (login) + `native-passkey-register` (required action) + `/passkey/register/*` endpoints.
- SDK `KeycloakNativeCore`: state machine, PKCE, DPoP (Secure Enclave + software), passkey bridge, CredentialsManager, error model, redacting logger.
- Example app S1–S3, S11, S14; Diagnostics log.
- Protocol spec v1.0-rc frozen for the challenge types implemented so far; conformance suite covers them.

## Phase 2 — Remaining factors, step-up, fallback, UI (4 w)

- `native-otp` (email via Keycloak templates; `sms-webhook` sender), `native-recovery-code`, `native-select` (if needed after Q2), `native-redirect-to-web`.
- Step-up (RFC 9470) and refresh-triggered re-auth paths; `WebFallback` in SDK.
- `KeycloakNativeUI` default screens + presenter override API; localisation; accessibility pass.
- Example app S4–S8, S13.
- Spec v1.0 published; conformance suite complete for the native flow.

## Phase 3 — Push MFA (3–4 w)

- Integrate ba-itsys (scenario A works with stock extension + our APNs sender).
- `native-auth-push-apns`; `/push/enroll/start` in-app enrolment; `native-push` authenticator (scenario B).
- `KeycloakNativePush` + approval UI + notification service extension.
- Example app S9, S10, S12. Browser demo realm with push as second factor.
- Contribute upstream to ba-itsys where we touched internals (enrolment API, APNs sender) — reduces our fork burden.

## Phase 4 — Hardening & release (3–4 w)

- Attestation-based client auth (App Attest → attestation JWT service → headers), `client_attestation_required` policy; DPoP required by default for production clients.
- Rate limiting at the endpoint; risk evaluator SPI hook; metrics dashboards; load test.
- Security review / pen test against 07 checklist.
- Docs: admin guide, SDK DocC, EXAMPLES.md, migration guide from browser-based login.
- v1.0 of extensions (Maven Central) and SDK (SwiftPM tag).

## Phase 5 — Android (post-v1, 4–5 w)

- Kotlin port of Core (Credential Manager for passkeys, Keystore/StrongBox for DPoP & push keys, FCM), Compose default UI, same conformance fixtures. ba-itsys already ships an FCM sender.

**Total to v1.0 (iOS):** roughly 16–20 weeks of calendar time with the two-engineer assumption.

---

## Key risks

| # | Risk | Impact | Mitigation |
|---|------|--------|------------|
| R1 | Keycloak `AuthenticationProcessor`/`DefaultAuthenticationFlow` cannot easily expose several ALTERNATIVE executions as one challenge set | Chooser UX degrades to "one factor at a time" | Phase 0 prototype; fallback is `native-select` authenticator that enumerates alternatives itself (we control it), which the spec already allows |
| R2 | Keycloak minor upgrades break private SPI usage (`AuthenticationProcessor`, `OAuth2CodeParser`, webauthn4j versions) | Maintenance cost | CI matrix incl. nightly; isolate Keycloak-internal calls in two classes (`ChallengeFlowDriver`, `CodeIssuer`); pin webauthn4j to Keycloak's version |
| R3 | FiPA draft changes (status codes, parameter names) before RFC | Protocol churn | Envelope isolated; `protocol_version`; SDK tolerant parsing |
| R4 | Upstream Keycloak ships its own FiPA support later | Duplicate effort | Design mirrors the direction of discussion #36924; our authenticators become adapters; the SDK/protocol survive since the draft leaves challenge payloads to implementers. Consider proposing our profile upstream. |
| R5 | ba-itsys internals not accessible for in-app enrolment | Must fork or duplicate | Engage maintainers early (Phase 0/1); the project accepts PRs and has `CONTRIBUTING.md` |
| R6 | Passkey dev setup friction (Associated Domains, HTTPS domain) slows iOS work | Schedule | Provision a stable dev hostname + AASA in Phase 0 |
| R7 | App Store / APNs provisioning and notification extension complexity | Phase 3 slip | Start APNs key + entitlements provisioning in Phase 1 |
| R8 | Operators mis-configure the native flow (e.g. include a form-based authenticator) | Broken logins | Endpoint validates the flow at startup/first use and returns a clear 500 with the offending execution; admin guide + demo realm |

---

## Open questions

### Decide before Phase 0
- **Q1 — Authorization code without `redirect_uri`.** Keycloak's authorization-code grant historically validates `redirect_uri` against the value stored with the code. Need to confirm on 26.x whether a null stored value is accepted when the token request omits `redirect_uri`. Options: (a) store null and verify; (b) store a sentinel such as `urn:keycloak:native` and have the SDK send it; (c) require a fixed registered redirect URI. Preference: (a) if it works, else (b). Metadata will advertise the requirement.
> Preference: (a) if it works, else (b).
> **Answered (09 Q1):** (a) works on 26.8.1 — `AuthorizationCodeGrantType` only compares when the stored value is non-null. Default `native-auth.code-redirect-uri-mode=none`; `sentinel`/`client-fixed` available and tested.
- **Q2 — Multi-alternative challenge sets.** Do we (a) extend/wrap the flow engine to probe all eligible ALTERNATIVE executions in one pass, or (b) rely on `native-select` plus one-challenge-at-a-time? (a) gives the nicer protocol; (b) is guaranteed feasible. Phase 0 answers this.
> Answer using validation in Phase 0. Do (a) if possible, but fall back to (b) if necessary.
> **Answered (09 Q2):** (a), without wrapping the engine: `AuthenticationFlowContext.getAuthenticationSelections()` already lists the eligible alternatives; the native base authenticator describes them all in one `challenges[]`. `native-select` stays optional.
- **Q3 — Endpoint path & well-known.** `/realms/{r}/native-auth/challenge` (RealmResource) vs trying to live under `/protocol/openid-connect/ext/…`. The former is what the SPI gives us; publish in metadata and optionally well-known. Confirm nobody objects to the `native-auth` provider id.
> Agreed
> **Confirmed (09 Q3):** `/realms/{realm}/native-auth/{metadata,challenge}` via `RealmResourceProviderFactory` id `native-auth`.
- **Q4 — Keycloak version floor.** 26.x only, or also 25? Recommend 26.x (DPoP GA, passkeys policy changes). Affects CI matrix.
> 26.8.x floor
> **Pinned (09 Q4):** 26.8.1 (parent POM, docker-compose, Testcontainers).

### Decide during Phase 1–3
- **Q5 — ba-itsys integration depth.** Depend on the published JAR and call internal classes (fragile), or upstream a small "programmatic enrolment" API and an APNs sender. Recommend upstreaming; budget review time.
> We can build the "programmatic enrolment" API and an APNs sender in our project, and then suggest for ba-itsys upstream. Should not block our development.
> **Done (Phase 3, 14 D9/D10):** `PushEnrolment` (start/complete), `/native-auth/push/enroll/start`, `native-push-enroll`, `native-push` and the `apns` sender live in this repository; the published ba-itsys jars target Java 25 and use `@RunOnVirtualThread`, so the demo deploys a Java 21 rebuild (`push-mfa-extension-java21`). The upstream list is in 14 D10.
- **Q6 — Push device client credentials.** ba-itsys expects `client_credentials` with a secret on `push-device-client`. In a public mobile app that secret is extractable. Options: (a) accept (DPoP still binds every call to the device key, which is the actual security boundary); (b) obtain the device access token via **token exchange** from the user's native access token (RFC 8693, Keycloak standard token exchange) so no secret ships; (c) attestation-based client auth. Recommend (b) in Phase 3, (c) in Phase 4; keep `DeviceTokenProvider` abstract in the SDK.
> Accept recommendation
> **Done (Phase 3, 14 D9):** (b) is not possible — Keycloak 26.8's standard token exchange refuses public clients. Implemented instead: the SDK's DPoP key is the device key and the user's DPoP-bound native access token is the device token (03 §7.1, metadata `push.device_token = "native"`); no secret ships, no second client. `DeviceTokenProvider` stays abstract (a `client_credentials` provider is the extension point for stock ba-itsys installs).
- **Q7 — Which required actions get native variants.** Minimum: passkey register, push enrol. Candidates: update password, verify email, terms. Everything else → `redirect_to_web`. Product decision.
> Accept recommendation. update password, verify email, terms. Everything else → `redirect_to_web`
> **Done (14 D1):** `native-update-password`, `native-verify-email`, `native-terms` substitute for Keycloak's actions; everything else is `redirect_to_web`.
- **Q8 — Username-less by default?** Should the first challenge be `passkey` (discoverable) with `username` as an alternative, or `username` first? Affects flow template and chooser defaults. Recommend passkey-first when the realm policy requires resident keys.
> Accept recommendation
- **Q9 — SMS provider.** Ship only `sms-webhook` and let operators integrate, or add a Twilio adapter? Recommend webhook only in v1.
> Webhook.
> **Done (13 D4, 14 D5):** `sms-webhook` sender; `SmsOtpIT` drives it against a host-side sink.
- **Q10 — OTP delivery for email: reuse Keycloak's existing `EmailSenderProvider` + theme templates** (yes) — confirm theme packaging approach (our JAR ships a theme with `native-otp.ftl` + messages).
> Accept recommendation
> **Done (14 D5):** the `native-auth-otp-sender` JAR ships `theme-resources/templates/{html,text}/native-otp.ftl` and `nativeOtp*` messages (en, de); sent through `EmailTemplateProvider`, overridable by the realm's email theme.
- **Q11 — Step-up `auth_session` lifetime.** Tie to SSO session max, SSO idle, or a dedicated realm attribute? Recommend SSO idle (so it dies with the session).
> yes
> **Done (14 D6):** `exp` = SSO idle timeout from minting, capped by the session max; `stepUp` still checks `isSessionValid`.
- **Q12 — Number-match on the native (scenario B) side.** Who shows the number — the initiating native client (we return it in `push.params.user_verification`) — confirmed in spec; verify ba-itsys exposes the chosen number to the authenticator (it does for the browser template).
> Accept recommendation

### Later / nice-to-have
- Publish the Keycloak Native Auth Profile as an Internet-Draft profile of FiPA, or at least as a public spec repo with the conformance suite, so third-party IdPs/clients can interoperate.
- Android parity and a React Native / Flutter wrapper (the netzbegruenung Flutter package shows demand).
- Native SSO between multiple first-party apps via OpenID Native SSO rather than repeating the native flow per app (FiPA §9.7).
- Account-console UI for listing/removing native devices (push credentials, DPoP-bound sessions).
