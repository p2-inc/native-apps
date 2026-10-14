# Keycloak Native Mobile Authentication — Investigation & Build Plan

**Date:** 14 October 2026
**Status:** Phase 0 spike complete (see `09-phase0-decisions.md`); username + password + TOTP work end to end over HTTP against Keycloak 26.8.1
**Scope:** Browserless native authentication for Keycloak (passkeys, TOTP, OTP codes, push MFA), delivered as (1) a set of Keycloak extensions, (2) an iOS SDK, and (3) an example iOS app.

## Documents in this folder

| # | File | What it covers |
|---|------|----------------|
| 01 | `01-reference-review.md` | Analysis of every reference: FiPA draft, Besozzi article, ba-itsys push MFA, netzbegruenung app-authenticator, Auth0.swift / Auth0.Android, Keycloak SPIs. What to borrow, what to avoid. |
| 02 | `02-architecture.md` | Component architecture, how the native flow maps onto Keycloak authentication flows, and the key design decisions (with rationale). |
| 03 | `03-protocol-spec.md` | **The stable wire protocol.** Endpoints, challenge types, request/response formats, session handling, errors, push-MFA device API. This is the contract third-party (non-SDK) developers code against. |
| 04 | `04-keycloak-extensions-plan.md` | Maven module layout, authenticators, required actions, REST resources, realm configuration, test strategy. |
| 05 | `05-ios-sdk-plan.md` | Swift package design, public API, UI customisation model, push module, credential storage, DPoP, error model. |
| 06 | `06-example-ios-app.md` | Demo app structure, screens, scenarios to demonstrate, local dev setup. |
| 07 | `07-security-considerations.md` | Threat model and mitigations: first-partyness/attestation, token & session binding, replay, push fatigue, passkey RP ID, key storage. |
| 08 | `08-roadmap-and-open-questions.md` | Phased implementation plan, effort estimates, risks, and unresolved questions that need a decision before/while building. |
| 09 | `09-phase0-decisions.md` | **Phase 0 spike results** (14 Oct 2026): answers to Q1–Q4 with evidence, decisions taken while building `keycloak-native-auth/`, spec edits, extension points. |
| 10 | `10-status-and-task-list.md` | **Current state and task list**: what exists and is verified, protocol coverage, known limitations, open tasks per phase. Start here when picking up the project. |

## Executive summary

**Protocol foundation.** Adopt the IETF draft *OAuth 2.0 for First-Party Applications* (FiPA, `draft-ietf-oauth-first-party-apps-04`, July 2026) as the outer envelope: a POST-only *Authorization Challenge Endpoint* that returns either an `authorization_code` or an `insufficient_authorization` error carrying an `auth_session` plus structured challenge descriptors. The draft deliberately leaves the challenge payloads to each deployment, so we define a **Keycloak Native Auth Profile** that specifies them. Tokens are then obtained from Keycloak's normal token endpoint, so everything downstream (refresh, introspection, logout, step-up via RFC 9470) stays standard.

**Keycloak is not there yet.** As of mid-2026 Keycloak has no built-in authorization challenge endpoint and its authenticators are tied to FreeMarker form responses. The reference implementation described in the Besozzi article is closed-source (TwoGenIdentity). We therefore build: a `RealmResourceProvider` endpoint that drives a dedicated **native authentication flow** through Keycloak's standard `AuthenticationProcessor`, plus a family of "native-aware" authenticators that emit JSON challenges instead of HTML forms while reusing Keycloak's existing credential providers (WebAuthn, OTP) for validation.

**Push MFA: adopt, don't rebuild.** The `ba-itsys/keycloak-push-mfa-extension` (Apache-2.0, Maven Central, v1.11) already implements enrolment, DPoP-bound device API, SSE browser wait, number-matching/PIN verification, FCM delivery and a pluggable `PushNotificationSender` SPI. We integrate it as the push-MFA server side, add an APNs sender, and add an *in-app enrolment* bridge so a user already authenticated in the mobile app can enrol without scanning a QR code. The older netzbegruenung plugin is a useful second reference (its Flutter client proves the model) but is less complete.

**SDK shape.** Mirror Auth0.swift's layering — a protocol-based API client, a credentials manager backed by Keychain, async/await + Combine, typed errors with stable `code` values — but with a *challenge-driven state machine* at the core: `start() -> .challenges([...]) -> respond(...) -> .authorized(credentials)`. Default SwiftUI screens are provided but every challenge type has a replaceable presenter, so the protocol stays fixed while the UI is fully customisable.

**Recommended build order.** (0) 2–3 week spike proving endpoint + auth_session + code issuance with username/password + TOTP over curl → (1) passkeys + iOS SDK core + example app → (2) email/SMS OTP, step-up, redirect-to-web fallback, UI customisation → (3) push MFA integration (ba-itsys + APNs + in-app enrolment) → (4) hardening: DPoP binding, App Attest, rate limiting, conformance test-suite, Android parity.

## How to use these files

- Treat `03-protocol-spec.md` as the source of truth; both the Keycloak extensions and the SDK are implementations of it. Change the spec first, then the implementations.
- `08-roadmap-and-open-questions.md` lists decisions that block or shape implementation — resolve the "Decide before Phase 0" items first.
- All source URLs reviewed are listed at the end of `01-reference-review.md`.
