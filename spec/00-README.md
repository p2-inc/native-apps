# Keycloak Native Mobile Authentication — Investigation & Build Plan

This folder is the design record: the investigation, the protocol, the plans for each component and the decisions taken while building them, in the order they were written. The plans and the dated decision memos are kept as written; when a later memo changes a decision, it says which one it supersedes. For where the project stands now, read the [roadmap](../ROADMAP.md) and `10-status-and-task-list.md`.

**Scope:** browserless native authentication for Keycloak (passwords, passkeys, TOTP, one-time codes, recovery codes, push MFA), delivered as Keycloak extensions, an iOS SDK and an Android SDK, with a demo app for each.

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
| 08 | `08-roadmap-and-open-questions.md` | The original phased plan, risks, and the open questions with the answers recorded later. The current plan is the top-level [`ROADMAP.md`](../ROADMAP.md). |
| 09 | `09-phase0-decisions.md` | **Phase 0 spike results** (14 Oct 2026): answers to Q1–Q4 with evidence, decisions taken while building `keycloak-native-auth/`, spec edits, extension points. |
| 10 | `10-status-and-task-list.md` | **Current state and task list**: what exists and is verified, protocol coverage, known limitations, open tasks per phase. Start here when picking up the project. |
| 11 | `11-phase1-decisions.md` | **Phase 1a (server passkeys) decisions** (14 Oct 2026): native required actions in-band, `native-passkey` eligibility/discoverable login, flow-order challenge sets, post-login `auth_session`, registration endpoints and freshness rule, the test software authenticator. |
| 12 | `12-phase1b-decisions.md` | **Phase 1b (iOS SDK core + example app) decisions** (14 Oct 2026): transcript fixture format, DPoP token binding found on the server, RP ID rule and tunnel strategy, public API deviations from 05, what was verified on macOS only. |
| 13 | `13-phase2-decisions.md` | **Phase 1c (simulator pass) and Phase 2 decisions** (14 Oct 2026): step-up re-entering the flow like the cookie authenticator, `redirect_to_web` as a server-stored PAR, DPoP binding of session/code/post-login session, `native-otp` with the sender SPI and the single-option send rule, SDK/UI product shape, what ran on the simulator. |
| 14 | `14-phase2b-3-decisions.md` | **Phase 2b (close-out) and Phase 3 (push MFA) decisions** (15 Oct 2026): native required actions substituting for Keycloak's update-password / verify-email / terms, recovery codes, the username phantom challenge and `retry.remaining`, enrol-on-first-login, SMS webhook IT and themed OTP mail, UI localisation and tests, the push-MFA integration. |
| 15 | `15-v1-additions-decisions.md` | **Additions to v1.0-rc from integrator feedback** (23 Oct 2026): optional required actions (`skippable`, `action=skip`, passkey "Not now"), custom answers, `x_*` extension parameters and their persistence, `redirect_to_web` for non-native executions, the provider-id length warning. |
| 16 | `16-keycloak-version-support.md` | **Keycloak version support** (23 Oct 2026): one build against 26.8.1 runs on stock 26.4, 26.6 and 26.8; the API differences handled at runtime (`KeycloakCompat`, `ServicesCompat`, `WebAuthnCompat`), the CI matrix; supersedes the 26.8 floor of 08 Q4 / 09 Q4. |
| 17 | `17-android-sdk-plan.md` | **Android SDK plan** (23 Oct 2026): readiness, modules (a plain-JVM `core` replaying the shared transcripts, then `android`, `push`, `ui`, `demo`), platform mapping, API sketch, testing, order of work, open questions. |
| 18 | `18-flutter-plugin-plan.md` | **Flutter plugin plan and status** (9 Nov 2026): a plugin that wraps the native SDKs over Pigeon channels (handles, typed answers, native ceremonies, params as JSON, no refresh token in Dart), the challenge-type mapping, activity and window anchors, transcript replay through a fake host API and a live suite, distribution (pub.dev, Maven Central, SwiftPM), phases A–E with A–D done, the decisions taken and the questions left. |
| 19 | `19-react-native-plan.md` | **React Native module plan** (9 November 2026): a TurboModule wrapping the iOS and Android SDK cores, the typed challenge model and React screens, the bridge and its JSON shapes, platform anchors, SPM through the pod and the Android composite build, transcript-driven Jest tests, order of work. |

## Executive summary (October 2026, before the build)

**Protocol foundation.** Adopt the IETF draft *OAuth 2.0 for First-Party Applications* (FiPA, `draft-ietf-oauth-first-party-apps-04`, July 2026) as the outer envelope: a POST-only *Authorization Challenge Endpoint* that returns either an `authorization_code` or an `insufficient_authorization` error carrying an `auth_session` plus structured challenge descriptors. The draft deliberately leaves the challenge payloads to each deployment, so we define a **Keycloak Native Auth Profile** that specifies them. Tokens are then obtained from Keycloak's normal token endpoint, so everything downstream (refresh, introspection, logout, step-up via RFC 9470) stays standard.

**Keycloak is not there yet.** As of mid-2026 Keycloak has no built-in authorization challenge endpoint and its authenticators are tied to FreeMarker form responses. The reference implementation described in the Besozzi article is closed-source (TwoGenIdentity). We therefore build: a `RealmResourceProvider` endpoint that drives a dedicated **native authentication flow** through Keycloak's standard `AuthenticationProcessor`, plus a family of "native-aware" authenticators that emit JSON challenges instead of HTML forms while reusing Keycloak's existing credential providers (WebAuthn, OTP) for validation.

**Push MFA: adopt, don't rebuild.** The `ba-itsys/keycloak-push-mfa-extension` (Apache-2.0, Maven Central, v1.11) already implements enrolment, DPoP-bound device API, SSE browser wait, number-matching/PIN verification, FCM delivery and a pluggable `PushNotificationSender` SPI. We integrate it as the push-MFA server side, add an APNs sender, and add an *in-app enrolment* bridge so a user already authenticated in the mobile app can enrol without scanning a QR code. The older netzbegruenung plugin is a useful second reference (its Flutter client proves the model) but is less complete.

**SDK shape.** Mirror Auth0.swift's layering — a protocol-based API client, a credentials manager backed by Keychain, async/await + Combine, typed errors with stable `code` values — but with a *challenge-driven state machine* at the core: `start() -> .challenges([...]) -> respond(...) -> .authorized(credentials)`. Default SwiftUI screens are provided but every challenge type has a replaceable presenter, so the protocol stays fixed while the UI is fully customisable.

**Recommended build order.** (0) 2–3 week spike proving endpoint + auth_session + code issuance with username/password + TOTP over curl → (1) passkeys + iOS SDK core + example app → (2) email/SMS OTP, step-up, redirect-to-web fallback, UI customisation → (3) push MFA integration (ba-itsys + APNs + in-app enrolment) → (4) hardening: DPoP binding, App Attest, rate limiting, conformance test-suite, Android parity.

## How to use these files

- Treat `03-protocol-spec.md` as the source of truth; both the Keycloak extensions and the SDK are implementations of it. Change the spec first, then the implementations.
- All source URLs reviewed are listed at the end of `01-reference-review.md`.
