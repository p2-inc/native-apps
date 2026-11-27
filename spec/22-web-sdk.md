# 22 — Web SDK and drop-in components

**Status:** phases 1–2 implemented (27 November 2026); phases 3–7 planned below.
**Audience:** implementers of the web packages and the server changes they need.

The browser becomes a fifth client of the challenge protocol (spec/03): the same `/native-auth/challenge` endpoint, the same challenge types and the same recorded transcripts as the iOS, Android, React Native and Flutter SDKs. A single-page app signs users in with its own screens, with no redirect to Keycloak, unless the flow reaches a step that has no native variant; then a popup carries it.

## 1. Decisions

| # | Decision | Why |
| --- | --- | --- |
| D1 | The web SDK lives in this repository under `web/` (npm workspaces), with the native SDKs, transcripts, CI and release line. | Every client here is a first-party app of the same protocol; one repository keeps the contract and its clients together. |
| D2 | Packages: `@p2-inc/keycloak-web` (framework-free core), `@p2-inc/keycloak-web-react` (hooks and unstyled components), later `@p2-inc/keycloak-elements` (web components with a styled default, also as a script-tag bundle). No separate vanilla-JS UI library. | One state machine (`LoginController`) behind every renderer; web components already work in plain HTML. |
| D3 | Licenses: SDKs and components Apache-2.0, new server modules ELv2, as for the native SDKs. | The split the native SDKs use (repository PR #22). |
| D4 | Tokens: access token, ID token and post-login `auth_session` in memory, as oidc-spa keeps them. The refresh token (and the post-login `auth_session`) is persisted in IndexedDB so a reload keeps the session; DPoP binds it to a non-extractable WebCrypto key that is stored next to it. No backend-for-frontend in this work (phase 7, later). | A reload must not sign the user out, and an embedded login sets no Keycloak cookie to restore from (oidc-spa's way). A copied refresh token is useless off the page without the key. |
| D5 | CORS on `/native-auth/*` for the client's Web Origins (Keycloak's own rule, `+` and `*` included). Errors whose client is unknown are readable by origins of any native-auth client of the realm. No credentials: the endpoint uses no cookies. Metadata is readable from any origin. | A browser can only read responses the server allows; the error case keeps `invalid_session` from turning into a network error. |
| D6 | Passkeys from the SPA's origin need no server code: the origin goes in the realm's Passwordless policy extra origins (as for Android's `android:apk-key-hash`), and the RP ID must be a registrable suffix of the page's host. | Keycloak's WebAuthn validation already accepts extra origins (`WebClientIT`). |
| D7 | `redirect_to_web` opens a popup on the client's `native-auth.web-fallback-redirect-uri`, which must be on the SPA's origin; a full-page redirect is the fallback when popups are blocked. | Keeps the app's state; the popup opens inside the click so popup blockers allow it. |
| D8 | Step-up for resource servers: `kc.fetch` reads RFC 9470 `insufficient_user_authentication`, runs a step-up through a handler (`<StepUpBoundary>` in React) and retries once. | The native protocol already does step-up; the browser needs the glue. |
| D9 | Sign-out revokes a DPoP-bound refresh token instead of calling the logout endpoint. | Keycloak (26.4–26.8) answers `invalid_grant: DPoP proof is missing` on `/logout` for a DPoP-bound refresh token even with a proof: `TokenManager.verifyRefreshToken` reads a session attribute only the token endpoint sets. Revocation with a proof ends the session. The native SDKs have the same gap (§5). |
| D10 | Server modules are installed on request (not in Phase Two's default image for now), independent of the hosted system. | Same as the native extensions today. |
| D11 | Registration and forgot password become native flows in every SDK (phase 3), with a popup to Keycloak's pages until they land. | They are the most common screens of a drop-in. |
| D12 | Account widgets use Keycloak's built-in account REST API, tested per supported Keycloak version; a versioned facade only if a release breaks it. | It exists and the account console uses it; it is undocumented, so the version matrix guards it. |
| D13 | Positioning: the FiPA draft (-04) calls browser use NOT RECOMMENDED. Redirect stays the default we recommend; embedded login is opt-in for first-party clients, with DPoP, per-session rate limits and a captcha step (phase 5) answering the draft's objections. | The draft has not caught up with first-party browser flows that Okta, Clerk, Ory, Descope and Hanko ship. |

## 2. What phase 1–2 delivered

Server (`native-auth-endpoint`): `WebCors` (preflight on every `/native-auth/*` path, origin check per client or realm), the metadata readable from any origin, `ChallengeFlowDriver.requestClient()`. `WebClientIT` covers preflight, a full browser-origin login, a refused origin, an error without a known client, and a passkey registered and used from the SPA's origin. The demo realm gains clients `demo-web` and `demo-web-stepup` (the step-up flow) for `http://localhost:5173`, and the demo resource server answers browsers (CORS).

Core (`@p2-inc/keycloak-web`): the challenge model (shared with the React Native module's TypeScript model), `NativeLoginFlow`, `Authentication` (`startLogin`, `stepUp`, `requiredAction`, `continueAfterTokenChallenge`), `Tokens`, `CredentialsManager` (memory plus IndexedDB refresh token, refreshes serialized across tabs with the Web Locks API, a `BroadcastChannel` sharing sign-in, refresh and sign-out between tabs), `DPoPSigner` (non-extractable ES256 key, nonces per origin), `BrowserPasskeyPlatform` (with conditional mediation for passkey autofill), `PasskeyRegistrationClient` (§6), `WebFallback` (popup or redirect), `kc.fetch` (DPoP proofs with `ath`, refresh on `invalid_token`, RFC 9470 step-up), and `LoginController`, the UI-agnostic state machine (push polling, passkey autofill, fallback).

React (`@p2-inc/keycloak-web-react`): `KeycloakProvider` (restores the session and finishes a full-page fallback on mount), `useKeycloak`, `useLogin`, `<SignIn>`, `<StepUp>`, `<RequiredAction>`, `<StepUpBoundary>`, and a default component per challenge type, each replaceable through `components`. Unstyled: semantic HTML with `data-kc-part` hooks and the right `autocomplete` values for password managers and one-time codes.

Tests: the core replays the transcripts with the same matching rules as `MockTransport.kt` / `MockTransport.swift`; React components run in jsdom against the same transcripts. Verified by hand in Chromium against the compose stack: password + TOTP login, reload restore, `max_age=0` step-up, `kc_action` cancel, RFC 9470 step-up to acr 2 against the demo resource server, passkey registration and sign-in with a virtual authenticator, the popup fallback for a non-native required action, and sign-out revoking the session.

## 3. Phases

1. **Spike** — done.
2. **Web SDK 0.x** — done (popup fallback, step-up, `kc_action`, DPoP, IndexedDB).
3. **Registration and forgot password,** native in every SDK. New challenge types `registration` (fields from the declarative user profile, `register_url` fallback) and `reset_credentials` (email code, then `update_password`); new authenticators in a `native-auth-registration` module bound through a client's `native-auth.registration-flow-alias` / `native-auth.reset-flow-alias`; SDK calls `authentication().startRegistration()` / `startPasswordReset()`. Gate: sign-up with email verification and a reset run end to end on web, iOS and Android.
4. **Account widgets and web components.** `kc.account()` over `/realms/{realm}/account` (profile with user-profile metadata, credentials, sessions and devices, linked accounts), keycloak-orgs' user endpoints and the active-organization API; React components `<Profile>`, `<Credentials>`, `<Sessions>`, `<OrganizationSwitcher>`; `@p2-inc/keycloak-elements` (`<kc-sign-in>`, `<kc-profile>`, `<kc-credentials>`, `<kc-sessions>`) with a styled default themed by CSS custom properties and `::part()`, inputs in the light DOM; a shadcn registry with styled copies. Gate: the dashboard or a customer uses them.
5. **Extensions** in every SDK: `magic_link` (wait-and-poll like push, approved by the magic-link continuation mechanism; optional link back to the app with a one-time token), `captcha` (Turnstile through keycloak-bot-protection, verified before the username step), `organization_select` (keycloak-orgs). Gate: bot-protection review of the public endpoint.
6. **SSO cookie session.** A client setting (`native-auth.web-sso-cookie`) that, when on, lets the SDK trade its post-login `auth_session` for a one-time code and set Keycloak's browser SSO cookie through a top-level navigation or the popup, so the user is also signed in to other apps, the account console and the browser fallback. Off, the IndexedDB refresh token alone keeps the session.
7. **BFF adapter, later.** Tokens server-side behind an httpOnly cookie, for customers that want no tokens in JavaScript.

## 4. Configuration for a web client

- A public OpenID Connect client with the standard flow, PKCE S256 and `native-auth.enabled=true`.
- **Web Origins**: the SPA's origin (or `+` for the redirect URIs' origins).
- **Redirect URIs** and the attribute `native-auth.web-fallback-redirect-uri`: an exact URI on the SPA's origin for the popup fallback (`/callback.html` in the demo).
- Passkeys: the SPA's origin in the realm's **Passwordless policy → Extra origins**; the policy's RP ID a registrable suffix of the SPA's host (`example.com` for `app.example.com` and `auth.example.com`).
- Optional: `native-auth.flow-alias` for a web-specific flow.

## 5. Found along the way

- **Native SDKs: sign-out leaves DPoP-bound sessions alive.** `Tokens.logout` in the Kotlin and Swift cores sends no proof, and Keycloak refuses a DPoP-bound refresh token on `/logout` even with one (D9). `CredentialsManager.logout()` logs the failure and clears local state, so the Keycloak session stays until it expires. Fix: revoke DPoP-bound refresh tokens with a proof, as the web SDK does.
- **The popup fallback asks for the password again.** The embedded login sets no browser cookie, so Keycloak's pages start a fresh login. Phase 6 removes the second sign-in.
