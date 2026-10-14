# 06 — Example iOS App (`KeycloakNativeDemo`)

Purpose: prove every protocol path end-to-end on a real device, serve as living documentation for SDK users, and act as the push-approval device for the browser demo. It is deliberately *not* a polished product; it exposes toggles and logs.

## 1. Structure

```
KeycloakNativeDemo/
├── App/                     DemoApp.swift (SwiftUI App), AppDelegate (APNs registration, notification delegate)
├── Config/                  Config.plist (issuer, clientId, rpId, pushDeviceClientId), Debug overrides via Settings bundle
├── Features/
│   ├── Login/               LoginRootView — hosts NativeLoginView (default UI) or CustomLoginFlowView (hand-rolled from Core)
│   ├── Home/                HomeView — user info from id token, token claims (acr!), buttons for scenarios
│   ├── StepUp/              ProtectedActionView — calls demo API; on 401 insufficient_user_authentication → kc.stepUp(acrValues:)
│   ├── Passkeys/            ManagePasskeysView — register new passkey, list (from account REST), delete
│   ├── Push/                PushEnrollmentView, PendingApprovalsView, ApprovalSheet (number match), PanicLockoutButton
│   └── Diagnostics/         FlowLogView — redacted request/response log, copy-to-clipboard, protocol version, DPoP on/off
├── NotificationService/     UNNotificationServiceExtension using KeycloakNativePush helper to enrich the alert
├── Shared/                  Theme, DemoAPIClient (tiny resource server stub expecting acr=2 for /transfer)
└── Tests/                   Smoke UI tests for login happy path (against docker-compose Keycloak)
```

Entitlements: Associated Domains (`webcredentials:idp.example.com`), Push Notifications, Keychain Sharing (app ⇄ notification extension app group), Background Modes (remote-notification).

## 2. Scenarios the app must demonstrate

| # | Scenario | Protocol paths exercised |
|---|----------|--------------------------|
| S1 | Username → passkey → done | `username`, `passkey` (allow-list), code exchange, DPoP |
| S2 | Username-less passkey (autofill / discoverable) | `passkey` with `discoverable: true`, `user_handle` |
| S3 | Username → password → TOTP | `password`, `totp`, retry with error descriptor |
| S4 | Username → password → email OTP with resend | `otp`, `action=resend`, cooldown |
| S5 | Choose factor: passkey vs password; TOTP vs push | multi-entry `challenges[]`, chooser UI |
| S6 | Step-up: open "Transfer" → RFC 9470 401 → `stepUp(acrValues: "2")` → passkey only | `auth_session` reuse, LoA conditions, new `acr` in token |
| S7 | Redirect-to-web fallback: user with Terms & Conditions required action | `redirect_to_web` + PAR `request_uri`, `ASWebAuthenticationSession`, code exchange |
| S8 | Refresh forces re-auth (admin shortens SSO idle) | token endpoint `insufficient_authorization` → `reauthenticationRequired` |
| S9 | Push enrolment in-app, then approve a **browser** login (scenario A) with number match | `/native-auth/push/enroll/start`, `/push-mfa/enroll/complete`, APNs, `/login/pending`, `/respond` |
| S10 | Push as native challenge from a second device/simulator (scenario B) | `push` challenge, `action=poll`, approve on phone |
| S11 | Register a second passkey after login; delete it | `/native-auth/passkey/register/*` |
| S12 | Rotate push key; update APNs token; panic lockout | `/device/rotate-key`, `/device/push-provider`, `/login/lockout` |
| S13 | Custom UI: toggle "Use custom TOTP screen" in Diagnostics | `challengePresenter(for:)` override |
| S14 | Failure handling: wrong password ×N → brute-force lock → `access_denied` | error mapping, `retry.remaining` |

Each scenario is a button on Home with a short description, and the FlowLogView records the full transcript so a developer can compare it to `03-protocol-spec.md`.

## 3. Local development setup

1. `cd keycloak-native-auth/demo && docker compose up` — Keycloak 26.x on `https://localhost:8443` with self-signed cert, Postgres, mailpit (email OTP inbox at `http://localhost:8025`), extensions and ba-itsys JAR mounted, `demo` realm imported.
2. Passkeys require a real domain with an `apple-app-site-association` file. Options for dev:
   - Use a tunnel (`cloudflared`/`ngrok`) with a fixed hostname and set `rp_id` + Associated Domain to it; or
   - Use `?mode=developer` Associated Domains with a local HTTPS host — documented in the app README.
3. APNs: sandbox environment, `.p8` key configured in `docker-compose.override.yml` env; simulator can't receive APNs — the app's "Pending approvals" pull-to-refresh covers that.
4. Demo resource server: `demo/resource-server` (tiny Node/Java service) validating tokens and returning `401 insufficient_user_authentication` with `acr_values="2"` for `/transfer`.
5. Test users: `alice` (password + TOTP seeded), `bob` (password only, passkey registration required action → S7-like native variant), `carol` (push enrolled via simulator script).

## 4. What the example app intentionally does *not* do

- No production-grade design system; the default SDK UI is what SDK users will see.
- No account self-service beyond passkeys/push (link to the Keycloak account console instead).
- No multi-realm / multi-issuer switching (a Settings-bundle override is enough for QA).
