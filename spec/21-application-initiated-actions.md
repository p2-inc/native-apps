# 21 — Application-initiated actions (`kc_action`)

**Date:** 20 November 2026
**Code:** `keycloak-native-auth/native-auth-endpoint` (`ChallengeFlowDriver`, `RequiredActionDriver`, `CodeIssuer`), `native-auth-required-actions` (`NativeUpdatePasswordRequiredAction`), `native-auth-core` (`Protocol`, `AuthorizationCodeResponse`); the four SDKs in a follow-up.

A signed-in app needs to start a required action on request: "Change password" in its settings, "Change PIN", "Add a passkey". In the browser this is Keycloak's application-initiated action (AIA): the authorization request carries `kc_action=<alias>`, Keycloak re-authenticates the user when the action's maximum authentication age has passed, runs the action even though nothing is pending on the user, lets the user cancel it, and reports `kc_action_status` on the redirect. Until now the native profile only ran required actions that Keycloak had already scheduled (03 §4.11). An integrator asked for a native password change that makes the user prove who they are first; they were using `kc_action=UPDATE_PASSWORD` in a web view.

## D1 — Reuse Keycloak's `kc_action` machinery

The request parameter `kc_action` (03 §2.1) is copied to the authentication session's `kc_action` client note, the note the authorization endpoint sets; like `AuthorizationEndpoint.performActionOnParameters`, an `alias:parameter` value is split into `kc_action` and `kc_action_parameter` (`delete_credential:<credential id>`, `idp_link:<identity provider alias>`, `webauthn-register:skip_if_exists`). Everything else is Keycloak's own code, which the native endpoint already calls (13 D1):

- `OIDCLoginProtocol.requireReauthentication` (called by the step-up) includes `isReAuthRequiredForKcAction`: a full re-authentication when the user session's `AUTH_TIME` is older than the action's maximum authentication age. For `UPDATE_PASSWORD` that is the Update Password required action's *Maximum Age of Authentication* or the password policy's `maxAuthAge` (default 300 s).
- `AuthenticationManager.nextRequiredAction` puts the requested action first even when it is not pending on the user, marks it enforced when it is, and reports `error` for an alias that is not configured.
- `AcrStore.getRequestedLevelOfAuthentication` raises the requested level when the action's credential type is mapped to a level in the flow.

The parameter is honored on a fresh login and on a step-up. The useful case is the step-up: the app sends its post-login `auth_session` (03 §5) with `kc_action`.

**Why not a separate endpoint.** A dedicated "change password" API would need its own re-authentication rules, events and lockout handling; the challenge endpoint already has all of them and Keycloak's AIA rules come with it unchanged. One parameter covers every native required action.

## D2 — Re-authentication follows the realm; the app can force it

`max_age` and `prompt=login` keep their meaning (03 §5): `max_age=0` always asks for the factors again. Without them the action's maximum authentication age decides, as in the browser. So an operator who wants a password change to always ask for the current credentials sets *Maximum Age of Authentication* on Update Password (or `maxAuthAge` in the password policy) to 0; an app that wants it regardless sends `max_age=0`.

**Step-up without levels.** A step-up on a flow without LoA conditions re-runs every factor (13 D1), which would make the realm's maximum age meaningless for most flows. A browser in the same situation is signed in by its identity cookie (`CookieAuthenticator`'s cookie-only branch). So when `kc_action` is present, `requireReauthentication` is false and the requested level is not above the level already authenticated in the user session, the step-up skips the flow and goes straight to the required actions (`SSO_AUTH`, `AUTH_TIME` untouched, as in 13 D1's "nothing had to be asked" case). Without `kc_action` the step-up behaves as before.

## D3 — Running the action

`RequiredActionDriver` applies `AuthenticationManager.executeAction`'s checks to the requested action: the native provider must return `InitiatedActionSupport.SUPPORTED` and be enabled in the realm, else the status is `error` and the login continues without it (the code is still issued). The served action may be the native one named directly or the native variant substituted for the requested Keycloak alias (03 §4.11); the status is recorded under the name the app sent, because Keycloak only records it when the provider id equals the `kc_action` note. (Before this change, success and skip statuses were recorded under the native id, so a substituted action never reported one.)

Native actions that allow it: `native-update-password` (for `UPDATE_PASSWORD`), `native-verify-email` (for `VERIFY_EMAIL`), `native-configure-pin` (for `phasetwo-configure-pin`, "change PIN") and `native-passkey-register` (requested under its own id; Keycloak's `webauthn-register*` aliases are not substituted, 03 §4.11). `native-terms` and `native-push-enroll` stay unsupported (`error`).

**Actions without a native variant** (`UPDATE_PROFILE`, `UPDATE_EMAIL`, `CONFIGURE_TOTP`, `CONFIGURE_RECOVERY_AUTHN_CODES`, `webauthn-register*`, `delete_credential`, `delete_account`, `idp_link`, …) end in `redirect_to_web` (03 §3.4) like a pending non-native action, and the stored PAR request carries `kc_action` (with its parameter). The browser signs the user in, Keycloak's own page runs the action, and the redirect to the app carries `kc_action_status` next to `code` and `state`. So every action Keycloak allows the application to start works: natively where a native variant exists, in the system browser otherwise.

## D4 — Cancel and status

An action the app asked for is `skippable` (03 §4.11) unless it is also pending on the user (Keycloak's `KC_ACTION_ENFORCED`): the user may decline with `action=skip`, like the browser's cancel button. The native action's own `processSkip` is not consulted for this; the skip ends the action with status `cancelled`. The success body (03 §3.1) carries `kc_action_status`: `success`, `cancelled` or `error`; it is absent when the request had no `kc_action`.

## D5 — Signing out other sessions

`update_password` gains a `logout_other_sessions` param (`true`, the suggested default, like the browser page's checked "Sign out from other devices" box) and an optional answer field of the same name. With `logout_other_sessions=true` every other user session and offline session of the user is ended through back-channel logout, and a `LOGOUT` event is recorded for each. Keycloak's `AuthenticatorUtil.logoutOtherSessions` cannot be used: it keeps only the session whose id equals the root authentication session's, which for a step-up is not the user session the app is signed in with. The native implementation keeps both. The field is optional, so older SDKs that never send it keep today's behavior (nothing is signed out).

## D6 — SDKs (follow-up PR)

- `LoginParameters.kcAction` on all four SDKs, sent as `kc_action`.
- `kc.authentication().requiredAction(_ alias:maxAge:)` (Swift; the Kotlin, Dart and TypeScript equivalents follow each SDK's naming): a step-up with the stored post-login `auth_session`, `kc_action` set and `max_age` only when the caller passes it. It returns the flow; driving it is the same as a login.
- `.authorized(Credentials)` gains the action status (`KcActionStatus`: `success`, `cancelled`, `error`, or absent).
- The default `update_password` screen gets "Sign out of other devices" (on by default, sends `logout_other_sessions`) and, when the descriptor is skippable, a Cancel button that sends `action=skip`.
- Transcripts from `KcActionIT` join the replay sets.

## Consequences

- An app can change the password, the PIN or add a passkey without a browser, with Keycloak's own re-authentication rules.
- Operators control how fresh the authentication must be per action in the admin console; apps can only make it stricter (`max_age`).
- Events: `UPDATE_CREDENTIAL` (password), `CUSTOM_REQUIRED_ACTION`, `LOGOUT` per ended session, and the step-up's `LOGIN` with `step_up=true`.
