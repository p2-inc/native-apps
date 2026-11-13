# 20 — PIN codes

**Date:** 12 November 2026
**Code:** new repository `p2-inc/keycloak-pin` (credential, browser authenticator, set-PIN required action, reset); `keycloak-native-auth/native-auth-pin/` (native authenticator and required action); the four SDKs (challenge types, answers, default screens).

A PIN is a short numeric secret used as a second factor (or as the factor of a step-up). please-open.it's [PIN Code Authenticator](https://github.com/ldesroch/keycloak-pin-code-authenticator) (Apache-2.0) showed the shape; we reviewed it and write our own because of gaps that matter for hosting and native login: no PIN-specific attempt limit (only realm brute-force protection, default 30 failures, against a 10⁴ space), server-wide configuration through `Config.Scope`, a custom Argon2 SPI next to Keycloak's own `argon2` hash provider, a custom admin reset endpoint and action token where Keycloak's built-ins suffice, no account-console integration, and a server-rendered visual keyboard that is inaccessible and not needed natively. Credit them in the README ("inspired by").

## D1 — Repository and packaging

`p2-inc/keycloak-pin`: Maven `io.phasetwo.keycloak:keycloak-pin`, package `io.phasetwo.keycloak.pin`, parent `io.phasetwo:oss-parent` like the other Phase Two extensions, Elastic License 2.0 (`COPYING`), Keycloak 26.4–26.8 (same matrix as native-auth, 16). No dependency on native-auth: the browser extension stands alone. `native-auth-pin` lives in native-apps (native-auth-core is not published) and depends on `keycloak-pin`; it ships in the providers zip but does nothing until an operator puts it in a flow, so PIN is optional by configuration, not by a third-party install.

## D2 — Credential

- Type and credential provider id: `phasetwo-pin`. Display name "PIN", category two-factor, removable. `CredentialTypeMetadata` declares create and update actions = the set-PIN required action, so the account console's *Signing in* page offers "Set up PIN" / "Update".
- One PIN per user; setting a new PIN replaces the old (update in place, keep the id).
- Hashing: Keycloak's built-in `PasswordHashProvider` with id `argon2` (hash + salt + parameters stored like `PasswordCredentialModel`). Re-hash on successful verification when the provider's parameters changed (`policyCheck`). No custom hash SPI.
- Credential data (non-secret): `length` (the PIN's length when set), `failures` (consecutive failed attempts), `locked` (boolean). Secret data: hash value, salt, additional parameters.

## D3 — Configuration (per realm, through built-in config surfaces)

- **Set-PIN required action** (`phasetwo-configure-pin`, display "Configure PIN"), Keycloak required-action config: `length` (4–12, default 4). Applies when a PIN is set; authentication uses the length stored on the credential, so changing the realm setting does not break existing PINs.
- **Authenticator** (`phasetwo-pin`, display "PIN"), execution config: `max-attempts` (default 5, 0 = unlimited). Weak PINs (all same digit, simple ascending/descending runs) are rejected at set time; toggle `reject-weak` on the required action config (default on).
- No server-wide `Config.Scope` settings, no visual keyboard.

## D4 — Attempts and lockout

Each wrong PIN increments `failures` on the credential and is also reported to realm brute-force protection as usual (`failureChallenge`, `INVALID_USER_CREDENTIALS` event). A correct PIN resets `failures`. When `failures` reaches `max-attempts`, the credential is `locked`: every later attempt fails without checking the hash (event error `user_temporarily_disabled`-style detail `pin_locked`) until the PIN is reset. Unlock = reset (D5), never time-based.

## D5 — Reset and enrollment

- Users set a PIN through the required action (assigned by an admin, `kc_action=phasetwo-configure-pin`, or the account console via D2's create action). Enrollment during login: `conditional-user-configured` (Keycloak's built-in condition) around the authenticator; the authenticator's `setRequiredActions` adds the set-PIN action when the execution is REQUIRED and the user has none (standard Keycloak behavior via `isUserSetupAllowed`).
- Admin reset: delete the credential on the user's *Credentials* tab, or send Keycloak's *execute actions* email with "Configure PIN". No custom REST endpoint.
- User-initiated reset: authenticator `phasetwo-pin-reset` ("Reset PIN") for the realm's **reset credentials** flow, modeled on Keycloak's `reset-otp`: removes the PIN and adds the set-PIN required action. No custom action token or email template.

## D6 — Their credentials (`pin-code`)

Optional, best effort: when a user has no `phasetwo-pin` but has please-open.it's `pin-code` credential with algorithm `argon2`, `phasetwo-pin` verifies against it (their layout mirrors Keycloak's: base64 hash and salt, Argon2 parameters `type`, `version`, `hashLength`, `memory`, `parallelism`, plus iterations) and on success migrates it: create `phasetwo-pin` with the same PIN, remove `pin-code`. Documented as a migration aid; the README recommends switching to this extension rather than running both. Drop D6 if their format turns out not to be readable with Keycloak's provider without copying their code.

## D7 — Native wire (03 §4.17, §4.18)

`pin` — the PIN factor (`native-pin`, display "Native: PIN"):
- params: `{ "length": 4 }` (the stored credential's length; clients show that many slots and a numeric keypad).
- response: `pin=<digits>`.
- errors: empty `pin` → `missing_credential` (not counted); wrong PIN → descriptor `error.code = invalid_credential` with `retry.remaining` = `max-attempts − failures` (when `max-attempts` > 0). Locked → descriptor `error.code = credential_locked`, `retry.remaining = 0`, also on the first descriptor of a login when the PIN is already locked; the client shows that the PIN is locked and must be reset (on the web or by an administrator) and offers cancel.
- Eligible like `native-totp`: requires a user, offered only when the user has a `phasetwo-pin` credential.

`pin_setup` — set a PIN (required action `native-configure-pin`, substitutes `phasetwo-configure-pin` per 03 §4.11):
- params: `{ "length": 4 }` (the realm's required-action config).
- response: `pin=<digits>&pin_confirm=<digits>`.
- errors on the descriptor: `missing_credential` (empty `pin`), `pin_mismatch`, `invalid_format` (wrong length or non-digits), `weak_pin`.

Metadata: `pin` and `pin_setup` appear in `challenge_types_supported` only when `native-auth-pin` and `keycloak-pin` are installed. `native-auth-core` `ChallengeType` gains `PIN("pin")` and `PIN_SETUP("pin_setup")`.

SDKs: new challenge types, typed params (`length`), answers `pin(String)` and `pinSetup(pin, confirm)`; `pin` and `pin_confirm` are added to every SDK's redactor `sensitiveKeys`; default screens: PIN entry (length slots, numeric keypad, secure entry, attempts-left and locked states) and set-PIN (enter + confirm). Strings in the SDKs' existing locales.
