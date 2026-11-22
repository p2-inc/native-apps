## 0.5.0-dev

- Application-initiated actions (spec/21): `Authentication.requiredAction(alias, maxAge:)` (a step-up with `kc_action`, e.g. `UPDATE_PASSWORD` for a "Change password" button), `LoginParameters.kcAction`, `KcActionStatus` on `AuthorizedStep` and `NativeLoginAuthorized`.
- `update_password`: `UpdatePasswordChallenge.logoutOtherSessions` and the answer's `logoutOtherSessions`; the default screen offers "Sign out of other devices" and, when the app asked for the change, Cancel (English and German).

## 0.4.0

- PIN (spec/20): the `pin` and `pin_setup` challenge types (`PinChallenge`, `PinSetupChallenge`, `Challenge.isLocked`), the answers `ChallengeAnswer.pin` and `ChallengeAnswer.pinSetup`, the error codes `credential_locked`, `pin_mismatch`, `invalid_format` and `weak_pin`, and the default `PinScreen` and `PinSetupScreen` with a numeric keypad, in English and German.

## 0.3.0

- Every challenge type and required action has a default screen; German strings (spec/18 phase B).
- Passkeys and passkey registration answered natively, saved passwords, `continueAfterTokenChallenge` (phase C).
- Push MFA: enrollment in-app and mid-flow, `PushApprovalsView` with number match, provider updates, key rotation, lockout (phase D).
- The flow log (`observeFlow`, `KeycloakNative.flowLog`).
- First slice (spec/18 phase A): configure, login and step-up flows, `username`, `password` and `totp` default widgets, the browser fallback, stored credentials with refresh and logout, over the iOS and Android SDKs.
