# 14 — Phase 2b (close-out of Phase 2) and Phase 3 (push MFA) decisions

**Date:** 15 October 2026 (in progress)
**Keycloak:** 26.8.1 (unchanged, 09 Q4)
**Code:** `keycloak-native-auth/` (required actions, authenticators, endpoint, demo), `ios/KeycloakNative/`,
`ios/KeycloakNativeDemo/`
**Evidence:** test names refer to `keycloak-native-auth/demo/src/test/java/.../*IT.java` (run with
`mvn verify`) and `ios/KeycloakNative/Tests/KeycloakNativeCoreTests/*.swift` (`swift test`).

This memo records what was decided while implementing the "Phase 2b — Close-out of Phase 2" and
"Phase 3 — Push MFA" blocks of `10-status-and-task-list.md`. Decisions of 09, 11, 12 and 13 are not
reopened. Each section names the slice of 10 it closes and how it was verified.

## Classes allowed to use Keycloak-internal APIs (08 R2)

Unchanged from 13: `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`,
`PasskeyRegistrationDriver`, `DPoPProofChecker`, `RedirectToWebBuilder`. `RequiredActionDriver`
gained `substituteFor` (reads `RealmModel.getRequiredActionProviderByAlias`, public SPI) and the
alias bookkeeping of D1; nothing new is internal. The required actions themselves use only public
SPI (`RequiredActionProvider`, `RequiredActionConfigModel`, `SubjectCredentialManager`,
`ThemeManager`, `TermsAndConditions.USER_ATTRIBUTE` from `keycloak-services`, which is a public
constant of a public class, not an internal API).

---

## D1 — Native required actions substitute for Keycloak's own actions instead of replacing them

**Problem.** 08 Q7 asked for native variants of update-password, verify-email and terms. Keycloak
addresses required actions by alias (the user's `requiredActions` list holds `UPDATE_PASSWORD`,
`VERIFY_EMAIL`, `TERMS_AND_CONDITIONS`), and those aliases are set by Keycloak itself (temporary
passwords, "verify email" realm switch, admin console buttons). Asking operators to assign
`native-update-password` instead would break every path that sets the Keycloak alias, and a browser
login of the same user must keep rendering Keycloak's own pages.

**Decision.** `NativeRequiredActionFactory.substitutesFor()` names the Keycloak alias a native action
can serve (`native-update-password` → `UPDATE_PASSWORD`, `native-verify-email` → `VERIFY_EMAIL`,
`native-terms` → `TERMS_AND_CONDITIONS`). When `CodeIssuer.complete` reports a pending alias with no
native factory of that id, `RequiredActionDriver.substituteFor` picks the installed native action
that (a) substitutes for the alias, (b) is **registered and enabled in the realm under its own id**
(the operator's off switch: disabling `native-update-password` makes carol fall back to
`redirect_to_web`, `disablingTheNativeVariantFallsBackToRedirectToWeb`) and (c) `canServe`s the
user (`native-verify-email` needs an e-mail address and a working `email` sender). The driver stores
the served alias in the auth note `native-auth.required-action.alias`; on success it removes **both**
the served alias and the native id from the user and the authentication session, so Keycloak's own
action disappears exactly as if its page had been completed. The native actions also work when
assigned directly under their own alias (same code path, alias = provider id). Outside a native
session every native action ignores itself (11 D1), so a browser login sees Keycloak's page.

**Spec.** 03 §4.11 (common rules), §4.12 `update_password`, §4.13 `verify_email`, §4.14 `terms`;
§1.1 lists the three types; §3.4 names which actions still redirect.

**Details that were not obvious.**
- `update_password` validates through `SubjectCredentialManager.updateCredential` (26.8.1 has no
  `updateCredentialAndGet`; that is nightly), so the realm's password policy, history and expiry
  rules apply unchanged. A policy violation surfaces as `ModelException(messageKey, parameters)`;
  the action renders it through the **login theme's messages** in the request's locale
  (`KeycloakContext.resolveLocale`, `ThemeManager.getTheme(LOGIN).getEnhancedMessages`) so the
  client gets *Invalid password: minimum length 8.* rather than `invalidPasswordMinLengthMessage`
  (`carolUpdatesHerPasswordInBand`, which sets `length(8)` on the realm for the test). The policy
  itself is exposed as `params.policy` (`{id: config}` minus hashing/lifetime entries) so clients
  can show hints or pre-validate. Keycloak's "sign out other sessions" checkbox has no equivalent
  (it would need `AuthenticatorUtil.logoutOtherSessions`, an internal API) — noted in 03 §4.12.
- `verify_email` is a **code**, not Keycloak's link: a link would send the user to a browser, which
  is what the native flow avoids. Delivery and bookkeeping reuse the `native-otp` machinery, now
  factored into `OtpCodes` (shared by `native-otp` and `native-verify-email`; the OTP module becomes
  a dependency of the required-actions module). The code is sent as soon as the challenge is issued
  because a required action is always the single entry of the set (13 D4's "only when single"
  rule holds trivially). The `code` form field is masked in transcripts only on the challenge
  endpoint (`TranscriptRecorder.MASKED_CHALLENGE_FORM_FIELDS`); on the token endpoint `code` is the
  authorization code and stays verbatim so the SDK replay still checks the exchanged code.
- `terms` reads its text / URL / version from the required action's configuration
  (`RequiredActionContext.getConfig()`, Keycloak 26's `RequiredActionConfigModel`, editable in the
  admin console) with realm attributes `native-auth.terms-*` as the fallback, because a realm
  export does **not** carry required-action config (`RealmRepresentation` has no field for it) and
  the demo realm needs importable values. Declining calls `failure("declined")`; the endpoint now
  carries a required action's failure message into `access_denied`'s `error_description`
  (`required_action:TERMS_AND_CONDITIONS declined`).
- Keycloak skips **disabled** required actions when computing the next action
  (`AuthenticationManager.getApplicableRequiredAction`), so `TERMS_AND_CONDITIONS` is enabled in
  the demo realm (Keycloak's default is disabled); it only affects users who carry the action.

**Demo realm.** New users `frank` (`UPDATE_PROFILE`, the `redirect_to_web` demo since carol is
served natively now), `grace` (`VERIFY_EMAIL`, `emailVerified=false`), `hank`
(`TERMS_AND_CONDITIONS`); the native actions are registered and enabled; realm attributes carry
the terms. `RedirectToWebIT` drives frank's update-profile page instead of carol's password page.

**SDK / UI / app.** `ChallengeType.updatePassword|verifyEmail|terms` (+ `isRequiredAction`),
`UpdatePasswordParams` (`policy`, `hints`), `VerifyEmailParams`, `TermsParams`, answers
`.updatePassword(_:confirm:)`, `.verifyEmail(code:)`, `.verifyEmailResend`, `.terms(accepted:)`;
`Redactor` masks `password_confirm` (and already `code`); default screens
`UpdatePasswordScreen`, `VerifyEmailScreen`, `TermsScreen`; demo scenarios *carol*, *grace*,
*hank*; S7 moved to frank. Replay tests: `Phase2bReplayTests` (5 transcripts of
`RequiredActionsIT`).

---

## Verified (how) — running list

| What | How |
|---|---|
| Slice 1 (native required actions): 46 integration tests, 15 unit tests | `mvn verify` (Docker; Keycloak + mailpit) |
| Slice 1 SDK: 86 tests | `swift test` (Xcode 27 toolchain) and `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` |
| Demo app package | `swift build` (macOS) |

## Left out (honest list) — running

- `update_password` has no "sign out other sessions" option.
- Required-action config for `native-terms` must be set through the admin console or REST; the
  demo relies on the realm-attribute fallback.
