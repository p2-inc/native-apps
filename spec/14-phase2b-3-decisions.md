# 14 — Phase 2b (close-out of Phase 2) and Phase 3 (push MFA) decisions

**Date:** 15 October 2026 (Phase 2b complete; Phase 3 in progress)
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

Phase 3 adds **`PushEnrolment`** (module `native-auth-push`) to the list: it uses
`KeycloakModelUtils.generateId` and `KeyWrapper` (`server-spi-private`) to mirror ba-itsys'
enrolment verification, plus ba-itsys' own non-SPI classes (`PushChallengeStore`,
`PushEnrollmentTokenBuilder`, `PushSignatureVerifier`, …), which are internal to that extension and
the reason for upstream item 1 in D10. `NativePushAuthenticator` and `NativePushEnrollRequiredAction`
use ba-itsys' `ChallengeIssuer` / `ChallengeNoteHelper` / `PushCredentialService` the same way.
`NativeAuthResource` reads `OIDCLoginProtocolService` only for the realm's token endpoint URL
(unchanged).

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

## D2 — `native-recovery-code` delegates to Keycloak's credential provider, which consumes codes in order

**Decision.** `native-recovery-code` (module `native-auth-authenticators`) is a `CredentialValidator`
for `recovery-authn-codes`: `configuredFor` is true while the user's credential has unused codes,
`describe` reports `remaining` (read from the stored credential data JSON — 26.8.1's
`RecoveryAuthnCodesCredentialModel` has no accessor for it) and the realm's
`recoveryCodesWarningThreshold`, and `action` normalises the input like Keycloak's form (dashes and
spaces dropped, upper-cased) and calls `credentialManager().isValid(buildFromBackupAuthnCode)`,
which checks the **next** unused code only and removes it on success. After the last code the
authenticator adds `CONFIGURE_RECOVERY_AUTHN_CODES`, which has no native variant, so the login ends
with `redirect_to_web` — the same thing Keycloak's form does with its page. A wrong code counts as a
brute-force failure. Spec: 03 §4.8 (eligibility, normalisation, `warning_threshold`).

**Demo / evidence.** User `ivy` (password, TOTP secret `ivy-totp-secret-20261015`, three recovery
codes seeded **hashed** in the export: SHA-512 + standard base64 exactly as
`RecoveryAuthnCodesCredentialModel.createFromValues` stores them; the raw codes are
`IVY1-IVY1-IVY1`, `IVY2-IVY2-IVY2`, `IVY3-IVY3-IVY3`); `native-recovery-code` is an ALTERNATIVE
beside `native-totp` in the `native` flow's second factor, so ivy's set is `[totp, recovery_code]`.
`RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut` covers wrong code, display format, order and
single use, the countdown, the redirect after the last code and the `[totp]`-only set afterwards;
it re-creates ivy from the export at the end (a user representation with `credentialData` /
`secretData` imports arbitrary credential types through the admin API). SDK: `.recoveryCode`,
`RecoveryCodeParams` (`shouldWarn`), `RecoveryCodeScreen`, demo scenario *ivy*.

## D3 — Unknown users get a phantom `password` challenge with the same lock-out countdown

**Problem.** 09 recorded the enumeration limitation: a valid username advanced to `password`, an
unknown one re-challenged `username`. 03 §4.1 asked for a phantom challenge.

**Decision.** When `native-username` finds no usable user (unknown, disabled, or locked by the
brute-force detector) and `reveal-user-not-found` is off, it stores the auth notes
`native-auth.phantom` (the attempted username) and `native-auth.phantom.attempts`, and emits the
**real** `native-password` execution's descriptor (first one in flow order; `[password]`,
`required`, `username_known: true`) as the pending set. The endpoint routes the answer to
`native-password` as usual (`DefaultAuthenticationFlow.processAction` does not check
`requiresUser`; only the forward path `processSingleFlowExecutionModel` does), which, seeing no user
and the phantom note, runs `dummyHash`, records a failure (`failureChallenge`, so a real-but-locked
account keeps accruing failures exactly like in the browser) and re-issues the challenge with
`invalid_credential` and `retry.remaining = failureFactor − attempts`; at zero it fails with
`USER_TEMPORARILY_DISABLED`, i.e. the same `403 access_denied "Account temporarily locked"` a real
account gets. A phantom session can never authenticate through the password (there is no user to
set); a discoverable passkey in the same flow still works through `user_handle`. A flow without
`native-password` falls back to the generic re-challenge of `username`.

**`retry.remaining`** (03 §3.3): `NativeAuthenticatorBase.failAndRechallenge` now sets it on the
failed descriptor for identified users when the realm is brute-force protected:
`failureFactor − (recorded failures + 1)` (the processor records the failure after the
authenticator returns). The quick-login rule (two failures within a second) can lock earlier than
the countdown predicts; the counter does not model it. Evidence:
`unknownUsernameGetsAPhantomPasswordChallengeThatLocksLikeARealAccount` (countdown 4…1, lock on
the fifth), `bruteForceLockEndsWithAccessDenied` (erin: countdown, then the locked account gets the
phantom challenge on the next login). SDK: default screens and the demo show "n attempts left".

## D4 — "Enrol on first login" is a per-execution flag that schedules the registration action for this login only

**Decision.** `native-passkey` gained the config property `enrol-on-first-login` (default off). In
its `authenticate()` branch for an identified user without a passkey (the execution is an
ALTERNATIVE beside the password, 11 D2), the flag adds `native-passkey-register` to the
**authentication session** (not the user) when the realm has that action enabled, then marks the
execution attempted as before; the password alternative authenticates the user and the registration
runs in-band right after (`EnrolOnFirstLoginIT.bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin`:
`[password]` → `passkey_registration` → code; the next login offers `[passkey, password]`). Scoping
the action to the session means a cancelled login leaves nothing behind and a browser login of the
same user never sees it. A REQUIRED `native-passkey` execution keeps failing with
`access_denied` for a user without a passkey: nothing could authenticate the user first, and
Keycloak's `SETUP_REQUIRED` shortcut would grant the primary factor without any factor.
`setRequiredActions`/`isUserSetupAllowed` were not used: the engine only consults them for
`requiresUser()` authenticators and REQUIRED executions.

**Registration endpoints restricted to native clients** (11 D5 option): realm attribute
`native-auth.passkey-registration-native-clients-only=true` makes `/passkey/register/*` answer
`403 access_denied` for a token whose client is not `native-auth.enabled`
(`registrationEndpointsCanBeRestrictedToNativeClients`, which flips demo-ios's flag under a token it
issued). Default off, as 11 D5 chose.

## D5 — SMS webhook proven against a host-side sink; the OTP mail is a theme template

**SMS.** `KeycloakContainerSupport` starts an in-JVM `HttpServer` (`SmsSink`) before Keycloak,
exposes its port with `Testcontainers.exposeHostPorts`, and configures the sender through the
environment form of the SPI options (`KC_SPI_NATIVE_OTP_SENDER__SMS_WEBHOOK__URL=http://host.testcontainers.internal:<port>/sms`,
`…__TOKEN`). The demo realm gained flow `native-sms` (username → password → `native-otp` with
config `native-otp - sms`, channel `sms-webhook`) and client `demo-ios-sms`; bob carries
`phoneNumber` (the IT enables the realm's unmanaged-attribute policy, since Keycloak's declarative
user profile drops unknown attributes on import). `SmsOtpIT.bobGetsAnSmsCodeThroughTheWebhook`
checks the descriptor (`channel: sms`, `destination_masked: ***23`, `sent: true`), the webhook
body and bearer token, a wrong code and the right one. The compose stack has no sink; set the same
two variables on the `keycloak` service to point at a real gateway.

**Themed mail (08 Q10).** `EmailOtpSender` now sends through `EmailTemplateProvider.send(subjectKey,
subjectAttributes, "native-otp.ftl", attributes)`; the JAR ships
`theme-resources/templates/{html,text}/native-otp.ftl` and `theme-resources/messages/messages_{en,de}.properties`
(`nativeOtpSubject`, `nativeOtpBodyText`, `nativeOtpBodyHtml`), which Keycloak's
`ClasspathThemeResourceProviderFactory` merges into every email theme, so a realm theme can override
the template without touching the JAR and the user's / request's locale selects the language. The
phrase *"Your verification code is <digits>"* is kept because the ITs, the SDK live tests and the
XCUITests parse it out of mailpit. A theme without the template falls back to the previous inline
message rather than failing the login. The same mail serves `native-verify-email`.

## D6 — Post-login `auth_session` lives for the SSO idle timeout (08 Q11)

`PostLoginAuthSession.mint` sets `exp = now + ssoSessionIdleTimeout`, capped by what is left of the
session's `ssoSessionMaxLifespan` (looked up from the user session), instead of the full max (11
D4). `stepUp` still checks `AuthenticationManager.isSessionValid`. Consequence: an app that keeps
its tokens fresh but does not step up within the idle window gets `invalid_session` on the next
step-up and must log in again — unless it received a fresh value from a step-up or a §6 refusal in
between. `StepUpIT.postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive` (idle =
3 s, refresh at 2 s, step-up at 4 s → `invalid_session` while a refresh still works). 03 §3.1 / §5
updated.

## D7 — UI product: a string catalogue with an override bundle, and tests of the model behind the screens

**Localisation.** `KeycloakNativeUI` ships `Resources/Localizable.xcstrings` (English source keys,
German translations; SwiftPM `.process` resource, `Bundle.module`). The screens read every text
through `NativeLoginStrings` (`@Environment(\.nativeLoginStrings)`), which looks a key up in an
optional **override bundle** first (`.nativeLoginStrings(bundle:)`, 05 §4) and falls back to the
package catalogue, so an app can replace single keys without copying the catalogue. Format
arguments use `%@` / `%lld` with `String(format:locale:)`. `Core`'s strings (error messages from the
server, `UpdatePasswordParams.hints`) stay English: they are data, not UI, and apps map them if they
need to. The CLT-only test mode (`--build-system native`) compiles the catalogue too (verified).

**Tests of the product.** A new test target `KeycloakNativeUITests` exercises `NativeLoginModel`
with a scripted transport (the model is what every screen binds to; SwiftUI views are not rendered
in `swift test`): the first supported entry is shown and unknown types are skipped, the chooser's
alternatives, switching entries, a failed entry being shown again with `retry.remaining`, success
→ `.authorized`, `cancel` → `action=cancel` + `.cancelled`, a network error staying inline while
`access_denied` ends the view, and `redirect_to_web` becoming its own phase; plus the catalogue
(English, German) and the override chain (`NativeLoginStringsTests`). Lesson recorded: Swift
Testing's `#expect` must not be called from inside a transport closure that runs on the model's
task — it traps the test process; assert on `transport.sent` afterwards.

**XCUITests** (`UITests/DemoAppUITests.swift`): S4 (bob's e-mail code via mailpit), S5 (default UI,
chooser `switchTo-otp`, "Send me a code"), S13 (custom TOTP presenter), S6 (Transfer → 401 →
step-up asks the TOTP only → `acr 2` → Transfer 200), S8 (server-side logout →
`reauthentication_required`), carol / grace / hank. S7 stays manual (Safari). The runner reads
mailpit's API with a plain `URL(string:)` — `URL.appending(path:)` percent-encodes the `?` of a
query and was the reason the first grace run found no mail.

## D8 — Protocol v1.0-rc: freeze the implemented sections, keep the wire version at `"1"`

03 §10.1 lists what is frozen (everything implemented on both sides: §1.1 minus `push`, §2, §3,
§4.1–§4.6, §4.8, §4.10–§4.14, §5, §6, §8) and what stays draft (`push`, §7, `select`, §9). The wire
value `protocol_version` remains `"1"` because clients compare majors only (03 §10) and nothing
incompatible changed. The conformance suite is the committed transcript set (53 files after this
phase); the SDK's replay tests and the integration tests are its two readers. Left for v1.0: the
Phase 3 push items and a final editorial pass. The optional well-known override (04 §2.3) and the
completion-handler / Combine API variants (05 §2) were not built: nothing in the phase needed them.

---

## D9 — Push MFA: the SDK's DPoP key is the device key and the native token is the device token

**Context.** 08 Q5/Q6 asked for a programmatic push enrolment API in this repository (ba-itsys'
extension only enrols through its own `push-mfa-register` web form) and for the device to obtain
a "device token" for the ba-itsys device API by token exchange from the user's native token, so
that no client secret ships in the app.

**Finding.** Keycloak 26.8's standard token exchange (`StandardTokenExchangeProvider`) refuses a
public client as the requesting party ("Public client is not allowed to exchange token"), and the
native clients are public with PKCE + DPoP (03 §2, §8). Token exchange would have required a
confidential "device" client and therefore a shipped secret or a backend — exactly what Q6 forbade.

**Decision (03 §7.1).** The ba-itsys device API already binds every call to a key: it accepts
`Authorization: DPoP <any realm access token>` whose `cnf.jkt` equals the thumbprint of the
enrolled device key, plus a DPoP proof carrying `ath`, `sub` and `deviceId`. The SDK's DPoP key
(05 §5.1, Secure Enclave or software P-256) is therefore used **as the device key**, and the user's
DPoP-bound native access token **is** the device token. The metadata `push` block says
`device_token: "native"`; the `client_credentials` variant is a documented extension point for
deployments with a backend (`device_client_id`), not built. `DeviceTokenProvider` stays abstract
in the SDK with the native-token implementation as its default.

Consequences:
- One key per installation covers both DPoP sender constraining and push approvals. Rotating the
  push key (`/push-mfa/device/rotate-key`) is therefore the SDK's DPoP key rotation: it re-binds the
  push credential to the new key, and the next login binds the tokens to it.
- A login that is not DPoP-bound cannot enrol a push device (the device API would be unreachable
  with that token); `native-push-enroll` refuses an enrolment JWT whose `cnf.jwk` differs from the
  session's DPoP key when the session is bound (03 §4.15), and `/native-auth/push/enroll/start`
  requires a DPoP-bound bearer.

**ba-itsys on Java 21.** Every published `keycloak-push-mfa-extension` jar (2.2.0 … 2.3.7) is
compiled with `--release 25` (class file 69); the `quay.io/keycloak/keycloak:26.8.1` image runs
OpenJDK 21 and refuses to load it ("compiled by a more recent version of the Java Runtime"). The
source uses no Java 22+ API, so the module `push-mfa-extension-java21` unpacks the published
**sources** jar of the pinned version (`push-mfa.version`, 2.3.7) at build time and recompiles it
with `--release 21` into `keycloak-push-mfa-extension-java21.jar`. No third-party source is checked
in; the demo deploys that rebuild and our modules compile against it.

A second obstacle is independent of the JRE: `PushMfaResource` marks its two SSE streams
`@RunOnVirtualThread`, and Quarkus refuses such endpoints when "the application" was compiled below
Java 19 — it measures that on the first class file it finds, which in the Keycloak distribution is
Keycloak's own `Environment$1.class`, compiled for Java 17 in 26.7.x and 26.8.x alike (verified on
the `keycloak-quarkus-server` jars). ba-itsys' own compose overlays a Java 25 JRE on the image,
which does not change that measurement. The rebuild therefore drops the two annotations (an Ant
`replace` on the unpacked source, the only source-level change); the SSE streams run on worker
threads and block for the challenge TTL, which the demo tolerates (the wait page also has a refresh
form, and the native paths never use SSE). Upstream item 0 below asks for both.

**Server pieces** (modules `native-auth-push`, `native-auth-push-apns`, plus a core SPI
`native-auth-push-enrolment` so the endpoint module stays free of ba-itsys types):
- `PushEnrolment` — the programmatic half of ba-itsys' enrolment: `start` creates the pending
  enrolment challenge and the realm-signed enrolment token with ba-itsys'
  `PushEnrollmentTokenBuilder`; `complete` verifies a device-signed enrolment JWT **exactly as
  `POST /push-mfa/enroll/complete` does** (subject, enrollmentId, nonce, exp, `cnf.jwk`, signature
  with `PushSignatureVerifier`, field limits with `PushMfaInputValidator`) and stores the
  credential with `PushCredentialService`. The verification is duplicated from ba-itsys'
  `PushEnrollmentResource` because that class is a JAX-RS resource with no reusable service
  behind it — the first item of the upstream list below.
- `POST /native-auth/push/enroll/start` (03 §7 b): bearer/DPoP native token → `{enrollment_token,
  expires_in, device_api_base, user_id}`; the device then calls ba-itsys'
  `/push-mfa/enroll/complete` itself. Scenario C's in-app enrolment.
- `native-push-enroll` required action (03 §4.15): substitutes for `push-mfa-register` (D1), so a
  user carrying ba-itsys' action enrols in-band; answers `token=<device JWT>` or `action=check`.
- `native-push` authenticator (03 §4.7): wraps ba-itsys' `ChallengeIssuer`/`PushChallengeStore`;
  `prepare` issues the challenge only when push is the single option (the "sent on describe" rule
  of 03 §4.7), otherwise `action=resend` creates it (10 s cooldown); `action=poll` reads the store:
  pending → re-challenge, approved → success, denied → `denied` with the cooldown, expired →
  `expired`. Number match is `params.user_verification`; the number list the device sees comes from
  ba-itsys' pending API. `cancel` is Keycloak's session end (03 §3.4), no device-side denial.
- Credential type and device API are ba-itsys' (`push-mfa`, `/realms/{realm}/push-mfa/*`); the
  browser flow `browser-push` of the demo realm uses ba-itsys' `push-mfa-authenticator` as a
  conditional second factor (scenario A) — nothing of ours is in that path except the APNs sender.

**Secrets.** The enrolment token, the device JWTs, the confirm token and the APNs device token are
never logged (the APNs sender logs challenge and credential ids only); `TranscriptRecorder` records
the device API exchanges and the SDK `Redactor` masks `token`, `enrollment_token`, `confirmToken`,
`pushProviderId` and `Authorization`.

---

## D10 — `apns` sender: HTTP/2 with token-based provider authentication, no third-party client

ba-itsys ships `log`, `none` and `fcm` senders. `native-auth-push-apns` registers `apns` for the
`push-notification-sender` SPI with the JDK `HttpClient` (HTTP/2) and a provider JWT (ES256,
`kid`/`iss`/`iat`) minted from the `.p8` key and reused for 50 minutes (Apple accepts up to 60).
`pushProviderId` of the credential is the APNs device token the app registered. Headers:
`apns-topic` (bundle id), `apns-push-type: alert`, `apns-priority: 10`, `apns-collapse-id: <cid>`,
`apns-expiration` (challenge TTL). Payload: a localised, time-sensitive alert
(`PUSH_MFA_TITLE`/`PUSH_MFA_BODY` with the client id as argument, category `PUSH_MFA_APPROVAL`,
`mutable-content: 1` so the notification service extension can decode the confirm token) and the
ba-itsys custom keys `confirmToken`, `cid`, `credId`, `typ`, `ver`. No username in the payload.
Delivery failures are logged with Apple's `reason` and never fail the login: the device can still
fetch the pending challenge itself (05 §5). Configuration: `--spi-push-notification-sender--apns--
{team-id,key-id,key|key-file,topic,environment,url,expiration-seconds}`; unconfigured, the sender
is installed but skips (so the compose stack starts without Apple credentials).

Tests: a unit test of the provider token and payload; the ITs run against an in-JVM fake APNs
(`ApnsSink`, `POST /3/device/{token}`) reached through `host.testcontainers.internal`, which
records headers and bodies. Apple's real endpoint was not exercised (no Apple team, see "Left out").

**Upstream to ba-itsys** (offer as PRs; what this repository carries in the meantime):
0. Build with `--release 21` (the image's JRE) and make `@RunOnVirtualThread` conditional or drop
   it, since the official Keycloak 26.x distribution cannot deploy it (module
   `push-mfa-extension-java21` here).
1. A `PushEnrollmentService` behind `PushEnrollmentResource` (start + complete without JAX-RS),
   which would delete `PushEnrolment.complete`'s duplicate verification.
2. The `apns` sender as a built-in sender next to `fcm`.
3. A hook in `PushMfaAuthenticator` (or a `ChallengeIssuer` with a configurable user-verification
   payload) so a non-HTML authenticator can reuse number-match generation without re-implementing
   the challenge lifecycle — `NativePushAuthenticator` would shrink to the wire mapping.
4. `DpopAuthenticator`: document that any DPoP-bound realm token is accepted as device token, which
   D9 relies on.

---

## Verified (how) — running list

| What | How |
|---|---|
| Slice 1 (native required actions): 46 integration tests, 15 unit tests | `mvn verify` (Docker; Keycloak + mailpit) |
| Slice 1 SDK: 86 tests | `swift test` (Xcode 27 toolchain) and `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` |
| Slice 1 app: carol / grace / hank XCUITests on the iPhone 18 Pro simulator (iOS 27.0) | `xcodebuild test … -only-testing:…` against a fresh compose stack (see "Simulator runs" below) |
| Slice 2 (recovery codes): `RecoveryCodeIT` (1) | `mvn verify -Dit.test=RecoveryCodeIT`, then the full `mvn verify` at the end of the phase |
| Slice 3 (phantom username, `retry.remaining`): `NativeAuthIT` (20) | `mvn verify -Dit.test=NativeAuthIT`, full run at the end |
| Slice 4 (enrol on first login, native-clients-only registration): `EnrolOnFirstLoginIT` (3) | `mvn verify -Dit.test=EnrolOnFirstLoginIT`, full run at the end |
| Slice 5 (SMS webhook, themed mail, idle-timeout `auth_session`): `SmsOtpIT` (1), `StepUpIT` (6), `OtpIT` / `RequiredActionsIT` with the templated mail | `mvn verify -Dit.test=…`, full run at the end |
| Slices 2–5 together: 52 integration tests, 15 unit tests | full `mvn verify` after slice 5 |
| Slice 6: `KeycloakNativeUITests` (7) + the Core suites: 102 tests | `swift test` (Xcode 27 toolchain) and `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native` |
| End of Phase 2b: compose stack + `walkthrough.sh` | `docker compose down -v && KC_PORT=8089 docker compose up --wait && KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh` → exit 0 |
| End of Phase 2b: 10 live SDK tests (S3 lifecycle, S11→S1→S2, dave, S6, S4, S7 on frank, carol, grace, hank, S14) | `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089 swift test --filter LiveServerTests` |
| End of Phase 2b: 10 XCUITests on the iPhone 18 Pro simulator (iOS 27.0): S3 + relaunch/refresh/logout, S14, S4, S5, S13, S6, S8, carol, grace, hank | `xcodebuild test … CODE_SIGN_IDENTITY="-"` against a fresh compose stack (5 min) |
| Demo app package | `swift build` (macOS) |
| Phase 3 server: `PushMfaIT` (6: in-app enrolment, scenario A browser login approved on the device, scenario B with number match, denied push + rate-limited resend, device maintenance incl. key rotation and lockout, judy's in-flow enrolment) against a fake APNs; `ApnsPayloadAndTokenTest` (2) | `mvn verify -Dit.test=PushMfaIT`, then the full `mvn verify` (58 ITs, 17 unit tests) |
| Phase 3 SDK: `Phase3ReplayTests` (8) replaying the 6 push transcripts, the push cases of `RedactionTests`, `NativeLoginModelTests` push enrolment commit | `swift test` (Xcode 27 toolchain) and `KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native`: 115 tests (107 Core + 8 UI) green in both modes |
| Phase 3 live: `LivePushTests` (4: S9 with a cookie-keeping `URLSession` as the browser, S10, S12, judy) + the 10 earlier live tests | `KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089 swift test --filter "LiveServerTests|LivePushTests"` against a fresh compose stack |
| Phase 3 app: `PushUITests` (4: S9, S10, S12, judy) on the iPhone 18 Pro simulator (iOS 27.0) | `xcodebuild test … -only-testing:KeycloakNativeDemoUITests/PushUITests CODE_SIGN_IDENTITY="-"`: 4/4, then the 10 earlier `DemoAppUITests` again: 10/10 (14 XCUITests in all) |
| End of Phase 3: compose stack from a clean clone + `walkthrough.sh` | `docker compose down -v && KC_PORT=8089 docker compose up --wait && KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh` → exit 0 (the stack now carries ba-itsys, the `apns` sender and the push bridge) |

## Left out (honest list) — running

- **Push MFA on a device.** No Apple team, no device and no Simulator.app in this environment: the
  `apns` sender was exercised against a fake APNs only, `PushNotificationService.rewrite` (the
  notification service extension helper) and the app delegate's token registration compiled but
  never ran, and every approval on the simulator was pulled from `/push-mfa/login/pending`. A device
  run needs: the Push Notifications entitlement, an `.p8` key in the compose environment
  (`APNS_*`), and a notification service extension target wired to the shared Keychain group.
- `PushEnrolment.complete` duplicates ba-itsys' enrolment verification (D9); it tracks
  `push-mfa.version` 2.3.7 and must be re-checked on every ba-itsys upgrade until upstream item 1 lands.
- The enrolment token's realm signature is not verified on the device (the token arrives over TLS
  from the issuer and the server verifies the device JWT it answers with); an app that wants it can
  verify against the realm JWKS before `prepareEnrollment` (extension point, no API yet).
- `select` (03 §4.9) still has no authenticator; the curl walkthrough has no push section (signing
  ES256 device JWTs in bash was not worth it; the ITs and the SDK cover it).

- `update_password` has no "sign out other sessions" option.
- Required-action config for `native-terms` must be set through the admin console or REST; the
  demo relies on the realm-attribute fallback.
