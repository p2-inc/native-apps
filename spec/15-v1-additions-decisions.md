# 15 — Additions to v1.0-rc from integrator feedback

**Date:** 23 October 2026
**Keycloak:** 26.8.1 (unchanged, 09 Q4; the 26.4 compatibility request is a separate change)
**Code:** `keycloak-native-auth/` (core SPI, endpoint, `native-passkey`, `native-passkey-register`), `ios/KeycloakNative/` (Core, UI)
**Evidence:** `EnrolOnFirstLoginIT`, `ExtensionParametersIT`, `NonNativeExecutionIT` (`mvn verify`), `ProtocolAdditionsReplayTests` (`swift test`), transcripts re-recorded with `demo/scripts/update-transcripts.sh`.

An integrator built a native login on the extensions and the iOS SDK and asked for additive pieces. This memo records the ones implemented here; all are additive to the v1.0-rc freeze (03 §10.1). Decisions of 09–14 are not reopened. Keychain access control, SwiftPM packaging and Keycloak 26.4 support are separate changes.

## D1 — Optional required actions: `skippable` + `action=skip`

**Wire.** A required-action descriptor MAY carry the common field `skippable: true` (03 §3.3); the client declines with `action=skip` (03 §2.2) and the server answers like any other success (next required action or the code). `skippable` is a common descriptor field rather than a `params` entry because it is not type-specific. A skip on a descriptor without the flag is `invalid_request` and the session stays valid (it does not end the login: an SDK or curl mistake should not cost the user the session).

**Server.** `NativeRequiredAction` gained `default boolean isSkippable(RequiredActionContext)` (false) and `default void processSkip(RequiredActionContext)` (`failure()`). `RequiredActionDriver` asks `isSkippable` after every challenge the action emits, puts the flag on the envelope's descriptor and records it in the auth note `native-auth.required-action.skippable`, which is what the endpoint checks before routing `action=skip` to `processSkip`. On success the action is removed from the authentication session only; event `CUSTOM_REQUIRED_ACTION` with detail `skipped=true`; `kc_action_status` = `cancelled`.

**Only session-scheduled actions are skippable.** `AuthenticationManager.nextRequiredAction` re-reads the user's stored required actions on every evaluation and has no "ignored this login" parameter, so a skipped action that stays on the user would come straight back (and the driver's loop guard would turn it into `redirect_to_web`). The driver therefore never marks an action skippable when its alias is stored on the user, whatever `isSkippable` says; an admin-assigned action cannot be declined. This fits the motivating case: `native-passkey`'s *enrol on first login* schedules `native-passkey-register` on the authentication session (14 D4).

**First user.** New `native-passkey` execution config `enrol-optional`: when *enrol on first login* schedules the registration it also sets `native-auth.passkey-register.optional`, which `NativePasskeyRegisterRequiredAction.isSkippable` reads. "Not now" records nothing: the next login without a passkey offers it again. A "don't ask again for N days" policy would be an extension's `processSkip` writing a user attribute; not built.

**SDK.** `Challenge.isSkippable`; `ChallengeAnswer.skip(ChallengeType)` sends `action=skip`. The type is carried because the flow already checks that an answer's type equals the challenge's; the flow refuses `.skip` locally (`flow_state`, nothing sent) when the challenge is not skippable. The default passkey-registration screen shows "Not now" and an offer subtitle for a skippable challenge (en, de).

## D2 — Custom answers

`ChallengeAnswer.custom(type:fields:)` sends arbitrary fields for a challenge through the normal pipeline (DPoP proof and `use_dpop_nonce` retry, `auth_session` rotation, code exchange on 200), so an extension type (03 §4.16) or an action without its own case needs no fork. Fields are `[FormField]` (a small `Hashable` struct), not tuples, so `ChallengeAnswer` stays `Equatable`. An answer may not set `auth_session`, `challenge_type` or `challenge_id` (`invalid_parameter`). Redaction stays name-based (`Redactor.sensitiveKeys`, plus `x_*`, D3): the flow log cannot know which unknown field is a secret, which the API docs say.

## D3 — Extension parameters `x_*`

**Wire (03 §2.3).** Names starting with `x_` are reserved for deployments and never defined by the profile; servers accept them on initial and continuation requests. Limits: 16 per request, names ≤ 64, values ≤ 2048 characters, else `invalid_request` (checked before the `auth_session` is decoded, so a rejected continuation leaves the session untouched). 03 §10 already told servers to ignore unknown parameters; what was missing was a namespace that cannot collide with future profile parameters, and persistence.

**Persistence.** An authenticator that runs at a later continuation never sees the initial request's form, so the endpoint stores initial-request (and step-up) `x_*` values as client notes `client_request_param_<name>`, the convention Keycloak's authorization endpoint uses for extra request parameters; `NativeRequestContext.extensionParameter(authSession, name)` reads them. Continuation values are plain form parameters of their request. Values are never logged or written to events by the server; the SDK masks every `x_*` value in its logs and flow log.

**SDK.** `LoginParameters.additionalParameters` (initial request) and `continuationParameters` (every continuation), plus `respond(_:to:additionalFields:)` for one request; dictionaries, sent in key order. Names the protocol uses (`client_id` … `action`) or the request already carries are refused with `invalid_parameter`. The `x_` prefix is recommended, not enforced by the SDK, so an existing authenticator that reads an un-prefixed field still works.

**Not tested end to end.** No stock authenticator reads an `x_` value and Keycloak's only session-note mapper reads user-session notes (storing request parameters there would keep them for the whole SSO session), so the ITs cover acceptance and the limits; the note-key mapping is a few lines of `ChallengeFlowDriver`.

## D4 — Non-native executions and provider-id length

- Realm attribute `native-auth.non-native-execution` = `error` (default, unchanged: `500 server_error`) | `redirect_to_web`. The latter answers `403 redirect_to_web` with `reason: execution:<provider id>` through `RedirectToWebBuilder` (PKCE and a redirect URI required, else `access_denied`, as for required actions). The error log now names the provider id as well as the execution id.
- Keycloak stores provider ids in `varchar(36)`; an over-long id fails only when it is added to a flow. `NativeAuthResourceProviderFactory.postInit` warns for any `NativeAuthenticatorFactory` / `NativeRequiredActionFactory` id over 36 characters (ours: at most 26).
- Docs: Keycloak loads only top-level JARs in `providers/` (development-and-troubleshooting).

## Not changed

- "Condition - credential" after a passkey login already works: `native-passkey` ends with `success(webauthn-passwordless)`; `CredentialConditionIT` and `docs/flow-examples.md` (separate change).
