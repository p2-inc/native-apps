# Protocol and server reference

[Index](README.md) · [End-to-end examples](flow-examples.md) · [iOS APIs](ios-integration.md) · [Android APIs](android-integration.md)

## Transport contract

Paths below are relative to the configured **issuer**, e.g. `https://idp.example.com/realms/demo`. The issuer already includes the realm. Native login uses no HTTP cookies: [ChallengeFlowDriver](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/ChallengeFlowDriver.java) creates a root authentication session and client tab without cookies; the [SDK transport](../ios/KeycloakNative/Sources/KeycloakNativeCore/Transport/HTTP.swift) disables cookie acceptance/storage and disk caching, uses a 30-second request timeout, and does not wait for connectivity.

| Method/path | Body/authentication | Response |
| --- | --- | --- |
| `GET /native-auth/metadata` | No authentication | 200 metadata |
| `POST /native-auth/challenge` | URL-encoded form, optional `DPoP` proof | 403 challenge, 200 code, or error |
| `POST /protocol/openid-connect/token` | URL-encoded authorization-code or refresh grant; public `client_id`; optional DPoP | Standard token JSON |
| `POST /native-auth/passkey/register/options` | No body; user access token | 200 creation options + `registration_id` |
| `POST /native-auth/passkey/register/finish` | JSON; user access token | 201 `credential_id`, `label` |
| `POST /native-auth/push/enroll/start` | No body; user access token | 200 enrollment challenge; 404 if bridge absent |
| `POST /protocol/openid-connect/revoke` | Form `client_id`, `token`, optional `token_type_hint` | Standard revocation result |
| `POST /protocol/openid-connect/logout` | Form `client_id`, `refresh_token` | Standard logout result |

Send `Accept: application/json`. Form requests use `Content-Type: application/x-www-form-urlencoded; charset=utf-8`; JSON requests use `application/json`. Binary WebAuthn fields are base64url without padding. Times such as `resend_allowed_at` and `expires_at` are Unix seconds; `timeout` in WebAuthn options is milliseconds. [Responses](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/Responses.java) adds `Cache-Control: no-store` and `Pragma: no-cache` to native JSON responses.

### Discovery and starting

[NativeAuthResource](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/NativeAuthResource.java) serves metadata under provider ID `native-auth`. Use this endpoint rather than assuming a custom OIDC well-known override exists (none is implemented here). Metadata contains `protocol_version: "1"`, `fipa_draft`, endpoint URLs, `code_exchange`, `passkey` (RP ID/registration URLs), installed `challenge_types_supported`, verified `dpop_signing_alg_values_supported`, and reserved `client_attestation: {required:false, methods:[]}`. `push` is present only with the push enrollment provider installed; this bridge advertises `device_token: "native"`. Installed types are not a guarantee that a particular client's flow offers them. `select` and `redirect_to_web` are not emitted by the installed-type enumeration; the latter is an error outcome, not a descriptor.

An initial form requires `client_id` and `response_type=code`. The client must exist, be enabled, public, standard-flow enabled, and have `native-auth.enabled=true`. Missing client ID is 400 `invalid_request`; an unknown/ineligible client is 401 `invalid_client`. There is no mobile client secret.

| Initial field | Type/behavior |
| --- | --- |
| `code_challenge`, `code_challenge_method` | Strings; SDK always generates S256. Server enforces the client's configured PKCE method. Without a client requirement it permits omitted PKCE, or `plain`/`S256`; supplied challenge must match `[A-Za-z0-9_-]{43,128}`. Configure S256 explicitly. |
| `scope` | Optional space-separated string; SDK defaults to `openid` |
| `login_hint`, `ui_locales` | Optional strings for username hint and request locale |
| `acr_values` | Optional space-separated ACR values, mapped through Keycloak's client/realm ACR-to-LoA configuration or numeric values |
| `max_age`, `prompt` | Optional seconds/string; used to force reauthentication when stepping up; they do not provide a browser cookie session on a fresh native login |
| `nonce` | Optional string copied to OIDC client notes; SDK does not generate or verify one automatically |
| `device_name`, `device_id` | Optional application-supplied label/stable UUID; informational client notes, not device attestation |
| `auth_session` | Omit for fresh login. A post-login value plus the initial fields starts step-up. An in-progress value routes to continuation instead. |

Native initial `redirect_uri` is not used to select the code redirect binding. That is server configuration below. Initial `state` is not an SDK parameter and is not a native continuation binding.

### Challenges and continuation

```json
{
  "error": "insufficient_authorization",
  "error_description": "Authentication required",
  "auth_session": "<opaque-session-1>",
  "protocol_version": "1",
  "expires_in": 1800,
  "challenges": [{
    "type": "username", "id": "<execution-username>",
    "label": "Username", "required": true,
    "params": {"allow_email": true}
  }],
  "context": {"client_name": "Demo iOS App"}
}
```

This illustrative response is HTTP **403**, which is an expected intermediate state. The SDK also tolerates 400 carrying this challenge envelope. Common descriptor fields: `type` and opaque `id` are required strings; `label` is optional display text; `required` is boolean; `params` is a type-specific object. Optional `error:{code,message?}` describes the previous failed attempt, and `retry:{remaining}` is a numeric advisory countdown when available. `context` can add `username`, `display_name`, `step_up` and `acr_requested`; it is informational, not proof of authentication.

Submit one currently offered descriptor:

```text
auth_session=<opaque-session-1>&challenge_type=username&challenge_id=<execution-username>&username=alice
```

URL-encode every value. Retain the **latest** `auth_session` after each response, including surviving-session `invalid_request` errors. `id` is an execution ID for authenticators, or a native provider ID for required actions; neither is application-selected. Do not resend initial fields on normal continuation. Server checks `client_id` if supplied but does not revalidate every repeated initial field; do not rely on scope/PKCE changes being accepted.

The encrypted `auth_session` binds realm key, client, root session/tab and optionally DPoP key. It is sensitive and opaque: never decode it in an application. In-flow validity comes from the server session, action and Keycloak login/user-action timeouts; valid continuations refresh the root timestamp. The export uses login **1800 s**, user action **300 s**. Rotating its JWE value is not a one-time-token guarantee: current pending execution and challenge-specific replay checks remain authoritative. See [security](security.md).

### Completion and standard tokens

HTTP 200 `{"authorization_code":"<code>","auth_session":"<post-login-session>"}` ends the native flow. [CodeIssuer](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/CodeIssuer.java) completes required actions, attaches a Keycloak session and issues the code; [NativeLoginFlow](../ios/KeycloakNative/Sources/KeycloakNativeCore/Challenge/LoginFlow.swift) exchanges it automatically before exposing `.authorized(Credentials)`.

```text
POST /realms/demo/protocol/openid-connect/token
grant_type=authorization_code&client_id=demo-native&code=<code>&code_verifier=<original-verifier>
```

Token response uses `access_token`, `token_type`, `expires_in`, and optional `refresh_token`, `refresh_expires_in`, `id_token`, `scope`. No `redirect_uri` is sent in default mode. SDK does not validate token signatures/issuer/audience/nonce; decoded claims are display-only. Resource servers must validate tokens and DPoP when applicable.

The returned post-login `auth_session` points to the user session, not the old authentication tab. It expires at issuance time plus SSO idle timeout, capped by remaining maximum lifespan (demo: 1800/36000 s). Refresh preserves this value and does **not** extend its embedded expiry. Successful step-up produces a fresh value; ended user sessions invalidate it. It does not itself authorize resource access.

### Errors, retries and cancellation

| HTTP/error | Behavior and application action |
| --- | --- |
| 400 `invalid_request` | Missing/mismatched type, unknown/not-pending ID, malformed initial fields. Existing flow can survive; error may include replacement `auth_session`. Correct the request. |
| 400 `invalid_session` | Invalid JWE, missing server session, expiry, cancellation, client/key mismatch or ended post-login session. Start a new login. An omitted session routes to a new initial request and may instead fail its required-field checks. |
| 400 `invalid_dpop_proof` | Supplied proof rejected before flow processing; correct proof/URL/clock/key. |
| 401 `invalid_client` | Correct client configuration. |
| 403 `access_denied` | Terminal flow failure, disabled/locked account, missing required credential, declined action or impossible fallback. |
| 500 `server_error` | Invalid flow or unexpected server error; SDK treats it as terminal. |
| 403 `redirect_to_web` | Separate terminal native outcome described below. |

Descriptor errors normally arrive inside a new 403 challenge set, so render them and use its fresh descriptor/params. Missing credentials generally rechallenge without counting a failed login; wrong password/TOTP/passkey/recovery/OTP and denied push use brute-force failure handling. Keycloak quick-login lockout can trigger before the displayed countdown reaches zero. Never retry credentials automatically. No general automatic network retry is implemented; an ambiguous network failure may mean the server already consumed an answer/code. A token-exchange failure happens after the flow is marked finished; start another login rather than calling `start()` again. Only DPoP nonce challenges have a one-time automatic retry.

Cancel an in-progress login with `auth_session=<latest>&action=cancel`, no descriptor required. Server removes the session and returns 400 `invalid_session` (“cancelled”); SDK `cancel()` absorbs errors, clears pending state and finishes locally. This is best effort if offline. It is not logout of a completed user session. A passkey-sheet cancellation alone leaves the native flow pending. No implemented `429 slow_down`, client-attestation enforcement or `action=select` should be inferred from the older spec.

## Server configuration

Values are implemented in [NativeAuthConfig](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/NativeAuthConfig.java). Import the [demo export](../keycloak-native-auth/demo/realm-export/demo-realm.json) for a reproducible setup; ordered layouts are in [flow examples](flow-examples.md).

| Scope/key | Default and meaning |
| --- | --- |
| Client `native-auth.enabled` | Unset/false denies native endpoint access; set string `true` |
| Client/realm `native-auth.flow-alias` | Client override → realm → `native`; not the realm browser-flow binding |
| Realm `native-auth.code-redirect-uri-mode` | `none`; alternatives `sentinel`, `client-fixed` |
| Client/realm `native-auth.code-redirect-uri` | Fixed code URI: client → realm → a registered client URI |
| Client `native-auth.web-fallback-redirect-uri` | Explicit fallback callback; otherwise lexicographically first non-wildcard registered URI; configure a registered exact URI |
| Realm `native-auth.passkey-registration-max-age` | `300` seconds since user-session `AUTH_TIME`; `0` disables. Also applied to push enrollment start. |
| Realm `native-auth.passkey-registration-native-clients-only` | `false`; `true` restricts authenticated registration and enrollment-start to native-enabled clients |
| Realm `native-auth.terms-text`, `native-auth.terms-url`, `native-auth.terms-version` | Fallback terms content for the required action |
| Keycloak client/realm `acr.loa.map`, `default.acr.values`, `minimum.acr.value` | Standard ACR settings used by requested-level calculation |

`none` stores no code redirect URI; SDK omits it at exchange. `sentinel` requires `urn:keycloak:native-auth`. `client-fixed` requires the stored fixed URI. **Current limitation:** realm-wide metadata only returns the realm's `native-auth.code-redirect-uri`, even though issuance can use a client override/registered URI. With `client-fixed`, configure a consistent realm value for SDK clients; per-client-only values can make SDK exchange fail (`invalid_response` or redirect mismatch). Metadata discovery has no client parameter.

### Flow composition

The server runs Keycloak's `AuthenticationProcessor.authenticateOnly()` and `DefaultAuthenticationFlow.processAction()`; it does not execute a fixed SDK screen sequence. `REQUIRED` executions/subflows must succeed. `ALTERNATIVE` siblings form choices: satisfying one can satisfy that subflow, so put sequential mandatory stages in separate required subflows. `CONDITIONAL` subflows run according to their required condition executions; `conditional-user-configured` gates factors by configured credentials, and `conditional-level-of-authentication` gates requested/reusable levels. `DISABLED` executions do not run. Follow the exported structure rather than mixing REQUIRED and ALTERNATIVE siblings expecting all to be offered.

[NativeAuthenticatorBase](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativeAuthenticatorBase.java) gathers eligible native alternatives from Keycloak selections, filters by credential availability, orders them by depth-first flow priority, then calls `prepare`. A singleton descriptor has `required=true`; multiple choices each have `required=false`. This flag describes the current choice set, not the admin console's execution requirement. Preparation sends OTP/push automatically only for a single choice. A non-native alternative can be skipped in set construction; an execution actually returning HTML instead of the native marker causes 500 `server_error` and session deletion. This is not an automatic browser handoff. Native authenticators placed in browser flows mark themselves attempted and warn; they cannot replace browser form authenticators there.

## Authenticator reference

All authenticators below accept REQUIRED, ALTERNATIVE or DISABLED execution settings. Required factors needing a credential fail if it is absent; optional eligible choices disappear instead. Factory display strings and source implementations are linked per row. Configuration defaults apply when absent, not necessarily the demo override.

| Provider ID / console display / source | Placement and challenge contract |
| --- | --- |
| `native-username` / **Native: Username** / [source](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativeUsernameAuthenticator.java) | REQUIRED first, or in discoverable login's username/password alternative. `username` params `allow_email:bool`, optional `hint:string`; answer `username:string`. Finds user by username/email and advances; already-known step-up user succeeds without UI. `reveal-user-not-found` default `false` produces a phantom password challenge for unknown/disabled/locked users; `true` can expose `invalid_user`. Empty/overlong input → `missing_credential`. Phantom answers always fail, with per-session countdown. |
| `native-password` / **Native: Password** / [source](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativePasswordAuthenticator.java) | After identification; REQUIRED or primary-factor ALTERNATIVE. No execution configuration. `password` params `username_known:bool`; answer `password:string` (not trimmed). Uses Keycloak password credential validation; success advances, missing value rechallenges, wrong password → `invalid_credential`, lock/disable terminal. |
| `native-totp` / **Native: TOTP** / [source](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativeTotpAuthenticator.java) | Identified user with an OTP credential; typically ALTERNATIVE in conditional second factor. No execution config; realm OTP policy controls digits/period/algorithm. Params `digits:int`, `period:int`, `algorithm:string`, `credential_labels:[string]`, `credentials:[{id,label}]`; answer `totp:string`, optional `credential_id:string` (defaults to user's default). Keycloak OTP provider handles validation/reuse; no native enrollment. |
| `native-passkey` / **Native: Passkey** / [source](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativePasskeyAuthenticator.java) | ALTERNATIVE to password, or discoverable before identification. Config `enrol-on-first-login=false`; `true` schedules enabled `native-passkey-register` for a user without a passkey after another factor authenticates. REQUIRED without a passkey still fails. Realm Passwordless WebAuthn policy applies. Params `challenge`, `rp_id`, `timeout?`, `user_verification`, `allow_credentials:[{type,id,transports}]`, `discoverable`. Answer `credential_id`, `client_data_json`, `authenticator_data`, `signature`, optional `user_handle`; all binary values base64url. Discoverable assertion needs a handle identifying the user. Verification delegates to Keycloak/WebAuthn; missing/undecodable fields → `missing_credential`; invalid assertion → `invalid_credential`; handle mismatch with known user is terminal. Each new challenge set replaces the WebAuthn challenge. |
| `native-recovery-code` / **Native: recovery code** / [source](../keycloak-native-auth/native-auth-authenticators/src/main/java/io/phasetwo/keycloak/nativeauth/authenticators/NativeRecoveryCodeAuthenticator.java) | Identified user with unused `recovery-authn-codes`; second-factor ALTERNATIVE. No execution config. Params `remaining:int?`, `warning_threshold:int`; answer `recovery_code:string`. Drops spaces/hyphens and uppercases, then Keycloak validates/consumes. Invalid/reused → `invalid_credential`; last code adds `CONFIGURE_RECOVERY_AUTHN_CODES`, causing browser fallback before code issuance. Generation is browser-only. |
| `native-otp` / **Native: one-time code (email / SMS)** / [source](../keycloak-native-auth/native-auth-otp-sender/src/main/java/io/phasetwo/keycloak/nativeauth/otp/NativeOtpAuthenticator.java) | After identified user and primary factor; REQUIRED for SMS demo, ALTERNATIVE email/TOTP in conditional subflow. Config `channel=email`, `digits=6`, `ttl=300`, `resend-cooldown=30`, `max-attempts=5`. Demo uses cooldown 10 / attempts 3. Params `channel:string`, `destination_masked:string?`, `digits:int`, `ttl:int`, `sent:bool`, optional `resend_allowed_at:number`. Answer `otp:string` or `action=resend`. Salted hashed code in execution auth note; success removes it. Exhaustion/expiry → `expired_code`, explicit resend needed; cooldown → `resend_too_soon`, wrong code counts a login failure. Eligibility currently checks default email sender, even for SMS configuration. |
| `native-push` / **Native: push MFA (approve on device)** / [source](../keycloak-native-auth/native-auth-push/src/main/java/io/phasetwo/keycloak/nativeauth/push/NativePushAuthenticator.java) | After identification, active `push-mfa` credential; second-factor ALTERNATIVE. Config `loginChallengeTtlSeconds=240`, `userVerification=none` (also `number-match` or `pin`), `userVerificationPinLength=4`, `pollIntervalSeconds=3`. Demo explicitly uses TTL 240 / number-match / poll 3. Resend cooldown fixed 10 s. Params `sent`, `devices:[{label}]`, `poll_interval`, optional `cid`, `expires_at`, `status`, `resend_allowed_at`, `user_verification:{type,number|pin}`. Answer `action=resend` or `action=poll`. Pending rechallenges; approved advances/consumes store entry; denied counts a failure, expired allows resend. Device approval uses separate API below. SDK typed/default requester UI supports number match; PIN requester display needs custom UI reading raw params (approving-device UI can collect PIN). |
| `native-pin` / **Native: PIN** / [source](../keycloak-native-auth/native-auth-pin/src/main/java/io/phasetwo/keycloak/nativeauth/pin/NativePinAuthenticator.java) | Optional module `native-auth-pin` with Phase Two's keycloak-pin ([PIN codes](#pin-codes)). Identified user with a PIN (`phasetwo-pin`, or a migratable legacy `pin-code`); usually REQUIRED inside a conditional second factor with `conditional-user-configured`. Config `max-attempts=5` (keycloak-pin's own key; `0` = no PIN limit). Params `length:int` (the stored PIN's length); answer `pin:string`. Verification, the attempt counter and the lock are keycloak-pin's, shared with its browser authenticator. Empty → `missing_credential` (not counted); wrong → `invalid_credential` with `retry.remaining` = PIN attempts left (absent when `max-attempts` is 0), counted as a brute-force failure; the attempt that reaches the limit and every later one → `credential_locked`, `retry.remaining:0`. A PIN that is already locked is announced on the first descriptor. Events: `LOGIN_ERROR` `invalid_user_credentials` with `credential_type=phasetwo-pin` (plus `reason=pin_locked`). No native enrollment from the authenticator (`isUserSetupAllowed` is false like every native factor); use the required action. |

## Required actions and supporting providers

Required actions run **after factors and before authorization-code issuance**, in Keycloak's required-action evaluation order. Register/enable them in Authentication → Required actions, then assign to a user or let a supported built-in action trigger substitution. They are not authentication-flow executions and have no REQUIRED/ALTERNATIVE setting. Each pending action emits one `required=true` descriptor whose ID is the native provider ID; its success removes the pending original alias and continues to the next action or code. [RequiredActionDriver](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/RequiredActionDriver.java) handles dispatch, substitution and timeout state.

| ID / display / source | Configuration, input and result |
| --- | --- |
| `native-passkey-register` / **Native: register passkey** / [source](../keycloak-native-auth/native-auth-required-actions/src/main/java/io/phasetwo/keycloak/nativeauth/requiredactions/NativePasskeyRegisterRequiredAction.java) | Explicit assignment/enrol-on-first-login; does not automatically substitute every WebAuthn browser action. No action-specific config; Passwordless policy supplies creation params: `challenge`, `rp:{id,name}`, `user:{id,name,display_name}`, `pub_key_cred_params:[{type,alg}]`, `authenticator_selection`, `attestation`, `exclude_credentials`, `timeout`. Answer `credential_id`, `client_data_json`, `attestation_object`, optional comma-separated `transports` and `label`. Fresh single-use challenge on retries; missing fields → `missing_credential`, failed verification → `invalid_attestation`. Stores passwordless credential on success. |
| `native-update-password` / **Native: update password** / [source](../keycloak-native-auth/native-auth-required-actions/src/main/java/io/phasetwo/keycloak/nativeauth/requiredactions/NativeUpdatePasswordRequiredAction.java) | Substitutes `UPDATE_PASSWORD`; no action config, realm password policy controls validation. Params `username`, `policy:object` omitting hashing/administrative policy entries. Answer `password`, `password_confirm`. Missing/mismatch/policy rejection → `missing_credential` / `password_mismatch` / `invalid_password`, without brute-force failures. Success changes password; does not sign out other sessions. |
| `native-verify-email` / **Native: verify email (code)** / [source](../keycloak-native-auth/native-auth-required-actions/src/main/java/io/phasetwo/keycloak/nativeauth/requiredactions/NativeVerifyEmailRequiredAction.java) | Substitutes `VERIFY_EMAIL` only if email sender can serve the user. Config `digits=6`, `ttl=300`, `resend-cooldown=30`, `max-attempts=5`. Params `email_masked`, `digits`, `ttl`, `sent`, `resend_allowed_at?`. Sends on first challenge; answer `code` (not `otp`) or `action=resend`. Missing/wrong/expired/cooldown errors follow code semantics; success sets email verified and records event. |
| `native-terms` / **Native: terms and conditions** / [source](../keycloak-native-auth/native-auth-required-actions/src/main/java/io/phasetwo/keycloak/nativeauth/requiredactions/NativeTermsRequiredAction.java) | Substitutes `TERMS_AND_CONDITIONS`. Config `terms-text`, `terms-url`, `terms-version` → corresponding realm attributes; if no text/URL, generic acceptance text. Params `text?`, `url?`, `version?`. Answer `accepted=true` or `false`; invalid input rechallenges, false ends with 403 `access_denied`, true timestamps user attribute `terms_and_conditions`. Version is informational; no versioned acceptance record is implemented. |
| `native-configure-pin` / **Native: configure PIN** / [source](../keycloak-native-auth/native-auth-pin/src/main/java/io/phasetwo/keycloak/nativeauth/pin/NativeConfigurePinRequiredAction.java) | Substitutes keycloak-pin's `phasetwo-configure-pin` (**Configure PIN**); no config of its own, it reads Configure PIN's `length` (4–12, default 4) and `reject-weak` (default `true`). Params `length:int`. Answer `pin`, `pin_confirm`. Empty `pin` → `missing_credential`; then keycloak-pin's checks in order: not exactly `length` ASCII digits → `invalid_format`, repeated digit or simple run → `weak_pin`, confirmation differs → `pin_mismatch`; none is a brute-force failure. Success replaces any earlier PIN (counter and lock cleared), records `UPDATE_CREDENTIAL` with `credential_type=phasetwo-pin`, removes the pending action. |
| `native-push-enroll` / **Native: enrol push MFA device** / [source](../keycloak-native-auth/native-auth-push/src/main/java/io/phasetwo/keycloak/nativeauth/push/NativePushEnrollRequiredAction.java) | Substitutes upstream `push-mfa-register`; no action-specific config. Params `enrollment_token` (realm-signed JWT), `expires_in`, `device_api_base`, `user_id`. Answer `token=<device-signed JWT>`; `action=check` supports enrollment completed via device API. Bound native session requires matching device key. Missing/invalid/expired → descriptor error; a pending enrollment challenge is reused until expired, then replaced. Always use newly returned params. Success creates `push-mfa` credential. |

Native-only actions used outside a native session warn/ignore for that login rather than rendering equivalent browser pages; keep built-in action aliases for shared browser requirements.

Supporting providers:

- `native-otp-sender` SPI: [email](../keycloak-native-auth/native-auth-otp-sender/src/main/java/io/phasetwo/keycloak/nativeauth/otp/EmailOtpSender.java) uses realm SMTP and theme resources `native-otp.ftl`/`nativeOtp*`; [sms-webhook](../keycloak-native-auth/native-auth-otp-sender/src/main/java/io/phasetwo/keycloak/nativeauth/otp/SmsWebhookOtpSender.java) requires `--spi-native-otp-sender--sms-webhook--url`, optional `--spi-native-otp-sender--sms-webhook--token`, and `--spi-native-otp-sender--sms-webhook--phone-attribute` (default `phoneNumber`). It POSTs `{"to":"<number>","message":"<message>"}` with optional bearer authentication. No SMS vendor integration is otherwise supplied. User profile must allow the phone attribute.
- `native-auth-push-enrolment` SPI: [bridge](../keycloak-native-auth/native-auth-push/src/main/java/io/phasetwo/keycloak/nativeauth/push/NativePushEnrolmentProviderImpl.java) provides metadata and enrollment behind the endpoint. Upstream [Java 21 rebuild](../keycloak-native-auth/push-mfa-extension-java21/pom.xml) supplies credential, browser authenticator `push-mfa-authenticator`, browser required action `push-mfa-register`, and device API. It recompiles 2.3.7 sources because the published binaries target Java 25.
- `apns` sender: [factory](../keycloak-native-auth/native-auth-push-apns/src/main/java/io/phasetwo/keycloak/nativeauth/apns/ApnsPushNotificationSenderFactory.java) implements upstream `push-notification-sender`; configuration keys `team-id`, `key-id`, `key` (PEM) or `key-file`, required matching `topic` (default empty), `environment` (`sandbox` default; `production` selects production URL), optional `url` override and `expiration-seconds=240`, under `--spi-push-notification-sender--apns--…`. Team/key identifiers and private key are required for delivery; otherwise sender is installed but skips notification sending. Compose maps `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_KEY`, `APNS_TOPIC` (default `io.phasetwo.keycloak.nativedemo`), `APNS_ENVIRONMENT`. `none` supports polling without notification delivery.
- `fcm` sender (ba-itsys, for Android): set `--spi-push-notification-sender--fcm--google-fcm-url=https://fcm.googleapis.com/v1/projects/<project id>/messages:send` and the environment variable `GOOGLE_APPLICATION_CREDENTIALS` to the path of the Firebase project's service-account key file inside the container. For each push it exchanges a JWT signed with that key for an access token at the file's `token_uri`, then sends an HTTP v1 message with a `notification` (title and body from the login theme messages `push-mfa-notification-title` / `push-mfa-notification-body`) and `data.token` = the confirm token. A backgrounded Android app receives `data` only when the user taps the notification, so the app also reads `/push-mfa/login/pending` when it opens (spec/03 §7). The sender honors `https_proxy` / `no_proxy`. FCM itself is free; it needs a Firebase project with the Android app registered.

## PIN codes

A PIN is a short numeric secret used as a second factor or as the factor of a step-up (spec/20). The credential, its hashing (Keycloak's `argon2` provider), the attempt counter, the lock, the browser authenticator, the set-PIN required action and the reset authenticator come from Phase Two's [keycloak-pin](https://github.com/p2-inc/keycloak-pin); `native-auth-pin` adds the native authenticator and required action on top of its API, so browser and native logins share one credential, one counter and one lock.

**Install.** Both jars (`keycloak-pin.jar`, `native-auth-pin.jar`) are in the providers zip; nothing changes for a realm until a flow uses them. `pin` and `pin_setup` appear in the metadata's `challenge_types_supported` once they are installed.

**Flow layout.** Put the PIN after the step that identifies the user, in a conditional sub-flow so users without a PIN skip it:

```text
native-pin                                  (the demo's flow, client demo-native-pin)
  R native-username
  R native-password
  C [second factor]
    R conditional-user-configured
    R native-pin                            config: max-attempts
```

`native-pin` can also be an ALTERNATIVE next to `native-totp` and other factors, or the factor of a step-up level. Enable the required actions **Configure PIN** (`phasetwo-configure-pin`) and **Native: configure PIN** (`native-configure-pin`); the native one serves Configure PIN in-band whenever it is pending on the user, and the browser keeps keycloak-pin's own page.

**Configuration.** Execution config of `native-pin`: `max-attempts` (default 5, `0` = no PIN-specific limit). Configure PIN's required-action config: `length` (4–12, default 4; existing PINs keep the length they were set with, which is what `pin` reports) and `reject-weak` (default `true`). There are no `Config.Scope` settings.

**Lockout.** Every wrong PIN increments the counter on the credential and is also a normal brute-force failure; a correct PIN resets the counter. When it reaches `max-attempts` the PIN is locked: every later attempt fails without checking the PIN (`credential_locked`), in the browser and natively. A lock is never lifted by time. Keep `max-attempts` below the realm's brute-force `failureFactor`, or the account locks before the PIN does (the demo uses 3 against 5).

**Reset paths.** An administrator deletes the PIN on the user's *Credentials* tab (with the conditional sub-flow the user then signs in without one), adds **Configure PIN** to the user's required actions, or sends an *execute actions* email with Configure PIN; a native login then asks for `pin_setup`. The user can reset it on the web through the realm's reset credentials flow with keycloak-pin's **Reset PIN** (`phasetwo-pin-reset`) after *Send Reset Email*, which removes the PIN and schedules Configure PIN. A new PIN starts unlocked.

**Account console.** The PIN is listed on *Signing in* as a two-factor credential when an enabled flow contains an authenticator whose reference category is `phasetwo-pin`; `native-pin` qualifies, so a realm that uses only native PIN logins still shows it. Set-up and update there run Configure PIN in the browser (enable it).

Evidence: [PinIT](../keycloak-native-auth/demo/src/test/java/io/phasetwo/keycloak/nativeauth/demo/PinIT.java); examples in [flow examples](flow-examples.md#pin-codes).

## Authenticated enrollment and push device API

[PasskeyRegistrationDriver](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/PasskeyRegistrationDriver.java) validates access token/user/session, optional native-client restriction and authentication freshness for both registration endpoints and push enrollment start. A refresh does not reset `AUTH_TIME`. Stale authentication gives 403 `insufficient_authorization` with `auth_session` and integer `max_age`, **without a challenge array**; start a step-up and retry. Missing/invalid/expired tokens → 401 `invalid_token` plus `WWW-Authenticate: Bearer …`.

Passkey options are creation params at the response top level, plus opaque `registration_id`. Finish JSON contains that ID, `credential_id`, `client_data_json`, `attestation_object`, optional `transports` (array or comma-separated string) and `label`. The registration ID is bound to the user, expires after user-action timeout and is atomically removed before attestation verification; after a failed finish obtain new options. Success returns 201 `{"credential_id":"<credential>","label":"iPhone"}`; malformed, expired/reused or invalid attestation → 400 `invalid_request`.

Push device paths use `/push-mfa` at the same issuer. With the supplied native bridge, use `Authorization: DPoP <native-access-token>` and a `DPoP` proof including `ath`; SDK adds `sub` and `deviceId` for enrolled-device requests. The device signing key is the SDK DPoP key. No `client_credentials` secret/provider ships.

| Method/path under `/push-mfa` | Request / result |
| --- | --- |
| `POST /enroll/complete` | JSON `{"token":"<device-JWT>"}` → 200/201 enrollment result. JWT includes `sub`, `enrollmentId`, `nonce`, `exp`, `cnf.jwk`, random `credentialId`, stable `deviceId`, `deviceType:"ios"`, `deviceLabel`, `pushProviderType`, optional `pushProviderId` (APNs token). |
| `GET /login/pending?userId=<sub>` | 200 `{"challenges":[…]}` with `cid`, user/client context, expiry, optional number-match choices or PIN requirement |
| `POST /login/challenges/{cid}/respond` | JSON `{"token":"<device-JWT>"}`; signed claims `cid`, `credId`, `deviceId`, `action:approve|deny`, optional `userVerification`, `exp` → 200 `{"status":"approved"}` or denied; 403 verification mismatch / 409 already resolved |
| `PUT /device/push-provider` | JSON `{"pushProviderType":"apns","pushProviderId":"<hex-token>"}` → 200 |
| `PUT /device/rotate-key` | JSON `{"publicKeyJwk":{…}}`, authenticated by current key → 200; SDK then commits new key and clears old bound credentials |
| `POST /login/lockout` | No body → 200; disables the user until an administrator re-enables it |

The native login client only sends/resends/polls; the approving device fetches trusted context and submits its signed decision. A notification is a hint to fetch pending state, not an approval. See [push examples](flow-examples.md#push-enrollment-and-approval) and [Swift implementation](../ios/KeycloakNative/Sources/KeycloakNativePush/Push.swift).

## Browser handoff and extending the system

For an unsupported pending required action, [RedirectToWebBuilder](../keycloak-native-auth/native-auth-endpoint/src/main/java/io/phasetwo/keycloak/nativeauth/endpoint/RedirectToWebBuilder.java) stores a PAR using the original PKCE, scope, nonce, ACR and locale, server-generated `state` and identified user's login hint. HTTP 403 contains `error:"redirect_to_web"`, opaque `request_uri`, `redirect_uri`, `state`, `expires_in` and informational `reason:"required_action:<alias>"`. Requires PAR feature, initial PKCE and usable registered callback. Otherwise 403 `access_denied`. Native session is removed in either case.

Browser opens normal authorization endpoint with `client_id` and `request_uri`; user authenticates again (subject to browser SSO), completes the browser action, returns `code`/`state` to callback. SDK checks returned state then exchanges with the **original** verifier and explicit callback URI. Browser-fallback credentials have no native post-login session; normal stored-session step-up is unavailable unless another native login supplies one. This path uses `ASWebAuthenticationSession`, not a webview.

To add a server authenticator, implement [NativeAuthenticator](../keycloak-native-auth/native-auth-core/src/main/java/io/phasetwo/keycloak/nativeauth/core/spi/NativeAuthenticator.java) / [NativeAuthenticatorFactory](../keycloak-native-auth/native-auth-core/src/main/java/io/phasetwo/keycloak/nativeauth/core/spi/NativeAuthenticatorFactory.java), normally extend `NativeAuthenticatorBase`, provide `describe`, `action`, eligibility and optional `prepare`, register the factory in `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`, and add it to a flow. The server's `ChallengeType` enum is closed: adding a new wire type also requires updating it and its parsing/model tests; a factory alone cannot define arbitrary strings. Required actions similarly implement the native interfaces and optional `substitutesFor`/`canServe`, with service registration and realm enabling.

On iOS, add `ChallengeType` parsing/support, typed params and a `ChallengeAnswer` case/form encoding, tests/transcripts and a UI presenter. Unknown types decode as `.unknown(String)` and remain visible in the set. Core does not throw just for receiving them; default UI picks supported alternatives or displays unsupported-method guidance. A presenter override alone cannot submit a new type through the closed answer enum. `select` parses but is unsupported and never emitted by current providers. Browser fallback is not automatically created by the SDK for unknown types.
