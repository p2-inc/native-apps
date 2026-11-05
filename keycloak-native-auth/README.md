# keycloak-native-auth

Browserless native authentication for Keycloak: a FiPA-style *authorization challenge endpoint*
(`POST /realms/{realm}/native-auth/challenge`) that drives a dedicated Keycloak authentication flow
and returns JSON challenges instead of HTML forms, plus native-aware authenticators. The wire
protocol is `../spec/03-protocol-spec.md`; design and plan are in `../spec/`.

**Status: Phase 2b** — username + password + TOTP + **passkeys** (allow-list and discoverable
login, registration mid-flow through a native required action and after login through
bearer-authenticated endpoints), **email / SMS one-time codes**, **step-up / re-authentication**
with the post-login `auth_session`, **native required actions** for update-password / verify-email /
terms (serving Keycloak's own `UPDATE_PASSWORD`, `VERIFY_EMAIL`, `TERMS_AND_CONDITIONS` in-band),
**redirect-to-web** for required actions the native flow cannot serve, and **DPoP binding** of
`auth_session` and code at the challenge endpoint. Push MFA is Phase 3.
Decisions are recorded in `../spec/09-phase0-decisions.md` (Phase 0), `../spec/11-phase1-decisions.md`
(Phase 1a), `../spec/12-phase1b-decisions.md` (iOS SDK), `../spec/13-phase2-decisions.md` (Phase 2) and
`../spec/14-phase2b-3-decisions.md` (Phase 2b / 3).

## Modules

| Module | Deployed to Keycloak | Contents |
|--------|----------------------|----------|
| `native-auth-core` | yes | Protocol model (snake_case JSON), `AuthSessionCodec` (JWE), `NativeAuthenticator` and `NativeRequiredAction` SPIs, `NativeRequestContext` |
| `native-auth-authenticators` | yes | `native-username` (with the phantom password challenge for unknown users), `native-password`, `native-totp`, `native-passkey`, `native-recovery-code` |
| `native-auth-otp-sender` | yes | `native-otp` authenticator (spec/03 §4.6), the `native-otp-sender` SPI with the `email` (realm SMTP, theme template `native-otp.ftl` + `nativeOtp*` messages shipped as theme resources) and `sms-webhook` senders, `OtpCodes` (shared with `native-verify-email`) |
| `native-auth-required-actions` | yes | `native-passkey-register`, `native-update-password`, `native-verify-email`, `native-terms` (spec/03 §4.11–§4.14) plus the passkey registration helpers (`PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier`) |
| `native-auth-endpoint` | yes | `RealmResourceProvider` id `native-auth`: `GET /metadata`, `POST /challenge`, `POST /passkey/register/options|finish`, `POST /push/enroll/start`; `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver`, `DPoPProofChecker`, `RedirectToWebBuilder` |
| `push-mfa-extension-java21` | yes | ba-itsys [`keycloak-push-mfa-extension`](https://github.com/ba-itsys/keycloak-push-mfa-extension) (`push-mfa.version` in `pom.xml`) recompiled for Java 21 from its published sources jar: the published jars target Java 25 and the Keycloak 26.8.1 image runs Java 21 (spec/14 D9). Credential type `push-mfa`, `push-mfa-authenticator` (browser), `push-mfa-register`, the device API `/realms/{realm}/push-mfa/*` |
| `native-auth-push` | yes | `native-push` authenticator (spec/03 §4.7), `native-push-enroll` required action (§4.15, substitutes for `push-mfa-register`), `PushEnrolment` (programmatic enrolment start/complete) and the `native-auth-push-enrolment` SPI behind `/push/enroll/start` and the metadata `push` block (spec/14 D9) |
| `native-auth-push-apns` | yes | `apns` push notification sender for ba-itsys' `push-notification-sender` SPI: HTTP/2, token-based provider auth, no third-party client (spec/14 D10) |
| `demo` | no | `docker-compose.yml` (Keycloak, Postgres, mailpit, a Node resource server for the step-up demo), `realm-export/demo-realm.json`, `scripts/walkthrough.sh`, `scripts/passkey-walkthrough.md`, Testcontainers integration tests |

Builds against **Keycloak 26.8.1** (`keycloak.version` in `pom.xml`) with Java 21; the same JARs run on **Keycloak 26.4, 26.6 and 26.8** (see [Keycloak versions](#keycloak-versions)).

### Keycloak versions

| Keycloak | Status | How it is verified |
|---|---|---|
| 26.8.x | supported, build target | `mvn verify` (default image `26.8.1`), CI |
| 26.6.x | supported | CI runs the full IT suite against a stock `26.6.4` container |
| 26.4.x | supported | CI runs the full IT suite against a stock `26.4.5` container |

The extensions compile against the newest version only. The Keycloak APIs that differ between these versions (`OAuth2Code`'s constructor, the PAR single-use key and `PAR_CLIENT_ID`, `WebAuthnPolicy.getResidentKey`, `KeycloakTrustAnchorRepository`, `AuthenticatorUtils.isUsernameTooLong`, the `kid` overload of `TokenUtil.jweDirectEncode`) are resolved once at runtime in `KeycloakCompat` (core), `ServicesCompat` (endpoint) and `WebAuthnCompat` (required actions); no other class may call them directly (spec/16). Run the ITs against another version with `mvn verify -Dkeycloak.image=quay.io/keycloak/keycloak:<version>`.

Version notes:

- **Attestation trust anchors.** With a server truststore, registration verifies attestation chains against it: through `KeycloakTrustAnchorRepository` on 26.8, through webauthn4j's `KeyStoreTrustAnchorRepository` over the same truststore before (what Keycloak's own `WebAuthnRegisterFactory` does there). Without a truststore every version uses `NullCertPathTrustworthinessVerifier`, which is only safe with the demo's `attestation: none`.
- **Realm exports.** `webAuthnPolicyPasswordlessResidentKey` is 26.8-only and the 26.4/26.6 importers reject it; the demo export carries it next to `webAuthnPolicyPasswordlessRequireResidentKey: Yes`, which older versions read instead. The ITs strip it for older images; remove it by hand to import the demo realm into 26.4/26.6 (`docker compose` pins 26.8.1).
- **Push MFA.** The ba-itsys rebuild (`push-mfa-extension-java21`) passes `PushMfaIT` on all three versions.

## Build and test

```bash
mvn verify                 # unit tests + integration tests (needs Docker; pulls quay.io/keycloak/keycloak:26.8.1)
mvn verify -DskipITs       # unit tests only
```

The integration tests also record every exchange with the native-auth and token endpoints as JSON
transcripts under `demo/target/transcripts/` (`TranscriptRecorder`: secrets in form fields masked,
bodies verbatim); `demo/scripts/update-transcripts.sh` copies them to the committed fixture set
`demo/transcripts/`, which the iOS SDK's unit tests replay (`../ios/KeycloakNative`).

The integration tests (`demo/src/test/java/.../NativeAuthIT.java`, `PasskeyIT.java`, `StepUpIT.java`,
`OtpIT.java`, `SmsOtpIT.java`, `RedirectToWebIT.java`, `DPoPBindingIT.java`, `RequiredActionsIT.java`,
`RecoveryCodeIT.java`, `EnrolOnFirstLoginIT.java`, `PushMfaIT.java`) start Keycloak (plus a mailpit SMTP sink, an in-JVM SMS webhook sink and an in-JVM fake APNs)
with the freshly built provider JARs and the demo realm, and exercise the happy path, re-challenge on
wrong password / wrong TOTP / wrong passkey signature, invalid / cancelled / expired `auth_session`,
unknown `challenge_id`, the `redirect_uri` modes, the multi-alternative challenge set, passkey
registration (authenticated endpoints and the `native-passkey-register` required action), allow-list
and discoverable passkey login, step-up with LoA conditions, `max_age` re-authentication, email OTP
with resend / cooldown / exhaustion, the browser fallback driven through Keycloak's HTML forms,
DPoP-bound sessions and codes, and the native required actions (update password with a policy
violation, verify email with a mailed code, terms accepted / declined, the fallback to
`redirect_to_web` when the native variant is disabled), and push MFA (in-app enrolment through
`/push/enroll/start` + ba-itsys' device API, a browser login approved on the device, the native `push`
challenge with number match, deny / resend rate limit, APNs token update, key rotation, lockout, the
`native-push-enroll` required action). `PasskeyIT` uses a software WebAuthn authenticator
(`SoftwareAuthenticator`, ES256, `none` attestation) and `DPoPBindingIT` a test-side proof signer
(`DPoPProofs`), so no device is needed.

## Run the demo and the curl walkthrough

```bash
mvn -DskipTests -DskipITs package          # builds demo/target/providers/*.jar
cd demo
docker compose up --wait                   # Keycloak 26.8.1 + Postgres + mailpit (http://localhost:8025) + resource server (:8091)
./scripts/walkthrough.sh                   # username -> password -> totp -> code -> tokens, exit 0 on success
docker compose down -v
```

The step-up demo API (`demo/resource-server/server.mjs`, Node 22, no dependencies) validates the
realm's tokens through JWKS (Bearer or DPoP-bound with a proof) and answers `GET /transfer` with
`401 insufficient_user_authentication, acr_values="2"` (RFC 9470) below acr 2; `GET /me` echoes the
claims. Behind a tunnel set `RS_EXTRA_ISSUERS=",https://<tunnel-host>/realms/demo"`.

The passkey sequence (registration after login, then passkey login) cannot be driven with curl alone
because an assertion needs a WebAuthn signer; `scripts/passkey-walkthrough.md` lists the requests and
points at the Java simulator the integration tests use.

If host port 8080 is taken: `KC_PORT=8089 docker compose up --wait` and
`KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh`. The script needs `curl`, `jq` and
`openssl`; it computes alice's TOTP locally from the secret seeded in the realm export.

Demo realm contents:

- Flow `native`: `native-username` (REQUIRED) → subflow *primary factor* (REQUIRED: `native-passkey`
  ALTERNATIVE, `native-password` ALTERNATIVE) → subflow *second factor* (CONDITIONAL: *Condition - user
  configured* + `native-totp` ALTERNATIVE + `native-recovery-code` ALTERNATIVE). Selected through the realm attribute
  `native-auth.flow-alias=native`. The passkey alternative is offered to a user only once they have
  one; the challenge set is ordered like the flow (passkey first).
- Flow `native-alternatives` (spec/08 Q2 prototype): password and TOTP as ALTERNATIVE siblings;
  bound to client `demo-ios-alt` via the client attribute `native-auth.flow-alias`.
- Flow `native-passkey-first` (client `demo-ios-passkey`): a REQUIRED subflow with `native-passkey`
  ALTERNATIVE (discoverable: no username yet) and a `native-username → native-password` subflow
  ALTERNATIVE, then the conditional second factor. The first challenge set is `[passkey, username]`.
- Flow `native-step-up` (client `demo-ios-stepup`, spec/03 §5): `native-username` → CONDITIONAL
  *level 1* (`conditional-level-of-authentication` level 1 / max age 36000 s, then passkey or
  password) → CONDITIONAL *level 2* (level 2 / max age 0, `conditional-user-configured`,
  `native-totp`). A plain login yields `acr=1`; `acr_values=2` (fresh login or step-up) adds the
  TOTP; a step-up re-asks only what the requested level needs.
- Flow `native-otp` (client `demo-ios-otp`, spec/03 §4.6): `native-username` → `native-password` →
  CONDITIONAL second factor with `native-totp` and `native-otp` (email) as ALTERNATIVEs. The code is
  only sent when `otp` is the single option or the client asks for it (`action=resend`); config alias
  `native-otp - email`: 6 digits, 300 s, 10 s resend cooldown, 3 attempts. Emails land in mailpit
  (template `native-otp.ftl`, subject `nativeOtpSubject`; override both in the realm's email theme).
- Flow `native-sms` (client `demo-ios-sms`): `native-username` → `native-password` → `native-otp`
  REQUIRED with config `native-otp - sms` (channel `sms-webhook`). The sender needs
  `--spi-native-otp-sender--sms-webhook--url` (and optionally `--token`); the integration test
  `SmsOtpIT` points it at an in-JVM sink through `host.testcontainers.internal`, the compose stack
  does not configure it (set `KC_SPI_NATIVE_OTP_SENDER__SMS_WEBHOOK__URL` on the `keycloak` service
  to try it). bob carries the `phoneNumber` attribute the sender reads (the realm's user profile
  must allow unmanaged attributes, which the IT switches on).
- Push MFA (spec/14 D9): the `native` flow's second factor also offers `native-push` (ALTERNATIVE,
  config `native-push - number match`: 240 s, number match, 3 s poll interval) to users with a
  `push-mfa` credential. The realm's **browser flow** is `browser-push` (cookie → username/password
  → CONDITIONAL `push-mfa-authenticator`, ba-itsys' web wait page; scenario A), so a browser login
  of an enrolled user asks the phone. Required actions `push-mfa-register` (ba-itsys) and
  `native-push-enroll` (its native substitute) are enabled. The `apns` sender is installed but idle
  until `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_KEY` (PEM), `APNS_TOPIC` and `APNS_ENVIRONMENT` are set
  in the compose environment; devices enrolled with `pushProviderType` `none` work without Apple (the
  app pulls pending approvals from `/push-mfa/login/pending`).
- WebAuthn **Passwordless** policy: RP ID `localhost`, ES256/RS256, user verification `required`,
  resident key `required`, attestation `none`, no extra origins. Required actions
  `native-passkey-register`, `native-update-password`, `native-verify-email` and `native-terms` are
  registered and enabled, and Keycloak's `TERMS_AND_CONDITIONS` is enabled (the export lists
  Keycloak's default required actions too, because Keycloak seeds them only into an empty list).
  Realm attributes `native-auth.terms-text|url|version` feed the `terms` challenge (a realm export
  cannot carry required-action config).
- Client `demo-ios`: public, PKCE S256 required, attribute `native-auth.enabled=true`,
  standard flow enabled (needed for the code exchange), redirect URI `demoapp://auth/callback`
  reserved for the later `redirect_to_web` fallback.
- Users: `alice` / `alice-password` with TOTP (secret `alice-totp-secret-20261014`, label *Phone*),
  `bob` / `bob-password` (password only, so the conditional second factor is skipped),
  `carol` / `carol-password` with a pending *Update Password* required action (served in-band by
  `native-update-password`, spec/03 §4.12), `frank` / `frank-password` with *Update Profile* pending
  (no native variant: `redirect_to_web`), `grace` / `grace-password` with *Verify Email* pending
  (served by `native-verify-email`: a code lands in mailpit), `hank` / `hank-password` with *Terms and
  Conditions* pending (served by `native-terms`), `dave` / `dave-password` with the
  pending `native-passkey-register` action (a passkey is enrolled in-band on the first native login),
  `erin` / `erin-password` reserved for the brute-force demo (spec/06 S14): `failureFactor` is 5 in
  the demo realm, so five wrong passwords (or two within a second) lock the account for a minute and
  the flow ends with `403 access_denied`; `ivy` / `ivy-password` with TOTP (secret
  `ivy-totp-secret-20261015`) and three recovery codes `IVY1-IVY1-IVY1`, `IVY2-IVY2-IVY2`,
  `IVY3-IVY3-IVY3` (seeded hashed; single use, consumed in order; after the last one Keycloak
  requires new codes, which the native flow hands to the browser); `judy` / `judy-password` with
  ba-itsys' `push-mfa-register` pending (served in-band by `native-push-enroll`, spec/03 §4.15: the
  first native login enrols the phone as a push device). No passkey is pre-registered in
  the export; the integration tests register them. frank's native login ends with `403
  redirect_to_web` (a PAR `request_uri` for the browser, spec/03 §3.4). An unknown username gets a
  phantom `password` challenge that fails like a real user's wrong password and locks after
  `failureFactor` attempts (spec/03 §4.1).
- `smtpServer` points at the compose/Testcontainers `mailpit` host (`noreply@demo.local`).
- `otpPolicyCodeReusable=true` so the walkthrough and tests can log in repeatedly within one
  30 s TOTP window. Keep the Keycloak default (`false`) in real deployments.

## Configuration reference

| Where | Attribute | Values | Default |
|-------|-----------|--------|---------|
| client | `native-auth.enabled` | `true` to allow the client on the challenge endpoint (client must be public, standard flow enabled) | unset = denied |
| client | `native-auth.flow-alias` | per-client override of the native flow | realm value |
| realm | `native-auth.flow-alias` | alias of the top-level flow to run | `native` |
| realm | `native-auth.code-redirect-uri-mode` | `none` (code stored without redirect_uri; token request must omit it), `sentinel` (`urn:keycloak:native-auth` stored and required), `client-fixed` (value of `native-auth.code-redirect-uri` or the client's first redirect URI) | `none` |
| realm / client | `native-auth.code-redirect-uri` | value for `client-fixed` | – |
| realm | `native-auth.passkey-registration-max-age` | seconds since the user authenticated (user session `AUTH_TIME`) within which `/passkey/register/*` accept the token; `0` disables. A stale token is refused with `403 insufficient_authorization` + `auth_session` + `max_age` so the client can step up | `300` |
| client | `native-auth.web-fallback-redirect-uri` | `redirect_uri` used for `redirect_to_web` (spec/03 §3.4); must be a registered redirect URI | first registered redirect URI without `*` |
| client / realm | `acr.loa.map`, `default.acr.values`, `minimum.acr.value` | Keycloak's own ACR-to-LoA settings; `acr_values` on the challenge endpoint is mapped exactly like on the authorization endpoint | numeric `acr_values` taken literally |
| authenticator `native-otp` | `channel`, `digits`, `ttl`, `resend-cooldown`, `max-attempts` | sender id (`email`, `sms-webhook`), code length, lifetime (s), seconds between sends, wrong codes before the code is invalidated | `email`, 6, 300, 30, 5 |
| SPI `native-otp-sender` / `sms-webhook` | `--spi-native-otp-sender--sms-webhook--url`, `--token`, `--phone-attribute` | webhook that receives `{"to","message"}` (optional bearer token), user attribute holding the number | –, –, `phoneNumber` |
| realm | WebAuthn Passwordless policy (`webAuthnPolicyPasswordless*`) | RP ID, algorithms, user verification, resident key, attestation, extra origins, create timeout: drives both the `passkey` and `passkey_registration` descriptors. Android apps need their `android:apk-key-hash:<…>` origin in the extra origins, one per signing key (spec/03 §4.3). A realm update applies this policy only when it includes `webAuthnPolicyPasswordlessRpEntityName`, and then replaces the whole policy: send every `webAuthnPolicyPasswordless*` field, or the update returns `204` and changes nothing | Keycloak defaults |
| authenticator `native-username` | `reveal-user-not-found` | `true` → error code `invalid_user` at the username step, otherwise the phantom password challenge (spec/03 §4.1) | `false` |
| authenticator `native-passkey` | `enrol-on-first-login` | `true` → a native login of a user without a passkey continues with the other alternative and then asks for `passkey_registration` in-band (`native-passkey-register` must be enabled; ALTERNATIVE executions only) | `false` |
| authenticator `native-passkey` | `enrol-optional` | with `enrol-on-first-login`: the `passkey_registration` descriptor carries `skippable: true` and the user may decline it for this login with `action=skip` ("Not now"); the next login offers it again (spec/03 §4.11) | `false` |
| realm | `native-auth.non-native-execution` | `error` → a flow execution that renders a page (a browser form authenticator) ends the request with `500 server_error`; `redirect_to_web` → `403 redirect_to_web` with `reason: execution:<provider id>` (spec/03 §3.4; needs PKCE and a redirect URI, else `access_denied`) | `error` |
| realm | `native-auth.passkey-registration-native-clients-only` | `true` → `/passkey/register/*` answer `403 access_denied` for tokens issued to clients without `native-auth.enabled` | `false` |
| required action `native-verify-email` (config) | `digits`, `ttl`, `resend-cooldown`, `max-attempts` | code length, lifetime (s), seconds between sends, wrong codes before the code is invalidated; delivery uses the `email` native-otp-sender | 6, 300, 30, 5 |
| required action `native-terms` (config) / realm | `terms-text`, `terms-url`, `terms-version` / `native-auth.terms-text`, `native-auth.terms-url`, `native-auth.terms-version` | what the `terms` challenge shows; the realm attributes are the fallback (importable) | a generic sentence |
| authenticator `native-push` | `loginChallengeTtlSeconds`, `userVerification`, `userVerificationPinLength`, `pollIntervalSeconds` | same keys as ba-itsys' `push-mfa-authenticator` (`none`, `number-match`, `pin`), plus the `poll_interval` the client is told (spec/03 §4.7) | 120, `none`, 2, 3 |
| required action `push-mfa-register` (config, ba-itsys) | `enrollmentChallengeTtlSeconds` | also the lifetime of `/push/enroll/start` tokens and of `native-push-enroll` challenges (spec/03 §4.15) | 300 |
| SPI `push-notification-sender` / `apns` | `--spi-push-notification-sender--apns--team-id`, `--key-id`, `--key` or `--key-file`, `--topic`, `--environment`, `--url`, `--expiration-seconds` | Apple team, the `.p8` key id and PEM (or its path), the app's bundle id, `sandbox`/`production`, an override URL (tests), the notification's lifetime. Unset team/key = installed but inactive (spec/14 D10) | –, –, –, –, `sandbox`, by environment, 240 |
| SPI `push-notification-sender` / `fcm` (ba-itsys) | `--spi-push-notification-sender--fcm--google-fcm-url`, and the environment variable `GOOGLE_APPLICATION_CREDENTIALS` | the HTTP v1 send URL `https://fcm.googleapis.com/v1/projects/<project id>/messages:send`, and the path of the Firebase project's service-account key file (JSON; its `token_uri` is where the sender gets its access token). Either unset = installed, but sends fail and are logged (`Missing FCM URL attribute` / `Failed to load FCM credentials`). Notification text: login theme messages `push-mfa-notification-title` / `push-mfa-notification-body` in the user's locale (spec/03 §7, `FcmPushIT`) | –, –; text `Push MFA` / `Please confirm your login` |
| SPI `push-mfa` (ba-itsys) | `--spi-push-mfa--*`, e.g. `--dpop-require-for-enrollment` | see the ba-itsys README; the device API accepts `Authorization: DPoP <native access token>` whose `cnf.jkt` is the enrolled key (spec/03 §7.1, spec/14 D9) | ba-itsys defaults |

`GET /realms/{realm}/native-auth/metadata` advertises the effective `redirect_uri` requirement under
`code_exchange`, the passkey RP ID and registration endpoints under `passkey`, the installed
`challenge_types_supported` (native authenticators and native required actions), the `push` block
(`enroll_start_endpoint`, `device_api_base`, `device_token: "native"`, `push_provider_types`) when
`native-auth-push` is installed, the realm's
`authorization_endpoint` (for `redirect_to_web`) and `dpop_signing_alg_values_supported` (the proof
algorithms the challenge endpoint verifies).

### Step-up, redirect-to-web and DPoP (Phase 2, spec/13)

- **Step-up** (spec/03 §5): a §2.1 request plus the post-login `auth_session` from a success body
  re-enters the native flow inside the existing user session: the username step is skipped, the
  levels already authenticated are carried over from the user session (`loa-map`), `acr_values` is
  mapped to `requested-level-of-authentication`, and `max_age` / `prompt=login` force a full
  re-authentication. The code is issued for the same user session; `acr` and `auth_time` follow
  Keycloak's step-up semantics. A flow without `conditional-level-of-authentication` executions
  simply runs every factor again.
- **Redirect to web** (spec/03 §3.4): a pending non-native required action (update password, verify
  email, terms, …) answers `403 redirect_to_web` with a PAR `request_uri` (stored exactly as
  Keycloak's PAR endpoint stores one: the native flow's PKCE challenge, scope, `login_hint`, a server
  `state`, the client's fallback `redirect_uri`). The app opens
  `authorization_endpoint?client_id=…&request_uri=…` in the system browser, the user completes the
  browser flow, and the code returned to `redirect_uri` is exchanged with the native verifier plus
  that `redirect_uri`. Requires PKCE on the native request and a registered redirect URI (else
  `access_denied` as before). The `PAR` feature must be enabled (default).
- **DPoP** (spec/03 §8): a `DPoP` header on a challenge request is verified with Keycloak's
  validator; an invalid one is `400 invalid_dpop_proof`. A proof on the first request binds the
  in-flow `auth_session`, the authorization code (`dpop_jkt`, so the token endpoint requires the
  same key) and the post-login `auth_session` (so a step-up requires the same key) to the key's
  thumbprint; a session started without a proof stays unbound.

### Passkey notes

- **Origin.** Keycloak checks `client_data_json.origin` against the request's base origin
  (`http(s)://host[:port]`) and the Passwordless policy's *extra origins*. iOS signs
  `https://<rp_id>`; if that is not Keycloak's public base URI (port, proxy host), add it to the
  policy's extra origins.
- **RP ID.** `passkey.rp_id` in metadata is the policy's RP ID (fallback: the base URI host). The app
  needs an Associated Domains `webcredentials:<rp_id>` entry.
- **Password managers.** The same association (iOS `webcredentials:`, Android `assetlinks.json` with
  `get_login_creds`) is what lets iCloud Keychain, Google Password Manager and third-party managers
  offer and save the site's passwords in the app. Serve both files even for password-only logins.
- **Required action continuation.** The `passkey_registration` descriptor's `id` is the required
  action's provider id (`native-passkey-register`); answer with `challenge_type=passkey_registration`
  and that `challenge_id`. While it is pending the `auth_session` is bound to the realm's
  *user action* timeout rather than the login timeout.
- **Registration after login.** `POST /passkey/register/options` with a Bearer (or DPoP) access
  token, then `POST /passkey/register/finish` with a JSON body; a `403 insufficient_authorization`
  means the authentication is older than `native-auth.passkey-registration-max-age` and the user has
  to log in again (step-up arrives in Phase 2).

## Flow configuration rules

- Only native-aware authenticators (and condition authenticators) may be used in the native flow.
  If a form-based execution produces a page, the endpoint answers `500 server_error` and logs the
  offending execution id and provider id (spec/08 R8); with the realm attribute
  `native-auth.non-native-execution=redirect_to_web` it hands the login to the browser instead.
- A native required action may let the user decline it for the current login (`skippable: true`,
  `action=skip`): only when it was scheduled for the login rather than stored on the user, and only
  when the action allows it (`NativeRequiredAction.isSkippable` / `processSkip`; today
  `native-passkey-register` with `enrol-optional`).
- Initial-request `x_*` extension parameters (spec/03 §2.3) are available to every authenticator
  and required action of the login through `NativeRequestContext.extensionParameter(authSession,
  name)`; continuation values are plain form parameters of their request.
- Custom provider ids must be at most 36 characters: Keycloak stores them in `varchar(36)` columns
  and an over-long id only fails when it is added to a flow (500). The endpoint logs a warning at
  startup for any native provider whose id is longer.
- Executions that are ALTERNATIVE siblings (directly or through sub-flows) are offered together in
  one `challenges[]` set; the client answers whichever it prefers by `challenge_id`.
- Native required actions pending after the flow are served in-band as another challenge:
  `native-passkey-register` under its own alias, and `native-update-password`, `native-verify-email`,
  `native-terms` either under their own alias or **in place of** Keycloak's `UPDATE_PASSWORD`,
  `VERIFY_EMAIL`, `TERMS_AND_CONDITIONS` when those are pending and the native action is registered
  and enabled in the realm (disable it to fall back to the browser; a user without an e-mail address
  cannot be served by `native-verify-email`). Any other required action (update profile, configure
  OTP, ...) ends the request with `403 redirect_to_web` (a PAR `request_uri` for the browser) when
  the native request carried PKCE and the client has a redirect URI, else `403 access_denied` naming
  the action.
- Step-up levels: put the factors under `conditional-level-of-authentication` sub-flows exactly as in
  Keycloak's browser step-up flow (see `native-step-up`); `native-username` skips itself when the
  user is already identified.
- `native-otp` as an ALTERNATIVE beside other factors sends nothing until the client picks it
  (`action=resend`); as the single option it sends at once.
- Challenge sets are ordered like the flow (depth-first execution order), so put the preferred
  factor first in the sub-flow.

## Security notes

- `auth_session` is a `dir`/AES-GCM JWE under the realm's `aes-generated` key (`A128GCM` with the
  default 128-bit key, `A256GCM` if the key provider is configured with `secretSize=32`). It is never
  logged; log lines use a SHA-256 prefix.
- Codes are PKCE-bound and single use; wrong password / TOTP / passkey / recovery-code attempts go
  through Keycloak's brute-force detector; brute-force or disabled accounts end with `403
  access_denied`, and the failed descriptor carries `retry.remaining`. Unknown, disabled and locked
  usernames are answered with a phantom password challenge (same countdown, same lock-out), so the
  username step does not reveal whether an account exists.
- Passkey challenges are single use and re-issued with every challenge set; registration challenges
  are additionally stored as single-use objects so a ceremony completes at most once cluster-wide.
- The success body's `auth_session` is a post-login JWE bound to the user session (lifetime = the
  SSO idle timeout from minting, capped by the session max; spec/14 D6) and, when the login carried
  DPoP proofs, to the DPoP key; presenting it starts a step-up (spec/03 §5) whose code is issued for
  the same user session. A revoked/ended user session or an expired value answers `invalid_session`.
- OTP codes are stored salted-and-hashed in the authentication session, expire after `ttl`, are
  invalidated after `max-attempts` wrong codes, and wrong codes count as brute-force failures.
- `request_uri` values for `redirect_to_web` are single use and expire with the realm's PAR lifespan.
- Client attestation and endpoint rate limiting are not implemented yet (spec/07).
