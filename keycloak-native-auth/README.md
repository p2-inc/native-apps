# keycloak-native-auth

Browserless native authentication for Keycloak: a FiPA-style *authorization challenge endpoint*
(`POST /realms/{realm}/native-auth/challenge`) that drives a dedicated Keycloak authentication flow
and returns JSON challenges instead of HTML forms, plus native-aware authenticators. The wire
protocol is `../spec/03-protocol-spec.md`; design and plan are in `../spec/`.

**Status: Phase 2** — username + password + TOTP + **passkeys** (allow-list and discoverable
login, registration mid-flow through a native required action and after login through
bearer-authenticated endpoints), **email / SMS one-time codes**, **step-up / re-authentication**
with the post-login `auth_session`, **redirect-to-web** for required actions the native flow cannot
serve, and **DPoP binding** of `auth_session` and code at the challenge endpoint. Push MFA is Phase 3.
Decisions are recorded in `../spec/09-phase0-decisions.md` (Phase 0), `../spec/11-phase1-decisions.md`
(Phase 1a), `../spec/12-phase1b-decisions.md` (iOS SDK) and `../spec/13-phase2-decisions.md` (Phase 2).

## Modules

| Module | Deployed to Keycloak | Contents |
|--------|----------------------|----------|
| `native-auth-core` | yes | Protocol model (snake_case JSON), `AuthSessionCodec` (JWE), `NativeAuthenticator` and `NativeRequiredAction` SPIs, `NativeRequestContext` |
| `native-auth-authenticators` | yes | `native-username`, `native-password`, `native-totp`, `native-passkey` |
| `native-auth-otp-sender` | yes | `native-otp` authenticator (spec/03 §4.6) and the `native-otp-sender` SPI with the `email` (realm SMTP) and `sms-webhook` senders |
| `native-auth-required-actions` | yes | `native-passkey-register` plus the passkey registration helpers (`PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier`) |
| `native-auth-endpoint` | yes | `RealmResourceProvider` id `native-auth`: `GET /metadata`, `POST /challenge`, `POST /passkey/register/options|finish`; `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver`, `DPoPProofChecker`, `RedirectToWebBuilder` |
| `demo` | no | `docker-compose.yml` (Keycloak, Postgres, mailpit, a Node resource server for the step-up demo), `realm-export/demo-realm.json`, `scripts/walkthrough.sh`, `scripts/passkey-walkthrough.md`, Testcontainers integration tests |

Requires **Keycloak 26.8.x** (pinned to 26.8.1 in `pom.xml`, see spec/09 Q4) and Java 21 to build.

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
`OtpIT.java`, `RedirectToWebIT.java`, `DPoPBindingIT.java`) start Keycloak (plus a mailpit SMTP sink)
with the freshly built provider JARs and the demo realm, and exercise the happy path, re-challenge on
wrong password / wrong TOTP / wrong passkey signature, invalid / cancelled / expired `auth_session`,
unknown `challenge_id`, the `redirect_uri` modes, the multi-alternative challenge set, passkey
registration (authenticated endpoints and the `native-passkey-register` required action), allow-list
and discoverable passkey login, step-up with LoA conditions, `max_age` re-authentication, email OTP
with resend / cooldown / exhaustion, the browser fallback driven through Keycloak's HTML forms, and
DPoP-bound sessions and codes. `PasskeyIT` uses a software WebAuthn authenticator
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
  configured* + `native-totp` ALTERNATIVE). Selected through the realm attribute
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
  `native-otp - email`: 6 digits, 300 s, 10 s resend cooldown, 3 attempts. Emails land in mailpit.
- WebAuthn **Passwordless** policy: RP ID `localhost`, ES256/RS256, user verification `required`,
  resident key `required`, attestation `none`, no extra origins. Required action
  `native-passkey-register` is registered and enabled (the export lists Keycloak's default required
  actions too, because Keycloak seeds them only into an empty list).
- Client `demo-ios`: public, PKCE S256 required, attribute `native-auth.enabled=true`,
  standard flow enabled (needed for the code exchange), redirect URI `demoapp://auth/callback`
  reserved for the later `redirect_to_web` fallback.
- Users: `alice` / `alice-password` with TOTP (secret `alice-totp-secret-20261014`, label *Phone*),
  `bob` / `bob-password` (password only, so the conditional second factor is skipped),
  `carol` / `carol-password` with a pending *Update Password* required action (shows the
  `access_denied` extension point for non-native required actions), `dave` / `dave-password` with the
  pending `native-passkey-register` action (a passkey is enrolled in-band on the first native login),
  `erin` / `erin-password` reserved for the brute-force demo (spec/06 S14): `failureFactor` is 5 in
  the demo realm, so five wrong passwords (or two within a second) lock the account for a minute and
  the flow ends with `403 access_denied`. No passkey is pre-registered in the export; the
  integration tests register them. carol's native login now ends with `403 redirect_to_web` (a PAR
  `request_uri` for the browser, spec/03 §3.4) instead of `access_denied`.
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
| realm | WebAuthn Passwordless policy (`webAuthnPolicyPasswordless*`) | RP ID, algorithms, user verification, resident key, attestation, extra origins, create timeout: drives both the `passkey` and `passkey_registration` descriptors | Keycloak defaults |
| authenticator `native-username` | `reveal-user-not-found` | `true` → error code `invalid_user`, otherwise generic `invalid_credential` | `false` |

`GET /realms/{realm}/native-auth/metadata` advertises the effective `redirect_uri` requirement under
`code_exchange`, the passkey RP ID and registration endpoints under `passkey`, the installed
`challenge_types_supported` (native authenticators and native required actions), the realm's
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
  offending execution id (spec/08 R8).
- Executions that are ALTERNATIVE siblings (directly or through sub-flows) are offered together in
  one `challenges[]` set; the client answers whichever it prefers by `challenge_id`.
- Native required actions (`native-passkey-register`) pending after the flow are served in-band as
  another challenge; any other required action (update password, verify email, ...) ends the request
  with `403 redirect_to_web` (a PAR `request_uri` for the browser) when the native request carried
  PKCE and the client has a redirect URI, else `403 access_denied` naming the action.
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
- Codes are PKCE-bound and single use; wrong password / TOTP / passkey attempts go through Keycloak's
  brute-force detector; brute-force or disabled accounts end with `403 access_denied`.
- Passkey challenges are single use and re-issued with every challenge set; registration challenges
  are additionally stored as single-use objects so a ceremony completes at most once cluster-wide.
- The success body's `auth_session` is a post-login JWE bound to the user session (lifetime = SSO
  session max) and, when the login carried DPoP proofs, to the DPoP key; presenting it starts a
  step-up (spec/03 §5) whose code is issued for the same user session. A revoked/ended user session
  answers `invalid_session`.
- OTP codes are stored salted-and-hashed in the authentication session, expire after `ttl`, are
  invalidated after `max-attempts` wrong codes, and wrong codes count as brute-force failures.
- `request_uri` values for `redirect_to_web` are single use and expire with the realm's PAR lifespan.
- Client attestation and endpoint rate limiting are not implemented yet (spec/07).
