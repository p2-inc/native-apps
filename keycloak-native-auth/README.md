# keycloak-native-auth

Browserless native authentication for Keycloak: a FiPA-style *authorization challenge endpoint*
(`POST /realms/{realm}/native-auth/challenge`) that drives a dedicated Keycloak authentication flow
and returns JSON challenges instead of HTML forms, plus native-aware authenticators. The wire
protocol is `../spec/03-protocol-spec.md`; design and plan are in `../spec/`.

**Status: Phase 1a** — username + password + TOTP + **passkeys** (allow-list and discoverable
login, registration mid-flow through a native required action and after login through
bearer-authenticated endpoints) over HTTP, code → token exchange. OTP delivery, push MFA, DPoP
binding, step-up, redirect-to-web and the iOS SDK are later phases. Decisions are recorded in
`../spec/09-phase0-decisions.md` (Phase 0) and `../spec/11-phase1-decisions.md` (Phase 1a).

## Modules

| Module | Deployed to Keycloak | Contents |
|--------|----------------------|----------|
| `native-auth-core` | yes | Protocol model (snake_case JSON), `AuthSessionCodec` (JWE), `NativeAuthenticator` and `NativeRequiredAction` SPIs, `NativeRequestContext` |
| `native-auth-authenticators` | yes | `native-username`, `native-password`, `native-totp`, `native-passkey` |
| `native-auth-required-actions` | yes | `native-passkey-register` plus the passkey registration helpers (`PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier`) |
| `native-auth-endpoint` | yes | `RealmResourceProvider` id `native-auth`: `GET /metadata`, `POST /challenge`, `POST /passkey/register/options|finish`; `ChallengeFlowDriver`, `CodeIssuer`, `RequiredActionDriver`, `PasskeyRegistrationDriver` |
| `demo` | no | `docker-compose.yml`, `realm-export/demo-realm.json`, `scripts/walkthrough.sh`, `scripts/passkey-walkthrough.md`, Testcontainers integration tests |

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

The integration tests (`demo/src/test/java/.../NativeAuthIT.java`, `PasskeyIT.java`) start Keycloak
with the freshly built provider JARs and the demo realm, and exercise the happy path, re-challenge on
wrong password / wrong TOTP / wrong passkey signature, invalid / cancelled / expired `auth_session`,
unknown `challenge_id`, the `redirect_uri` modes, the multi-alternative challenge set, passkey
registration (authenticated endpoints and the `native-passkey-register` required action), allow-list
and discoverable passkey login. `PasskeyIT` uses a software WebAuthn authenticator
(`SoftwareAuthenticator`, ES256, `none` attestation) so no device is needed.

## Run the demo and the curl walkthrough

```bash
mvn -DskipTests -DskipITs package          # builds demo/target/providers/*.jar
cd demo
docker compose up --wait                   # Keycloak 26.8.1 + Postgres; admin console http://localhost:8080/admin (admin/admin)
./scripts/walkthrough.sh                   # username -> password -> totp -> code -> tokens, exit 0 on success
docker compose down -v
```

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
  integration tests register them.
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
| realm | `native-auth.passkey-registration-max-age` | seconds since the user authenticated (user session `AUTH_TIME`) within which `/passkey/register/*` accept the token; `0` disables | `300` |
| realm | WebAuthn Passwordless policy (`webAuthnPolicyPasswordless*`) | RP ID, algorithms, user verification, resident key, attestation, extra origins, create timeout: drives both the `passkey` and `passkey_registration` descriptors | Keycloak defaults |
| authenticator `native-username` | `reveal-user-not-found` | `true` → error code `invalid_user`, otherwise generic `invalid_credential` | `false` |

`GET /realms/{realm}/native-auth/metadata` advertises the effective `redirect_uri` requirement under
`code_exchange`, the passkey RP ID and registration endpoints under `passkey`, and the installed
`challenge_types_supported` (native authenticators and native required actions).

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
  with `403 access_denied` naming the action until `redirect_to_web` lands in Phase 2.
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
  session max); the challenge endpoint rejects it with `invalid_session` until step-up exists.
- DPoP binding, client attestation and endpoint rate limiting are not implemented yet (spec/07).
