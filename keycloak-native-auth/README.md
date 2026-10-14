# keycloak-native-auth

Browserless native authentication for Keycloak: a FiPA-style *authorization challenge endpoint*
(`POST /realms/{realm}/native-auth/challenge`) that drives a dedicated Keycloak authentication flow
and returns JSON challenges instead of HTML forms, plus native-aware authenticators. The wire
protocol is `../spec/03-protocol-spec.md`; design and plan are in `../spec/`.

**Status: Phase 0 spike** (username + password + TOTP over HTTP, code → token exchange). Passkeys,
OTP delivery, push MFA, DPoP binding, redirect-to-web and the iOS SDK are later phases. Decisions
taken during the spike (Keycloak version, `redirect_uri` handling, multi-alternative challenges,
endpoint path) are recorded in `../spec/09-phase0-decisions.md`.

## Modules

| Module | Deployed to Keycloak | Contents |
|--------|----------------------|----------|
| `native-auth-core` | yes | Protocol model (snake_case JSON), `AuthSessionCodec` (JWE), `NativeAuthenticator` SPI, `NativeRequestContext` |
| `native-auth-endpoint` | yes | `RealmResourceProvider` id `native-auth`: `GET /metadata`, `POST /challenge`; `ChallengeFlowDriver`, `CodeIssuer` |
| `native-auth-authenticators` | yes | `native-username`, `native-password`, `native-totp` |
| `demo` | no | `docker-compose.yml`, `realm-export/demo-realm.json`, `scripts/walkthrough.sh`, Testcontainers integration tests |

Requires **Keycloak 26.8.x** (pinned to 26.8.1 in `pom.xml`, see spec/09 Q4) and Java 21 to build.

## Build and test

```bash
mvn verify                 # unit tests + integration tests (needs Docker; pulls quay.io/keycloak/keycloak:26.8.1)
mvn verify -DskipITs       # unit tests only
```

The integration tests (`demo/src/test/java/.../NativeAuthIT.java`) start Keycloak with the freshly
built provider JARs and the demo realm, and exercise the happy path, re-challenge on wrong
password / wrong TOTP, invalid / cancelled / expired `auth_session`, unknown `challenge_id`, the
`redirect_uri` modes and the multi-alternative challenge set.

## Run the demo and the curl walkthrough

```bash
mvn -DskipTests -DskipITs package          # builds demo/target/providers/*.jar
cd demo
docker compose up --wait                   # Keycloak 26.8.1 + Postgres; admin console http://localhost:8080/admin (admin/admin)
./scripts/walkthrough.sh                   # username -> password -> totp -> code -> tokens, exit 0 on success
docker compose down -v
```

If host port 8080 is taken: `KC_PORT=8089 docker compose up --wait` and
`KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh`. The script needs `curl`, `jq` and
`openssl`; it computes alice's TOTP locally from the secret seeded in the realm export.

Demo realm contents:

- Flow `native`: `native-username` (REQUIRED) → subflow *primary factor* (REQUIRED: `native-password`
  ALTERNATIVE) → subflow *second factor* (CONDITIONAL: *Condition - user configured* + `native-totp`
  ALTERNATIVE). Selected through the realm attribute `native-auth.flow-alias=native`.
- Flow `native-alternatives` (spec/08 Q2 prototype): password and TOTP as ALTERNATIVE siblings;
  bound to client `demo-ios-alt` via the client attribute `native-auth.flow-alias`.
- Client `demo-ios`: public, PKCE S256 required, attribute `native-auth.enabled=true`,
  standard flow enabled (needed for the code exchange), redirect URI `demoapp://auth/callback`
  reserved for the later `redirect_to_web` fallback.
- Users: `alice` / `alice-password` with TOTP (secret `alice-totp-secret-20261014`, label *Phone*),
  `bob` / `bob-password` (password only, so the conditional second factor is skipped),
  `carol` / `carol-password` with a pending *Update Password* required action (shows the
  `access_denied` extension point).
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
| authenticator `native-username` | `reveal-user-not-found` | `true` → error code `invalid_user`, otherwise generic `invalid_credential` | `false` |

`GET /realms/{realm}/native-auth/metadata` advertises the effective `redirect_uri` requirement under
`code_exchange` and the installed `challenge_types_supported`.

## Flow configuration rules

- Only native-aware authenticators (and condition authenticators) may be used in the native flow.
  If a form-based execution produces a page, the endpoint answers `500 server_error` and logs the
  offending execution id (spec/08 R8).
- Executions that are ALTERNATIVE siblings (directly or through sub-flows) are offered together in
  one `challenges[]` set; the client answers whichever it prefers by `challenge_id`.
- Required actions pending after the flow (update password, verify email, ...) currently end the
  request with `403 access_denied` naming the action; native required actions and
  `redirect_to_web` are Phase 1–2 work.

## Security notes (Phase 0)

- `auth_session` is a `dir`/AES-GCM JWE under the realm's `aes-generated` key (`A128GCM` with the
  default 128-bit key, `A256GCM` if the key provider is configured with `secretSize=32`). It is never
  logged; log lines use a SHA-256 prefix.
- Codes are PKCE-bound and single use; wrong password / TOTP attempts go through Keycloak's
  brute-force detector; brute-force or disabled accounts end with `403 access_denied`.
- DPoP binding, client attestation and endpoint rate limiting are not implemented yet (spec/07).
