# Development, testing and troubleshooting

[Index](README.md) · [Server reference](protocol-and-flows.md) · [Sample setup](sample-app.md) · [Security](security.md)

## Layout and dependencies

| Path | Responsibility |
| --- | --- |
| `keycloak-native-auth/native-auth-core` | JSON protocol models, session JWE codec, native SPI interfaces |
| `keycloak-native-auth/native-auth-endpoint` | Realm resource, authentication orchestration, code issuance, required-action dispatch, token-authenticated enrollment and browser handoff |
| `keycloak-native-auth/native-auth-authenticators` | Username, password, TOTP, passkey, recovery-code authenticators and shared challenge base |
| `keycloak-native-auth/native-auth-otp-sender` | Email/SMS authenticator, sender SPI, hashed-code state and email templates |
| `keycloak-native-auth/native-auth-required-actions` | Passkey enrollment, password update, email verification and terms |
| `keycloak-native-auth/push-mfa-extension-java21` | Upstream 2.3.7 published-source rebuild for Java 21 |
| `keycloak-native-auth/native-auth-push`, `native-auth-push-apns` | Native bridge/enrollment and HTTP/2 APNs sender |
| `keycloak-native-auth/demo` | Realm export, Compose stack, walkthrough, resource-server example, integration tests/transcripts |
| `Package.swift`, `ios/KeycloakNative` | Swift package manifest (repository root) and the Core, UI and Push sources and Swift Testing suites |
| `ios/KeycloakNativeDemo` | Swift package sample model/views, generated Xcode application and XCUITests |
| `spec/` | Original protocol/design documents and historical decisions/plans |

The [parent POM](../keycloak-native-auth/pom.xml) pins Keycloak **26.8.1**, Java release **21**, push MFA **2.3.7**, JUnit **6.1.3**, Testcontainers **2.0.5**, REST Assured **6.1.0**. Keycloak server private SPIs/services are compile dependencies; binary compatibility across other versions is not promised. Test realm/container version and production provider build must match. Compose adds Postgres 17 Alpine, mailpit v1.27 and Node 22 Alpine. Resource server uses Node built-ins without npm dependencies.

Swift tools/language mode 6, iOS 17+ / macOS 14+ are declared in the [manifest](../Package.swift). The demo also targets iOS 17+. Xcode 27 / Swift 6.4 is the toolchain verified here. The Android SDK (`android/`, compileSdk 37, minSdk 28) and its demo app are in progress; see [the Android demo README](../android/demo/README.md) and [spec/17](../spec/17-android-sdk-plan.md).

## Build, deploy and run

From `keycloak-native-auth`:

```bash
mvn -DskipTests -DskipITs package
mvn verify -DskipITs
mvn verify
```

The first packages providers, second runs unit tests without Docker ITs, third runs unit + Testcontainers HTTP integration tests. Packaging copies deployable runtime JARs (including the Java 21 push rebuild) to `demo/target/providers` with version-stripped names. Deploy **all** these JARs together in Keycloak's `providers/` directory; using only the endpoint JAR omits its protocol/authenticator dependencies. Avoid deploying upstream Java 25 binary alongside its Java 21 rebuild. For an optimized Keycloak installation, include providers during its normal image/server augmentation/build step; the checked-in reproducible deployment is the Compose `start-dev --import-realm` setup below, not a production image recipe.

```bash
cd demo
KC_PORT=8089 docker compose up --wait
KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh
docker compose logs --tail=200 keycloak
docker compose down
```

Keycloak only loads JARs at the top level of `/opt/keycloak/providers`; JARs in subdirectories are ignored, so mount or copy the files themselves, not a folder that contains them. Compose mounts `target/providers` read-only into `/opt/keycloak/providers` and `realm-export` into `/opt/keycloak/data/import`. Server must be restarted/rebuilt as appropriate after replacing JARs; mounted files alone do not reload Java classes. Ensure the container user can read files (CI uses `chmod -R a+rX target/providers realm-export`). Existing persisted realm imports are not overwritten. `docker compose down -v` is a destructive disposable-demo reset, not a routine update procedure.

Native flow selection is by realm/client attributes, independent of browser flow. The export sets browser flow `browser-push` and native alias `native`. For an existing realm, reproduce [exported executions and configs](flow-examples.md#concrete-exported-flows), enable native required actions (keep defaults if importing a full `requiredActions` list), configure the public client and S256, and register a fallback URI. Check [metadata](protocol-and-flows.md#discovery-and-starting) after deployment. Realm SMTP is required for email OTP and verification. SMS needs an explicitly configured webhook and allowed phone user attribute; compose intentionally has no SMS service.

SDK (from the repository root, where the manifest is):

```bash
swift build
swift test
```

On a Command Line Tools-only Mac without toolchain Testing/XCTest, the manifest supports:

```bash
KEYCLOAK_NATIVE_TESTING_FROM_SOURCE=1 swift test --build-system native
```

That mode downloads `swift-testing` **6.2.4** as a test-only dependency; library products remain dependency-free. It was inspected, not rerun during this task.

Sample (from `ios/KeycloakNativeDemo`):

```bash
swift build
xcodebuild -project KeycloakNativeDemo.xcodeproj -scheme KeycloakNativeDemo \
  -destination 'generic/platform=iOS Simulator' CODE_SIGN_IDENTITY="-" build-for-testing
```

The committed project needs no XcodeGen install to build; regenerate with `xcodegen generate` only when editing `project.yml`. Use `xcrun simctl list devices available` and choose an actual installed destination for running tests, e.g. the available device used by repository examples:

```bash
xcodebuild test -project KeycloakNativeDemo.xcodeproj -scheme KeycloakNativeDemo \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro,OS=27.0' CODE_SIGN_IDENTITY="-"
```

## Test coverage and manual verification

[Java integration tests](../keycloak-native-auth/demo/src/test/java/io/phasetwo/keycloak/nativeauth/demo) start their own Keycloak/mailpit plus SMS/APNs/FCM sinks using Testcontainers and the fresh provider artifacts/export. They cover flow alternatives, invalid/cancelled/expired sessions, PKCE/redirect modes, password/TOTP failures and lockout, software WebAuthn assertions/registration, required actions, LoA step-up, post-login expiry, DPoP binding, browser fallback HTML flow, OTP resend/exhaustion, recovery codes and push enrollment/approval/maintenance. APNs and FCM tests verify payload/signing/fake delivery (for FCM also the service-account token grant), not Apple or Google production delivery. `AndroidOriginIT` verifies the server side of Android passkeys with a software authenticator, not Credential Manager.

Java transcripts are generated under `demo/target/transcripts`; committed `demo/transcripts` are Swift replay fixtures. Refresh intentionally with `./demo/scripts/update-transcripts.sh` from `keycloak-native-auth` **after** a successful server verification; this deletes/replaces the committed JSON fixtures. Do not refresh them just for documentation or blindly treat generated token material as redacted. [Transcript format](../keycloak-native-auth/demo/transcripts/README.md) explains matching/masking.

Swift tests cover parsing, form fields, transcript replay, PKCE/JOSE, DPoP, redaction, credentials/refresh and UI model behavior. Replay verifies client handling of recorded exchanges, not a live server connection. Live tests opt in:

```bash
KEYCLOAK_NATIVE_LIVE_BASE=http://localhost:8089 swift test
```

Run from the repository root against a disposable, correctly initialized stack. Mailpit/resource defaults are `http://localhost:8025` and `http://localhost:8091`; override `KEYCLOAK_NATIVE_LIVE_MAILPIT` / `KEYCLOAK_NATIVE_LIVE_RESOURCE`. Tests modify users, required actions and enrollments; use fresh/reset demo data when needed. Live suites are disabled unless base variable is set.

[XCUITests](../ios/KeycloakNativeDemo/UITests) drive actual app input, restoration, refresh/logout, required actions, email OTP, default/custom UI, step-up, lockout and push maintenance. Push tests depend on enrollment/setup order. They need the stack on 8089; do not run against production accounts. S7 system-browser fallback and real passkey ceremonies remain manual sample checks. [CI workflow](../.github/workflows/ci.yml) defines Java verify, compose walkthrough, SDK tests, sample package build and simulator `build-for-testing`; it compiles rather than runs XCUITests. Local verification here does not prove GitHub CI was run.

Manual acceptance from a fresh disposable realm:

1. Start stack/package providers; inspect metadata and run curl walkthrough. Confirm code/token exchange and no browser for password/TOTP.
2. Run app S3; wrong input must render descriptor error, correct input reaches Home. Relaunch restores standard-client credentials; refresh succeeds; logout clears local state.
3. S4 bob receives email automatically; alice's OTP alternative waits for request. Test cooldown, wrong/expired code and explicit resend.
4. Exercise carol/grace/hank, ivy single-use codes, S6 transfer step-up and S8 refused refresh. Consumed actions/codes change subsequent behavior.
5. Enroll push with `none`, approve browser requester, then native requester with number match. Deny/expiry should permit appropriate retry/alternative; key rotation requires new login.
6. Configure associated domain/real issuer and validate S11 → S1/S2 and dave registration/cancellation on Apple platform. Separately validate APNs on signed physical hardware. Try frank browser fallback; verify return code/state and no native session resumption.

## Diagnostics and troubleshooting

Diagnostics in the sample uses `FlowObserver` plus debug OSLog, showing redacted request/response bodies, URLs/status, metadata and DPoP thumbprint. Flow state/session is SDK-owned; use descriptor `type`/ID and server event fields (`native_protocol`, `challenge_type`) to trace execution. Compose enables `io.phasetwo.keycloak.nativeauth:debug` and upstream push debug. Login success is not necessarily printed at INFO; inspect configured Keycloak events/admin console as well. Do not publish raw debug output or fixture tokens.

| Symptom | Checks | Likely resolution |
| --- | --- | --- |
| Native metadata 404; providers absent | Correct issuer/realm/path? JARs in `demo/target/providers`? Startup/provider/service-registration errors? | Package the full reactor; install all providers; restart server. Do not infer native support from standard well-known document alone. |
| 401 `invalid_client` or 400 initial request | Client enabled/public/native-enabled/standard-flow? `response_type=code`, S256 fields? | Match exported client attributes and PKCE settings. Client secret is not required or accepted as a substitute for native enablement. |
| 500 flow not configured / HTML execution | Realm/client `native-auth.flow-alias`, exact alias and provider IDs; the error log names the offending execution and provider id | Restore exported native flow layout; use native factors, not HTML form factors, or set `native-auth.non-native-execution=redirect_to_web` to send such logins to the browser. Changing browser binding alone does not select native flow. |
| 500 when adding a custom authenticator to a flow | Provider id longer than 36 characters (startup warning `Native provider id ... varchar(36)`) | Shorten the id; Keycloak stores provider ids in `varchar(36)`. |
| Only password, no passkey/second factor | User's actual stored credentials, chosen flow/client, conditional eligibility | Register needed credential or use the intended client. No passkey is in fresh export. Conditional bob/password-only behavior is expected. |
| Unsupported challenge UI | `ChallengeType.isSupported`, metadata vs flow offers, SDK version, raw descriptor | Offer another supported alternative or update server/SDK/UI together; unsupported execution is not an automatic browser handoff. |
| Network error / ATS / wrong issuer | Simulator vs device hostname; 8089 app vs 8080 Compose default; discovery URLs and proxy host/protocol; certificate | Match server port/config. Device needs reachable HTTPS host; configure trusted proxy/public issuer consistently. Do not ship broad ATS exceptions. |
| `invalid_session` after waiting/relaunch/logout | Latest session, bound key/client, login/user-action timeout, original process/flow, post-login embedded expiry | Create a new flow/login. Do not reuse old tab/session, change clients or expect refresh to extend post-login session expiry. |
| `flow_state`, reused challenge | Already started/finished flow? Submission pending? Challenge from latest set? | Serialize UI actions, retain one flow and replace steps atomically; start a new flow after completion. |
| Token exchange `invalid_grant` / redirect mismatch | Original verifier/key and code, native redirect mode metadata vs browser callback, already attempted exchange | Match configuration; use automatic exchange. Fix realm-wide `client-fixed` metadata inconsistency; restart login after consumed code. |
| `invalid_dpop_proof` / bound-token rejection | Exact method/URL, issuer/proxy rewrite, clock, original key/thumbprint and feature state | Use same instance/key and correct proof URL; configure trusted proxy/public host, keep clocks synchronized. Key rotation needs new tokens. |
| Passkey `rp_id_mismatch`, OS sheet fails or invalid assertion | RP/issuer relationship, entitlement/AASA/team, iCloud Keychain, Passwordless policy and accepted origin | Complete domain/provisioning setup; use returned fresh challenge, not an old assertion. `allowRpIdMismatch` does not repair OS association. |
| `keychain_error` / OSStatus `-34018` on simulator | Was signing disabled? Access group entitlement/service? | Keep ad hoc signing (`CODE_SIGN_IDENTITY="-"`); use correct access group. SDK needs storage even before login for DPoP key. |
| OTP unsent, `expired_code`, `resend_too_soon` | `sent`, `resend_allowed_at`, TTL/attempt config, SMTP/mailpit or webhook logs, email/phone attribute | Explicitly request an alternative code; wait cooldown/resend; fix delivery. SMS is not wired in Compose; eligibility still checks default email channel. |
| Required action unexpectedly browser-only | Native action registered/enabled? Substitution available/canServe? Callback/PAR/PKCE? | Enable supported native action, supply email delivery, or deliberately complete browser-only action. TOTP/recovery-code generation/profile update have no native equivalent. |
| Registration 403 `insufficient_authorization` without `challenges` | Authentication `AUTH_TIME` vs 300-second registration limit, native-client-only policy | Drive error's `auth_session`/`max_age` via step-up then retry; token refresh alone does not renew authentication. |
| Push unavailable / no delivery / approvals fail | Metadata push block, active local/server credential, DPoP token/key, user/account, APNs sender/provisioning | Install bridge/upstream dependencies; enroll same key/account; test polling with `none` first. Real APNs needs entitlement/token/server key/topic/environment. |
| Push number mismatch / conflict | User-selected number and latest pending state; already resolved on another device? | Show fresh context, submit intentional match; re-fetch on 409 instead of repeating approval blindly. |
| Android passkey `invalid_credential`, or Credential Manager refuses the request | `assetlinks.json` on the RP ID (package name + signing-cert SHA-256, `get_login_creds`), the `android:apk-key-hash:` origin of the signing key in use in the Passwordless policy's extra origins, whether the policy update stuck | Add the origin for every signing key (debug, upload, Play App Signing). Update the policy with all `webAuthnPolicyPasswordless*` fields: an update with only the extra origins returns 204 and is ignored. |
| Demo differs after prior tests | Persistent database, consumed required actions/codes, passkeys/push, quick-login lockout | Inspect user state; re-enable/unlock deliberately or reset only a disposable demo database. Fast wrong-password attempts can lock before countdown zero. |

## Verification record

Executed during this documentation task on **2026-10-15**:

| Check | Result and scope |
| --- | --- |
| `mvn -B --no-transfer-progress verify` | Passed full reactor, **17 unit tests + 58 integration tests**, zero failures/errors/skips. Host Maven 3.9.16 / Java 25.0.1 compiled with release 21; test container is Keycloak 26.8.1. This does not prove arbitrary JDK/Keycloak compatibility. |
| `swift test` in SDK | **107 tests passed in 18 suites** with Xcode 27.0 / Swift 6.4. Live suites not enabled; test discovery/build compiles their source. Existing docs' “115 tests” does not match this run. |
| `swift build` in sample | Passed; existing Combine import warnings in timer-based SwiftUI screens remain. |
| Simulator `xcodebuild … build-for-testing` | Passed app and UI-test compilation with ad hoc signing; no simulator interaction or XCUITest execution in this task. |
| `KC_BASE=http://localhost:8089 ./scripts/walkthrough.sh` | Passed against already-running Compose demo; obtained Bearer tokens for alice. Stack was inspected healthy, not reset/recreated. Testcontainers verification used isolated server infrastructure. |
| Local docs/source links, flow export and examples | All 137 local links/heading targets checked; Markdown fences and example PKCE pair checked. Complete SwiftUI login example type-checked against built SDK with Swift 6 targeting macOS 14. Flow layouts/fields cross-checked with export, source and transcripts. |

Apple physical-device passkeys, Secure Enclave behavior, associated-domain/provisioning setup, notification service extension, real APNs delivery and accessibility were **not executed** here. These remain hardware/deployment verification gaps; successful software WebAuthn/APNs-sink tests and simulator compilation do not fill them. No production deployment or external services were configured.

Meaningful conflicts/limitations found by source inspection:

- The server README's “Phase 2b / push later”, early tables in `spec/10`, old comments saying no step-up/session binding, and spec push version “v1.11” are historical. Current code has push/required actions, binding and step-up; POM resolves push 2.3.7. The older metadata example includes unimplemented `select`/`redirect_to_web` advertised entries; installed-type enumeration does not.
- `NativeUsernameAuthenticatorFactory` help text understates phantom password behavior; implementation handles unknown/disabled/locked accounts as described in the new reference. Retry countdown and enroll-on-first-login are implemented despite early status claims to the contrary.
- `client-fixed` issuance can use client-specific URI while client-agnostic metadata exposes only realm URI. Use a consistent realm URI with current SDK. No behavior change was made.
- `native-otp.configuredFor` uses the default email sender rather than each execution channel; SMS webhook tests configure additional server/user-profile state absent from Compose.
- Push PIN can be produced server-side, but typed Swift/default screens primarily support number matching. Notification JWT parsing is not signature verification; fetch authenticated server state.
- Sample entitlements are empty; associated domains and APNs provisioning must actually be added. RootView restores session at startup but has no automatic foreground approvals fetch; approvals refresh is user-driven. Persistence errors are hidden by sample `try?`, scenario switching drops a flow without canceling it, and storage is issuer/client-scoped rather than user-scoped.

Existing design documents are preserved to retain decisions and history. Current guides distinguish those claims from implementation; none of these findings was addressed by changing application behavior.
