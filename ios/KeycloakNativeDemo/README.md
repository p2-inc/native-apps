# KeycloakNativeDemo (example iOS app)

Proves the protocol paths end to end against the demo realm and shows both ways of driving the SDK:
the hand-rolled login screen (the "full control" sample: it renders the server's challenge set
itself) and, for S5/S13, `NativeLoginView` from `KeycloakNativeUI`. Also a Home screen with token
claims, post-login passkey registration, the step-up "Transfer" call and the S8 session controls, a
Scenarios list (S1–S14 and the `dave` / `judy` enrolment paths of `spec/06 §2`) and a Diagnostics
tab with the redacted flow log, plus the Phase 2b required actions (carol: update password in-band,
grace: verify email with a code, hank: terms and conditions) and the Phase 3 push MFA section on Home
(enrol, sign-in requests with number match, APNs token, key rotation, lockout). Design:
`../../spec/06-example-ios-app.md`.

Layout: `Sources/KeycloakNativeDemoApp` is a Swift package library (SwiftUI + `DemoModel`) so it
type-checks with `swift build` on macOS; `App/` holds the `@main` entry, `Config.plist`, entitlements;
`UITests/` the XCUITest smoke tests; `project.yml` is the [XcodeGen](https://github.com/yonaskolb/XcodeGen)
spec that produces `KeycloakNativeDemo.xcodeproj` (committed, regenerate with `xcodegen generate`
after editing).

## 1. Simulator, no passkeys (S3, S14, token lifecycle)

```bash
cd keycloak-native-auth
mvn -DskipTests -DskipITs package
cd demo && KC_PORT=8089 docker compose up --wait          # http://localhost:8089 (8080 is often taken)
open ../../ios/KeycloakNativeDemo/KeycloakNativeDemo.xcodeproj
```

In Xcode pick the scheme **KeycloakNativeDemo** (the one with the app icon). Xcode also lists the
Swift package products as schemes (`KeycloakNativeDemoApp`, `KeycloakNativeCore`,
`KeycloakNativeUI`); those are libraries, so running one of them makes Xcode ask for an executable.
Hide them with Product → Scheme → Manage Schemes if they get in the way.

`App/Config.plist` already points at `http://localhost:8089/realms/demo` (the simulator shares the
Mac's `localhost`; `NSAllowsLocalNetworking` permits plain HTTP). Run on an iOS 17+ simulator,
choose **S3**, log in as `alice / alice-password` and the TOTP from
`keycloak-native-auth/demo/scripts/walkthrough.sh` (it prints the current code) or any
authenticator app seeded with `alice-totp-secret-20261014`.

**S14** runs itself from the Scenarios tab (user `erin`, five wrong passwords → `access_denied`;
the realm's `failureFactor` is 5 and the lock lasts 60 s).

**Simulator Keychain:** the app must be code-signed, even ad hoc. With `CODE_SIGNING_ALLOWED=NO`
the simulator's Keychain answers `-34018` (missing entitlement) and the SDK's DPoP key store and
`CredentialsManager` fail (`keychain_error`). Xcode's default "Sign to Run Locally" is fine; from the
command line pass `CODE_SIGN_IDENTITY="-"`.

### XCUITest smoke tests (spec/06 §1)

```bash
xcodebuild test -project KeycloakNativeDemo.xcodeproj -scheme KeycloakNativeDemo \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro,OS=27.0' CODE_SIGN_IDENTITY="-"
```

`UITests/DemoAppUITests.swift` drives the real app against a **fresh** compose stack
(`docker compose down -v && KC_PORT=8089 docker compose up --wait`, because the required-action
scenarios are consumed by their first run): S3 (password + TOTP computed from the seeded secret),
the Keychain restore across a relaunch, refresh, logout, the software DPoP key (`jkt` in
Diagnostics, `token_type DPoP`), S14, S4 (e-mail code read from mailpit's API), S5 and S13 (default
UI with the chooser, custom TOTP presenter), S6 (step-up for Transfer), S8 (server-side logout →
`reauthentication_required`) and the carol / grace / hank required actions. They are not part of CI
(the runner has no Keycloak); CI only compiles them (`build-for-testing`). S7 needs Safari and stays
manual.

### Phase 2 scenarios on the simulator (S4, S6, S7, S8, S5/S13; all but S7 also run as XCUITests)

- **S4** (client `demo-ios-otp`): `bob / bob-password` → the email code is sent at once; read it in
  mailpit (`http://localhost:8025`). `alice` gets `[totp, otp]` and a "Send me a code" button.
- **S5 / S13**: the same client rendered by `NativeLoginView`; S13 swaps the TOTP screen.
- **S6** (client `demo-ios-stepup`): log in with the password (acr 1), Home → **Transfer**: the
  compose `resource-server` (`http://localhost:8091`) answers `401 insufficient_user_authentication`,
  the app steps up with the stored `auth_session`, the Login tab shows only the TOTP, and the next
  Transfer succeeds with acr 2 (the token is DPoP-bound; the API checks the proof).
- **S7**: `frank / frank-password` → "Continue in the browser" → Safari (`ASWebAuthenticationSession`)
  shows the realm's login with frank pre-filled, then the *Update profile* page; the code returns
  to `demoapp://auth/callback` and the app exchanges it. Safari needs to reach the issuer host: on
  the simulator `localhost:8089` works. (carol's *Update password* is served natively since Phase 2b.)
- **S8**: after any login, Home → **End session on the server**, then **Refresh tokens** →
  `reauthentication_required` (Keycloak answers `invalid_grant` without an `auth_session`, so the
  app starts a new login).

### Phase 2b required actions on the simulator (carol, grace, hank)

- **carol** (`carol / carol-password`): after the password the server asks for `update_password`
  (`challenge_id native-update-password`); the realm's password policy arrives as hints. Enter
  `carol-password` twice to keep the demo repeatable (the action is removed from carol afterwards;
  `docker compose down -v` restores it).
- **grace** (`grace / grace-password`): `verify_email` — the 6-digit code is in mailpit
  (`http://localhost:8025`); "Resend" is rate-limited by the server (30 s).
- **hank** (`hank / hank-password`): `terms` — Accept continues to the tokens, Decline ends the
  login with `access_denied`.

- **ivy** (`ivy / ivy-password`): the second factor offers `[totp, recovery_code]`; enter
  `IVY1-IVY1-IVY1` (then `IVY2-…`, `IVY3-…`; after the last one Keycloak requires new codes and the
  login goes to the browser). Wrong passwords anywhere show "n attempts left" (`retry.remaining`);
  an unknown username gets the same password challenge and countdown as a real one.

The carol / grace / hank scenarios are covered by XCUITests (`testCarolUpdatesPasswordInBand`, `testGraceVerifiesEmail`,
`testHankAcceptsTerms` in `UITests/DemoAppUITests.swift`).

## 2. Real passkeys (S1, S2, S11, dave): HTTPS host + Associated Domains

Platform passkeys need (a) an RP ID that is a real domain the app is associated with and (b) a
`client_data_json.origin` Keycloak accepts (`spec/11 D2`). The compose stack is plain HTTP on
`localhost`, so put it behind a tunnel with a fixed hostname and tell both sides about it:

1. **Tunnel** (`cloudflared` or `ngrok`, with a reserved hostname), e.g.
   `ngrok http 8089 --domain=kc-demo.example.ngrok.app` or
   `cloudflared tunnel --hostname kc-demo.example.com --url http://localhost:8089`.
   Keycloak must see the public host: the compose file sets `KC_HOSTNAME_STRICT=false` and the
   tunnel forwards `Host`/`X-Forwarded-*`, so `issuer`, `token_endpoint` and the WebAuthn origin
   check all use `https://<tunnel-host>`. Set `KC_PROXY_HEADERS=xforwarded` in `docker-compose.yml`
   (environment) if the tunnel sends `X-Forwarded-Proto`.
2. **Apple App Site Association.** The RP ID host must serve
   `https://<tunnel-host>/.well-known/apple-app-site-association` with
   `{"webcredentials":{"apps":["<TEAMID>.io.phasetwo.keycloak.nativedemo"]}}`
   (content type `application/json`). Keycloak does not serve that path; put a small reverse proxy
   (Caddy, nginx) in front of Keycloak that answers it and forwards everything else, and point the
   tunnel at the proxy. Caddyfile example:
   ```
   :8090 {
     handle /.well-known/apple-app-site-association {
       header Content-Type application/json
       respond `{"webcredentials":{"apps":["TEAMID.io.phasetwo.keycloak.nativedemo"]}}`
     }
     reverse_proxy localhost:8089
   }
   ```
3. **Realm.** Admin console → Authentication → Policies → *WebAuthn Passwordless Policy*: set
   **Relying party ID** to `<tunnel-host>`. **Extra origins** can stay empty when the tunnel host is
   Keycloak's public base URL; add `https://<tunnel-host>` there if Keycloak's base URL differs
   (`spec/11 D2`, README "Passkey notes"). A realm restart is not needed.
4. **App.** `App/KeycloakNativeDemo.entitlements`: `webcredentials:<tunnel-host>?mode=developer`
   (developer mode skips Apple's CDN and reads the AASA file from the host directly; only for
   Xcode-signed development builds). `App/Config.plist`: `Issuer` = `https://<tunnel-host>/realms/demo`.
   Leave `AllowRpIdMismatch` false: the issuer host equals the RP ID. Set it to true only when you
   deliberately keep the issuer on `http://localhost:8089` while the policy RP ID is the tunnel host —
   the SDK's rule (`spec/12`) refuses that combination otherwise, and iOS would refuse the passkey
   sheet anyway unless the entitlement matches.
5. Run on a device or simulator signed in to iCloud Keychain. Order: **S3** (log in) → **S11**
   (Home → Register passkey) → **S1** (restart login: `[passkey, password]` after the username) →
   **S2** (client `demo-ios-passkey`, discoverable). **dave**: fresh realm (`docker compose down -v`),
   log in as `dave / dave-password`, the `passkey_registration` challenge appears in-band.

The Diagnostics tab shows every request/response with secrets masked (`auth_session`, codes, tokens,
passwords, OTPs, assertions) and the DPoP key thumbprint; "Copy" puts the log on the pasteboard.

### Push MFA on the simulator (S9, S10, S12, judy; spec/14 D9)

The compose stack ships ba-itsys' push MFA (rebuilt for Java 21), the `apns` sender (idle without an
Apple team) and the native bridge. The simulator receives no APNs: every approval is pulled from
`/push-mfa/login/pending` through Home → "Sign-in requests" (pull to refresh).

1. **S9** — scenario S9, log in as alice, Home → "Enrol this device for push". Then sign in as alice
   in a browser (`http://localhost:8089/realms/demo/account`, flow `browser-push`): the browser waits,
   Home → "Sign-in requests" → Approve, the browser continues.
2. **S10** — scenario S10, log in as alice: the second factor is `[totp, push]`; "Send request" shows
   a number; Home → "Sign-in requests" offers three, pick the matching one; back on Login the app polls
   (`action=poll`) and finishes.
3. **S12** — Home: "Simulate APNs token" (`PUT /device/push-provider`; a device registers its real
   token through "Enable notifications" and the app delegate), "Rotate device key" (`PUT
   /device/rotate-key`: the DPoP key rotates, the stored tokens were bound to the old key, sign in
   again), "Lock out account" (`POST /login/lockout`: ba-itsys disables alice; re-enable her in the
   admin console or `docker compose down -v`).
4. **judy** — scenario "Enrol for push mid-flow": after the password the `push_enrollment` challenge
   enrols this device with the app's DPoP key; judy's next login asks for push at once.

The four `PushUITests` run these on the simulator (`-only-testing:KeycloakNativeDemoUITests/PushUITests`,
in name order; the browser of S9 is a `URLSession` with a hand-rolled cookie jar inside the test,
and the admin API resets alice / judy at the end). Real APNs delivery and the notification service
extension need a device and an Apple team (spec/14 "Left out").

## Not demonstrated here

Real push delivery (APNs needs a device). The app has no Settings bundle yet; edit `Config.plist`
(`Issuer`, `ClientId`, `PasskeyClientId`, `StepUpClientId`, `OtpClientId`, `ResourceServer`,
`AllowRpIdMismatch`, `DeviceName`).
