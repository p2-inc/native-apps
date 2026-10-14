# KeycloakNativeDemo (example iOS app)

Proves the protocol paths end to end against the demo realm and shows how an app drives
`KeycloakNativeCore` without the (Phase 2) default UI: a hand-rolled login screen that renders the
server's challenge set, a Home screen with token claims and post-login passkey registration, a
Scenarios list (S1, S2, S3, S11, S14 and the `dave` enrolment path of `spec/06 §2`) and a Diagnostics
tab with the redacted flow log. Design: `../../spec/06-example-ios-app.md`.

Layout: `Sources/KeycloakNativeDemoApp` is a Swift package library (SwiftUI + `DemoModel`) so it
type-checks with `swift build` on macOS; `App/` holds the `@main` entry, `Config.plist`, entitlements;
`project.yml` is the [XcodeGen](https://github.com/yonaskolb/XcodeGen) spec that produces
`KeycloakNativeDemo.xcodeproj` (committed, regenerate with `xcodegen generate` after editing).

## 1. Simulator, no passkeys (S3, S14, token lifecycle)

```bash
cd keycloak-native-auth
mvn -DskipTests -DskipITs package
cd demo && KC_PORT=8089 docker compose up --wait          # http://localhost:8089 (8080 is often taken)
open ../../ios/KeycloakNativeDemo/KeycloakNativeDemo.xcodeproj
```

`App/Config.plist` already points at `http://localhost:8089/realms/demo` (the simulator shares the
Mac's `localhost`; `NSAllowsLocalNetworking` permits plain HTTP). Run on an iOS 17+ simulator,
choose **S3**, log in as `alice / alice-password` and the TOTP from
`keycloak-native-auth/demo/scripts/walkthrough.sh` (it prints the current code) or any
authenticator app seeded with `alice-totp-secret-20261014`.

**S14** runs itself from the Scenarios tab (user `erin`, five wrong passwords → `access_denied`;
the realm's `failureFactor` is 5 and the lock lasts 60 s).

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

## Not demonstrated here

S4–S10, S12, S13 (OTP, chooser UI product, step-up, redirect-to-web, refresh-forced re-auth, push,
custom presenters) depend on Phase 2/3 server and SDK work. The app has no Settings bundle yet;
edit `Config.plist`.
