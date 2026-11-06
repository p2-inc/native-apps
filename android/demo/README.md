# Android demo app

The Android counterpart of `ios/KeycloakNativeDemo`: an app (`io.phasetwo.keycloak.nativedemo`) that runs the native login against the demo realm with the SDK's default screens and shows what the SDK gives an app afterwards. It has four tabs:

- **Login.** Pick a demo-realm client and start a login. `NativeLoginScreen` from the `ui` module renders whatever the server asks for: username, password, TOTP, push with number matching, email code, passkey, the required actions, and the browser fallback. A `push_enrollment` challenge registers the FCM token when the build has a Firebase config.
- **Home.** The access token's claims, plus the session actions:
  - Transfer: the step-up demo API, which asks for acr 2 and opens a step-up flow on the Login tab.
  - Refresh tokens.
  - Register a passkey.
  - End session on the server (S8).
  - Log out.
- **Push.** Enroll this device (with FCM when configured, else `none`), the sign-in requests (`PushApprovalsScreen` with number matching), key rotation, the lockout button, and forgetting the local enrollment. A foreground FCM message opens this tab on its request; a tapped notification does the same. The list is read again whenever the app resumes, because a backgrounded app does not see FCM data until the notification is tapped.
- **Diagnostics.** The server metadata, the DPoP key thumbprint, and the redacted request/response log.

The SDK instances use the `android` module's platform pieces:

| Piece | Used for |
|---|---|
| `KeystoreSecureStore` | One store per client |
| `KeystoreDPoPKeys` | DPoP keys in the Keystore |
| `CredentialManagerPasskeyPlatform` | Passkeys |
| `CredentialManagerSavedPasswordPlatform` | Saved passwords |
| `AuthTabWebPresenter` with `NativeAuthRedirectActivity` | The browser fallback, on `demoapp://auth/callback` |

## 1. Run it against the compose stack

```bash
cd keycloak-native-auth && mvn -DskipTests -DskipITs package
cd demo && RS_EXTRA_ISSUERS=",http://10.0.2.2:8080/realms/demo" docker compose up --wait
cd ../../android && ./gradlew :demo:installDebug     # an emulator or device must be attached
```

The emulator reaches the host's `localhost` as `10.0.2.2`, so the app's issuer is `http://10.0.2.2:8080/realms/demo` and the tokens carry that issuer. `RS_EXTRA_ISSUERS` lets the step-up demo API accept them. Plain HTTP is allowed for `10.0.2.2` and `localhost` in debug builds only (`src/debug/res/xml/network_security_config.xml`).

Settings are Gradle properties, read at build time (`-Pdemo.<name>=…` or `~/.gradle/gradle.properties`):

| Property | Default |
|---|---|
| `demo.issuer` | `http://10.0.2.2:8080/realms/demo` (use `…:8089/…` if compose runs with `KC_PORT=8089`) |
| `demo.clientId`, `demo.passkeyClientId`, `demo.stepUpClientId`, `demo.otpClientId` | `demo-ios`, `demo-ios-passkey`, `demo-ios-stepup`, `demo-ios-otp` (the realm's native clients; they register `demoapp://auth/callback`) |
| `demo.resourceServer` | `http://10.0.2.2:8091` |
| `demo.allowRpIdMismatch` | `false` |
| `demo.deviceName` | `KeycloakNativeDemo Android` |
| `demo.googleServicesJson` (or `DEMO_GOOGLE_SERVICES_JSON`) | `~/.config/native-apps/google-services.json` |

Logins to try:

- **Standard:** alice / alice-password with the TOTP from `keycloak-native-auth/demo/scripts/walkthrough.sh`, or bob / bob-password, who has no second factor.
- **Required actions:** carol (update password), grace (email code in mailpit at `http://localhost:8025`), hank (terms), ivy (recovery code `IVY1-IVY1-IVY1`), and judy (push enrollment during sign-in).
- **Browser fallback:** frank, who has to update his profile in the browser.
- **Step-up:** sign in with the Step-up client's password, then Home → Transfer.

## 2. Push MFA over FCM

Push works without Firebase: the device enrolls as `none` and reads its requests on the Push tab. For real notifications:

1. **Firebase project with the app.** Register an Android app with package `io.phasetwo.keycloak.nativedemo` and save its `google-services.json` as `~/.config/native-apps/google-services.json`. When that file exists, the build copies it into `android/demo/` (git-ignored) and applies the google-services plugin. Without it, the plugin is skipped, `BuildConfig.FIREBASE_CONFIGURED` is false, and the app enrolls without delivery. Build without it on purpose with `-Pdemo.googleServicesJson=/nonexistent`.
2. **Service account for Keycloak's `fcm` sender.** In the Firebase console, go to Project settings → Service accounts → Generate new private key. Save it as `~/.config/native-apps/fcm-service-account.json`, and never commit it.
3. **Compose with the FCM override.** `docker-compose.fcm.yml` sets the sender's send URL and mounts the key read-only as `GOOGLE_APPLICATION_CREDENTIALS`:
   ```bash
   cd keycloak-native-auth/demo
   FCM_PROJECT_ID=<project id> RS_EXTRA_ISSUERS=",http://10.0.2.2:8080/realms/demo" \
     docker compose -f docker-compose.yml -f docker-compose.fcm.yml up --wait
   ```
   `FCM_SERVICE_ACCOUNT=<path>` points at a key elsewhere.
4. **Emulator.** Use a Google Play image signed in to a Google account. Allow notifications when the app asks (Android 13+).
5. **Try it.** Sign in as alice, then Push → Enroll this device (`pushProviderType` `fcm` with the registration token). Then do either of these:
   - Sign in as alice in a browser on the host (`http://localhost:8080/realms/demo/account`).
   - Start a second native login as alice and choose push.

   The notification arrives, and tapping it opens the request; with number matching, pick the number the other side shows. A new registration token (`onRegistered`, or `onNewToken` on older paths) goes to the server through `onNewFcmToken`.

## 3. Real passkeys and saved passwords: HTTPS host + Digital Asset Links

Credential Manager needs an RP ID that is a real HTTPS domain and that lists the app in its Digital Asset Links. The compose stack is plain HTTP, so put it behind a tunnel with a fixed hostname, as for iOS (`ios/KeycloakNativeDemo/README.md` §2):

1. **Tunnel.** For example `cloudflared tunnel --hostname kc-demo.example.com --url http://localhost:8080`. Keycloak must see the public host, through `KC_HOSTNAME_STRICT=false` and the forwarded headers.
2. **Asset links.** The RP ID host serves `https://<host>/.well-known/assetlinks.json`, through a small proxy in front of Keycloak (Caddy, nginx). It lists `delegate_permission/common.handle_all_urls` and `delegate_permission/common.get_login_creds` for `io.phasetwo.keycloak.nativedemo`, with the SHA-256 fingerprint of the signing certificate. For debug builds that's the debug keystore's fingerprint: `keytool -list -v -keystore ~/.android/debug.keystore -storepass android`.
3. **Realm.** In the WebAuthn Passwordless policy, set Relying party ID to `<host>`, and add the app's origin `android:apk-key-hash:<base64url of the same SHA-256>` to the extra origins. Send the whole policy, because a partial update is ignored (keycloak-native-auth/README.md, Passwordless policy).
4. **App.** Build with `-Pdemo.issuer=https://<host>/realms/demo`. Sign in with alice, then Home → Register a passkey. Then log in again with the Passkey first client.

The same `assetlinks.json` (`get_login_creds`) lets Google Password Manager and third-party managers offer and save the site's passwords in the app.

## Notes

- The app is a demo: no settings screen, no release signing, and plain HTTP in debug builds only.
- Push belongs to the standard client's SDK instance, as in the iOS demo, so the device API needs a login with that client.
- CI builds the app (`:demo:assembleDebug`) but runs nothing on a device.
