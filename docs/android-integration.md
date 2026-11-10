# Integrating the Android SDK

[Index](README.md) · [Protocol](protocol-and-flows.md) · [iOS integration](ios-integration.md) · [Android demo](../android/demo/README.md)

## Installation and configuration

The [Gradle build](../android/settings.gradle.kts) has four library modules. `core` is plain Kotlin/JVM (coroutines, kotlinx.serialization): the challenge state machine, PKCE, DPoP, tokens and credentials, passkey and saved-password models, and the push protocol. `android` adds the platform pieces: `KeystoreSecureStore`, `KeystoreDPoPKeys`, `CredentialManagerPasskeyPlatform`, `CredentialManagerSavedPasswordPlatform` and `AuthTabWebPresenter`. `ui` holds the default Jetpack Compose (Material 3) screens and `PushApprovalsScreen`. `push` adds Firebase Cloud Messaging. The Android modules need minSdk 28 (Android 9); they are built against SDK 37 and apps compile against them with compileSdk 36 or later (the floor their AndroidX dependencies set). The libraries target Java 17 bytecode.

From 0.3.0 the four modules are on Maven Central under the group `io.phasetwo.keycloak.nativeauth`, so `mavenCentral()` is the only repository you need:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
  repositories {
    google()
    mavenCentral()
  }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
  implementation("io.phasetwo.keycloak.nativeauth:keycloak-native-android:0.3.0")
  implementation("io.phasetwo.keycloak.nativeauth:keycloak-native-ui:0.3.0")    // default Compose screens
  implementation("io.phasetwo.keycloak.nativeauth:keycloak-native-push:0.3.0")  // push MFA over FCM
}
```

`keycloak-native-core` comes in transitively. Each [GitHub release](../README.md#releases) also carries `keycloak-native-android-<version>-maven-repo.zip`, the same artifacts as a Maven repository you can unzip and add with `maven { url = uri(...) }`; 0.2.0 is only available that way. Before 1.0 any release may change the API, so pin exact versions. The SDKs and the server share one version line (see [Releases](../README.md#releases)).

### Kotlin version

Your app needs Kotlin 2.2 or later. A Kotlin compiler reads class metadata written by its own version and the next one, so a library built with a newer Kotlin can be unusable from an older app ("Module was compiled with an incompatible version of Kotlin"). The SDK is built with Kotlin 2.4 but compiles its four libraries at language and API level 2.2 and declares `kotlin-stdlib` 2.2.20, so they carry 2.2 metadata and use only the 2.2 standard library. The floor of 2.2 comes from the dependencies the libraries expose: kotlinx.serialization 1.11 is built with Kotlin 2.3 (and pulls `kotlin-stdlib` 2.3.20 into your build), which a 2.2 compiler can read and a 2.1 compiler cannot. kotlinx.serialization 1.12 and later are built with Kotlin 2.4; if your app adds one of them, it needs Kotlin 2.3 or later itself. Kotlin 2.2 is React Native 0.88's default, so cross-platform wrappers can depend on the SDK without making their apps raise Kotlin. The `ui` module additionally needs the Compose compiler plugin matching your Kotlin version, as every Compose library does.

Configure a public Keycloak client using the [server setup](README.md#practical-quick-start). Use the **issuer URL including `/realms/<realm>`**, not the challenge endpoint; the client ID is separate. PKCE S256 must be required on the client. Register a callback such as `demoapp://auth/callback` for browser fallback; native success itself does not redirect. Use HTTPS outside the local demo; debug builds of the demo allow plain HTTP only to `10.0.2.2` and `localhost` through a network security config. Keep one SDK instance per issuer/client so credentials, DPoP key, metadata cache and refresh coordination remain consistent.

`KeycloakNative.Options` is immutable and passed to `configure`, but the platform pieces need an activity: Credential Manager shows its sheets over the activity on screen, and `AuthTabWebPresenter` registers an activity result launcher, which must happen in the activity's `onCreate`. The usual shape, which the [demo app](../android/demo/src/main/kotlin/io/phasetwo/keycloak/nativedemo/DemoApplication.kt) follows, is an SDK instance on the `Application` whose platforms look the current activity up when they need it:

```kotlin
import android.app.Activity
import android.app.Application
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.android.AuthTabWebPresenter
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerPasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerSavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreSecureStore
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.lang.ref.WeakReference
import java.net.URI

class ExampleApp : Application() {
  /** Set from ActivityLifecycleCallbacks (onActivityResumed / onActivityPaused). */
  @Volatile var currentActivity: WeakReference<Activity> = WeakReference(null)

  /** Set in MainActivity.onCreate. */
  @Volatile var authTab: AuthTabWebPresenter? = null

  val kc: KeycloakNative by lazy {
    KeycloakNative.configure(
      URI("https://idp.example.com/realms/demo"),
      "demo-native",
      KeycloakNative.Options(
        hardwareKeys = KeystoreDPoPKeys(this),
        secureStore = KeystoreSecureStore(this, namespace = "demo-native"),
        passkeyPlatform = CredentialManagerPasskeyPlatform(this) { currentActivity.get() },
        savedPasswordPlatform = CredentialManagerSavedPasswordPlatform(this) { currentActivity.get() },
        webPresenter = WebAuthenticationPresenter { url, redirectUri ->
          val presenter = authTab
            ?: throw NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_FAILED, errorDescription = "No activity to open the browser from")
          presenter.authenticate(url, redirectUri)
        },
      ),
    )
  }
}
```

and in the activity, before it starts:

```kotlin
class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    (application as ExampleApp).authTab = AuthTabWebPresenter(this)
    setContent { LoginScreen((application as ExampleApp).kc) }
  }
}
```

Single-activity apps can use the one-argument constructors, `CredentialManagerPasskeyPlatform(activity)` and `CredentialManagerSavedPasswordPlatform(activity)`, which hold the activity weakly.

[Options](../android/core/src/main/kotlin/io/phasetwo/keycloak/nativeauth/sdk/KeycloakNative.kt) defaults: `dpop = DPoPMode.AUTOMATIC`, `allowRpIdMismatch = false`, metadata cache TTL 5 minutes, `NoopLogger`, no platforms. Options also accept a transport, a flow observer (redacted request/response entries, for a diagnostics screen), a separate `credentialsStore` and a logger. Without `secureStore` the SDK keeps credentials and the DPoP key in memory and logs a warning; use `InMemorySecureStore` only in tests and previews. `AUTOMATIC` DPoP uses `KeystoreDPoPKeys` (a P-256 signing key in the Android Keystore, in StrongBox when the device has one, whose private key never leaves the secure hardware) when `hardwareKeys` is set and the device supports it, and a software key otherwise; `DPoPMode.HARDWARE` requires the Keystore key and fails with `dpop_key_error` without it. Keep the key available for the life of bound credentials and push enrollment.

`KeystoreSecureStore` seals each item with an AES-256-GCM key from the Android Keystore and writes it to `noBackupFilesDir`, so items never reach a backup or another device. An item that can no longer be opened (the Keystore key was invalidated or replaced) is deleted and reads as absent, which sends the user through a fresh login. Give each SDK instance its own `namespace`.

### Browser fallback callback

`AuthTabWebPresenter` uses an [Auth Tab](https://developer.chrome.com/docs/android/custom-tabs/guide-auth-tab) when the default browser supports one, which hands the callback straight back for a custom scheme or a verified `https` App Link. Otherwise it opens a Custom Tab, and the callback arrives through `NativeAuthRedirectActivity`, which the app declares with an intent filter for its `redirect_uri`:

```xml
<activity
  android:name="io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity"
  android:exported="true"
  android:theme="@android:style/Theme.Translucent.NoTitleBar">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="demoapp" android:host="auth" android:path="/callback" />
  </intent-filter>
</activity>
```

The library's manifest already adds the `INTERNET` permission and the `<queries>` entry that finds browsers offering Custom Tabs. `AuthTabWebPresenter(activity, ephemeral = true)` asks the browser for a session that shares no cookies with normal browsing. Closing the browser is `web_fallback_cancelled`; no browser, an App Link that fails verification or a second concurrent call is `web_fallback_failed`.

## Minimal working Compose integration

This screen uses the `ui` module and explicitly persists successful credentials. Create a new flow for each login attempt; pass an **unstarted** flow to `NativeLoginScreen`, which starts it when it enters the composition. Keep it in the composition while a result is being persisted. The application decides navigation after `signedIn` changes.

```kotlin
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.ui.NativeLoginResult
import io.phasetwo.keycloak.nativeauth.sdk.ui.NativeLoginScreen
import kotlinx.coroutines.launch

@Composable
fun LoginScreen(kc: KeycloakNative) {
  val scope = rememberCoroutineScope()
  var flow by remember { mutableStateOf<NativeLoginFlow?>(null) }
  var signedIn by remember { mutableStateOf(false) }
  var message by remember { mutableStateOf<String?>(null) }

  Column {
    val current = flow
    when {
      signedIn -> Text("Signed in")
      current != null -> NativeLoginScreen(kc, current, onResult = { result ->
        when (result) {
          is NativeLoginResult.Authorized -> scope.launch {
            try {
              kc.credentialsManager().store(result.credentials)
              signedIn = true
            } catch (e: NativeAuthError) {
              message = e.code
            }
            flow = null
          }
          NativeLoginResult.Cancelled -> flow = null
          is NativeLoginResult.Failed -> {
            message = result.error.code
            flow = null
          }
        }
      })
      else -> Button(onClick = {
        message = null
        flow = kc.authentication().startLogin(LoginParameters(scope = "openid profile", deviceName = "Example Pixel"))
      }) { Text("Sign in") }
    }
    message?.let { Text(it) }
  }
}
```

The default screens handle all implemented challenge types, alternatives ("Try another way"), descriptor errors, resend countdowns, passkey ceremonies, push polling and enrollment, and the browser fallback. `NativeLoginScreen` returns `NativeLoginResult.Authorized`, `Cancelled` or `Failed`. It does not store credentials or own your application session or navigation. Its other parameters: `presenters`, `chooser`, `header` (shown above every screen, for a logo), `autoSelectPasskey` (run the passkey prompt as soon as a set contains `passkey`), `offerSavedPasswords`, `offerToSavePassword` and `pushRegistration` (see [Push integration](#push-integration)). Strings come from the module's resources, in English and German, and follow the app's locale. See [NativeLoginScreen](../android/ui/src/main/kotlin/io/phasetwo/keycloak/nativeauth/sdk/ui/NativeLoginScreen.kt) and [NativeLoginModel](../android/ui/src/main/kotlin/io/phasetwo/keycloak/nativeauth/sdk/ui/NativeLoginModel.kt).

## Driving custom native screens

`core` exposes suspend functions; there is no callback or `Flow` facade for the login. `NativeLoginFlow` is safe to call from any thread, but serialize submissions in your UI: a second `respond` while the first is suspended answers a challenge set that is about to be replaced.

```kotlin
val flow = kc.authentication().startLogin(LoginParameters(scope = "openid profile", deviceName = "Example Pixel"))
val firstStep = flow.start()
```

`startLogin` creates a fresh PKCE pair but sends nothing until `start()`. Retain `flow` and the latest `FlowStep` in your view model:

| `FlowStep` | Application responsibility |
| --- | --- |
| `Challenges(challenges, context)` | Render the choices in server order; `supportedChallenges` filters out types this SDK cannot answer. Collect one response and replace the entire step with its result. A descriptor `error` is inline feedback, not a thrown terminal error. |
| `Authorized(credentials)` | Code exchange already succeeded. Explicitly store credentials, clear credential input fields and move to signed-in UI. |
| `RedirectToWeb(request)` | Offer the system browser, keeping the original flow and PKCE; call `kc.webFallback().complete(request, flow)` and persist the returned credentials. If browser use is unacceptable, end the attempt. |

For example, after a username screen collected `enteredUsername` for its `Challenge`:

```kotlin
val nextStep = flow.respond(ChallengeAnswer.Username(enteredUsername), challenge)
```

Note the argument order: the answer first, then the challenge it answers. Do not manufacture challenge IDs, select challenges from an old set, loop over all alternatives, or call `start()` twice on one flow. Use `flow.pendingChallenges`, `authSession`, `expiresIn` and `currentState` for state inspection; keep the session value private. States are `IDLE` → `AWAITING_ANSWER` → `FINISHED`. The SDK retains continuation state and validates the pending type, ID and answer type before sending. Store an app-generated stable device ID in app configuration if you choose to supply `LoginParameters.deviceId`; the SDK does not generate one.

| `challenge.type` / typed params | Submit via `flow.respond(answer, challenge)` |
| --- | --- |
| `ChallengeType.Username` / `usernameParams` | `ChallengeAnswer.Username(input)` |
| `ChallengeType.Password` / `passwordParams` | `ChallengeAnswer.Password(input)` |
| `ChallengeType.Totp` / `totpParams` | `ChallengeAnswer.Totp(input, credentialId = selectedId)` (ID optional) |
| `ChallengeType.Otp` / `otpParams` | `ChallengeAnswer.Otp(input)` or `ChallengeAnswer.OtpResend`; use `sent` / `resendWait()` to render controls |
| `ChallengeType.RecoveryCode` / `recoveryCodeParams` | `ChallengeAnswer.RecoveryCode(input)`; warn from `shouldWarn` |
| `ChallengeType.Passkey` / `passkeyParams` | `val assertion = kc.passkeys().assert(params)` then `ChallengeAnswer.Passkey(assertion)` |
| `ChallengeType.PasskeyRegistration` / `passkeyRegistrationParams` | `val attestation = kc.passkeys().register(params)` then `ChallengeAnswer.PasskeyRegistration(attestation, label)` |
| `ChallengeType.UpdatePassword` / `updatePasswordParams` | `ChallengeAnswer.UpdatePassword(input, confirm = confirmation)`; policy hints do not replace server validation |
| `ChallengeType.VerifyEmail` / `verifyEmailParams` | `ChallengeAnswer.VerifyEmail(input)` or `ChallengeAnswer.VerifyEmailResend` |
| `ChallengeType.Terms` / `termsParams` | `ChallengeAnswer.Terms(accepted = decision)` |
| `ChallengeType.Push` / `pushParams` | `ChallengeAnswer.PushResend`, then `ChallengeAnswer.PushPoll` every `pollInterval` seconds while pending; display the number-match number |
| `ChallengeType.PushEnrollment` / `pushEnrollmentParams` | Prepare the enrollment with `kc.push()`, respond with `prepared.answer`, and commit locally only after the server accepts it |
| any required action with `isSkippable` | `ChallengeAnswer.Skip(challenge.type)` declines it for this login ("Not now"); the default passkey-registration screen shows the button |
| extension or otherwise unmodeled answer | `ChallengeAnswer.Custom(challenge.type, listOf(FormField("name", "value")))`, sent through the normal pipeline (DPoP, nonce retry, `auth_session` rotation, code exchange) |

Extra request fields (spec/03 §2.3), e.g. a device or risk signal from another SDK: `LoginParameters.additionalParameters` go on the initial request, `continuationParameters` on every continuation, and the `additionalFields` map of `flow.respond(answer, challenge, additionalFields)` adds fields to one request. Use the reserved `x_` prefix; names the protocol or the answer already uses are refused with `invalid_parameter`. `x_*` values are masked in logs and the flow log; other `Custom` field values are masked only when their name is in `Redactor.sensitiveKeys`.

`Challenge` has `id`, `type`, `label`, `required`, `error`, `retry`, `isSkippable`, the typed views above and the raw `params`. [ChallengeModels](../android/core/src/main/kotlin/io/phasetwo/keycloak/nativeauth/sdk/challenge/ChallengeModels.kt) defines these and the form encoding. Unknown types remain `ChallengeType.Unknown`; choose another supported alternative or surface unsupported-method guidance. `ChallengeType.Select` is recognized but unsupported.

To replace one default screen, pass `presenters = mapOf(ChallengeType.Totp to { context -> MyTotpScreen(context) })`. Your composable receives a `ChallengePresentationContext` with the current `challenge`, the set (`challenges`, `alternatives`), `flowContext`, `isSubmitting`, `isStepUp`, `submit(answer)`, `switchTo(other)`, `usePasskey()`, `registerPasskey(label)`, `enrollPush(deviceLabel)`, `useSavedPassword()` and `cancel()`. To replace the "Try another way" list, pass `chooser`; its `ChallengeChooserContext` has `current`, `alternatives` and `select(challenge)`.

### Password managers

Credential Manager covers Google Password Manager and third-party providers such as 1Password or Bitwarden. Two things make it work well:

- **Association.** Serve `https://<rp_id>/.well-known/assetlinks.json` granting your app `delegate_permission/common.get_login_creds`, the same statement passkeys need (see [passkeys](#passkeys)). Then passwords saved by the website appear in the app's sheet, and passwords saved from the app are offered on the website.
- **Autofill hints.** The default screens set Compose `ContentType` on every field: `Username` on the username field, `Password` on the password field, `NewPassword` on both update-password fields, and `SmsOtpCode` or `EmailOtpCode` on the one-time-code fields. Custom screens must do the same.
- **Two-step login.** Keycloak asks for the username and the password on separate screens, and autofill services pair a password with a username field on the same screen. The default password and update-password screens therefore repeat the username (`FlowContext.username`) in a read-only field.
- **Saved-password sheet.** `kc.pickSavedPassword()` shows Credential Manager's sheet and returns the pick; answer `ChallengeAnswer.Username(saved.username)`, then the following `password` challenge with `ChallengeAnswer.Password(saved.password)`. The default username and password screens offer it as "Use a saved password" (turn off with `NativeLoginScreen(offerSavedPasswords = false)`). Closing the sheet is `saved_password_cancelled` and leaves the flow as it was; nothing saved is `saved_password_unavailable`.
- **Saving.** Unlike iOS, the autofill framework's own save prompt is unreliable when the username and the password were typed on different screens. After a sign-in with a typed or newly set password, the default screens call `kc.savePassword(username, password)`, which shows Credential Manager's "Save password?" prompt (turn off with `offerToSavePassword = false`; a picked or rejected password is never offered). Custom screens call it themselves after `FlowStep.Authorized`.

### Passkeys

`CredentialManagerPasskeyPlatform` runs the WebAuthn ceremonies through Credential Manager. Android only lets an app use passkeys for a relying party that vouches for it: serve `https://<rp_id>/.well-known/assetlinks.json` with a `delegate_permission/common.get_login_creds` statement for your package name and signing-certificate SHA-256 fingerprint (debug and release keys differ). The RP ID comes from the server metadata and must be the issuer host or a registrable suffix of it; otherwise the SDK refuses with `rp_id_mismatch`. `allowRpIdMismatch = true` exists only for development against a tunnel. Cancellation is `passkey_cancelled` (the challenges stay available); no matching passkey, no provider or an unsupported device is `passkey_unavailable`; anything else is `passkey_failed`. A Google account and a screen lock are required on the device. The [Android demo README](../android/demo/README.md) walks through the setup.

## Tokens and application sessions

```kotlin
val manager = kc.credentialsManager()
val restored = manager.stored()
val credentials = manager.credentials(minTtl = 60.seconds)
val headers = kc.resourceRequestHeaders(credentials, "GET", URI("https://api.example.com/me"))
```

`stored()` returns possibly expired credentials or `null`. `hasValid(minTtl)` only checks expiry, not server validity. `credentials(minTtl)` refreshes when the access token is within 30 seconds plus `minTtl` of expiry, serializes concurrent refreshes and persists the result; durations are `kotlin.time.Duration`. With nothing stored it throws `credentials_not_found`; a direct `kc.tokens().refresh(credentials)` does not persist. Access, refresh and ID tokens and the post-login session live in `Credentials`; `accessTokenClaims` and `idTokenClaims` are unverified display conveniences.

Set the returned headers on your request (`Authorization: Bearer …`, or `Authorization: DPoP …` plus a `DPoP` proof when the tokens are bound), preserving the exact method and URL for DPoP. Core does not perform resource requests, validate authorization results, schedule background refresh or retry business operations.

```kotlin
val elevatedFlow = kc.authentication().stepUp(acrValues = "2")
val elevatedFirstStep = elevatedFlow.start()
```

Drive it like a login (or pass it to `NativeLoginScreen`); store its authorized credentials and retry the protected operation yourself. For an `insufficient_authorization` from a registration endpoint carrying an `auth_session` and `maxAge`, use `kc.authentication().continueAfterTokenChallenge(error)` then `flow.start()`. A refresh refused with `invalid_grant` clears stored credentials and maps to `reauthentication_required`; one refused with `insufficient_authorization` maps to `reauthentication_required` carrying an `auth_session` for `continueAfterTokenChallenge`. Start a fresh login when no session comes with it.

For post-login passkey enrollment:

```kotlin
val credentials = kc.credentialsManager().credentials()
val registered = kc.passkeys().registerNewPasskey(label = "Pixel", credentials = credentials)
```

Stale authentication needs a step-up and a fresh registration attempt; the SDK does not replay registration after the new login.

### Protected credentials

To keep tokens in a store that requires user authentication, pass it as `credentialsStore`; the DPoP key reference and push enrollment stay in `secureStore`, which the SDK reads on every signed request without user interaction. The SDK ships no biometric-gated `SecureStore` yet; implement the three-method `SecureStore` interface (`data`, `set`, `remove`) over a Keystore key that requires authentication, and surface a failed or canceled authentication as `keychain_authentication_failed`.

## Push integration

Push uses the same SDK instance and DPoP key as the stored native login: the DPoP key is the device key.

```kotlin
import io.phasetwo.keycloak.nativeauth.sdk.push.PushApprovalAction
import io.phasetwo.keycloak.nativeauth.sdk.push.fcm.enrollWithFcm

val push = kc.push()
val enrollment = push.enrollWithFcm(deviceLabel = "Pixel")   // or push.enroll("Pixel") to pull without FCM
val pending = push.pendingApprovals()
```

The `none` provider (`push.enroll(deviceLabel)`) works by fetching approvals. After explicit user approval, call `push.respond(approval, PushApprovalAction.Approve(userVerification = chosenNumber))`; use `PushApprovalAction.Deny` to reject. Never approve on receipt of a notification. Fetch on resume and pull-to-refresh, because delivery may be delayed. `PushApprovalsScreen(push, focus = cid)` from the `ui` module is the default list with number-match buttons; a wrong number keeps the card so the user can try again.

For FCM, apply the google-services Gradle plugin with your own Firebase project's `google-services.json`, ask for `POST_NOTIFICATIONS` on Android 13+, and declare a messaging service:

```kotlin
class AppMessagingService : FirebaseMessagingService() {
  private val kc get() = (application as ExampleApp).kc
  private val scope = MainScope()

  override fun onNewToken(token: String) {
    scope.launch { kc.push().onNewFcmToken(token) }
  }

  override fun onMessageReceived(message: RemoteMessage) {
    scope.launch {
      val payload = kc.push().handle(message) ?: return@launch
      val approval = kc.push().pendingApproval(payload)
      // show the approval (e.g. open PushApprovalsScreen with focus = payload.cid)
    }
  }
}
```

`onNewFcmToken` updates the server only when this device is enrolled with FCM and the token changed. Firebase Messaging 26 adds `onRegistered(token)` as the replacement for `onNewToken`; forward both, as the [demo's service](../android/demo/src/main/kotlin/io/phasetwo/keycloak/nativedemo/DemoMessagingService.kt) does. The server's `fcm` sender sends a visible `notification` plus `data.token`. Such a message reaches `onMessageReceived` only while the app is in the foreground; in the background Android shows the notification and hands the data to the launch activity's intent extras only when the user taps it, so pass the extras to `push.handleMessage(map)` there and read `pendingApprovals()` whenever the app opens. `handle` returns `null` for messages that are not push MFA or are for another credential; it does not verify the realm's JWT signature, and `pendingApproval(payload)` resolves server state.

During a `push_enrollment` challenge, `NativeLoginScreen(pushRegistration = { FcmPush.registration() })` enrolls with the FCM token; without `pushRegistration` the device enrolls as `none`. Custom screens use `push.prepareFcmEnrollment(params, deviceLabel)` (or `prepareEnrollment(params, deviceLabel)`), then `flow.respond(prepared.answer, challenge)`. If the response accepts the action (the next step is not its error rechallenge), call `push.commit(prepared)`. Preparation alone does not persist a valid enrollment. Push state is scoped by issuer and client, like credentials, not by user; account switching needs an explicit policy for forgetting and re-enrolling it.

`rotateKey()` registers a fresh key using the current proof, then commits it and clears the old bound credentials: sign in again. `forgetEnrollment()` only deletes local state; it does not remove the server credential. `lockout()` disables the server user until an administrator intervenes. `updatePushProvider(type, id)` changes the registration directly. The default `NativeDeviceTokenProvider` uses the stored native login and requires DPoP-bound tokens; `kc.push(tokenProvider = …)` takes a custom `DeviceTokenProvider`.

## Errors, retries, logout and cancellation

Catch `NativeAuthError` and compare its `code` with the constants in `NativeAuthError.Code`, not with display descriptions. It also carries `statusCode`, `errorDescription`, `authSession`, `maxAge`, `details`, `isNetworkError`, `isRetryable` and `retryAfter`. Distinguish inline descriptor errors from thrown HTTP, transport and state errors:

- `invalid_session`, `access_denied`, `invalid_client` and `server_error` finish the flow; a new attempt needs a new flow. `invalid_request` can preserve it and update the continuation session.
- `network_error` leaves the last local pending state, but the server may already have advanced. Offer a deliberate retry or restart; there is no general automatic safe replay. A failed token exchange cannot be retried through the finished flow.
- `passkey_cancelled` leaves the challenges available; the user can pick another way. `web_fallback_cancelled` follows a terminal native handoff and requires starting again.
- `rp_id_mismatch` requires a deployment or configuration correction. Do not ship `allowRpIdMismatch = true` as a workaround.
- `flow.cancel()` is a best-effort server cancellation of pending native state. Canceling a coroutine or leaving the composition is not an explicit server cancel; call it when your UI abandons the login. There is no restoration of an in-progress login across process death.
- Storage failures are `keychain_error` and authentication failures of a protected store `keychain_authentication_failed`: the codes are shared with iOS.

`manager.logout()` attempts a server logout with the stored refresh token and clears local credentials regardless of the network result. It does not remove browser SSO cookies, passkeys, push enrollment or DPoP keys, and cannot guarantee server invalidation while offline. For explicit revocation use `kc.tokens().revoke(refreshToken)` and manage local state separately. See [security](security.md).

## The demo app

[`android/demo`](../android/demo/README.md) is a working reference: one SDK instance per demo client with `KeystoreSecureStore`, `KeystoreDPoPKeys`, the Credential Manager platforms and an Auth Tab presenter that follows the current activity; `NativeLoginScreen` for every login; claims, step-up, passkey registration and logout on Home; FCM enrollment, `PushApprovalsScreen`, rotation, lockout and forget on Push; and the metadata, `jkt` and redacted flow log on Diagnostics. Its README covers running it on an emulator against the compose stack, Firebase setup, and the HTTPS host and `assetlinks.json` that passkeys and saved passwords need.
