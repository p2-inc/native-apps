package io.phasetwo.keycloak.nativedemo

import android.app.Activity
import android.content.Context
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerPasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerSavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreSecureStore
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.push.Push
import io.phasetwo.keycloak.nativeauth.sdk.push.PushEnrollment
import io.phasetwo.keycloak.nativeauth.sdk.push.PushProviderRegistration
import io.phasetwo.keycloak.nativeauth.sdk.push.fcm.FcmPush
import io.phasetwo.keycloak.nativeauth.sdk.push.fcm.enrollWithFcm
import io.phasetwo.keycloak.nativeauth.sdk.push.fcm.onNewFcmToken
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowLogEntry
import io.phasetwo.keycloak.nativeauth.sdk.ui.NativeLoginResult
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.net.HttpURLConnection
import java.net.URI
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Which demo-realm client (and so which flow) a login uses; the Android counterpart of the iOS scenarios. */
enum class DemoClient(val title: String, val description: String) {
  STANDARD("Standard (S3)", "Username, password, then TOTP or push: alice / alice-password; bob / bob-password has no second factor."),
  PASSKEY("Passkey first (S2)", "A discoverable passkey, or username and password. Needs an https RP ID (README)."),
  STEP_UP("Step-up (S6)", "Password for acr 1; Home → Transfer asks for acr 2 (TOTP)."),
  OTP("Email code (S4)", "bob / bob-password gets an email code; read it in mailpit on the host (http://localhost:8025)."),
}

enum class DemoTab { LOGIN, HOME, PUSH, DIAGNOSTICS }

/**
 * The demo's state and actions, the counterpart of the iOS `DemoModel`: one SDK instance per client,
 * built from the `android` module's platform pieces; logins through `NativeLoginScreen`; the session
 * actions on Home; push MFA for the standard client; and the redacted flow log.
 */
class DemoModel(
  context: Context,
  val config: DemoConfig,
  private val currentActivity: () -> Activity?,
  private val webPresenter: WebAuthenticationPresenter,
) {
  data class State(
    val tab: DemoTab = DemoTab.LOGIN,
    val client: DemoClient = DemoClient.STANDARD,
    /** The flow `NativeLoginScreen` drives; a new one per login or step-up. */
    val flow: NativeLoginFlow? = null,
    val flowClient: DemoClient = DemoClient.STANDARD,
    val credentials: Credentials? = null,
    val signedInClient: DemoClient? = null,
    val status: String = "Pick a client, then start a login.",
    val isBusy: Boolean = false,
    val resourceResult: String? = null,
    val enrollment: PushEnrollment? = null,
    /** The approval a notification pointed at; shown first. */
    val approvalsFocus: String? = null,
    /** Bumped to make the approvals list read the server again (resume, a message). */
    val approvalsTick: Int = 0,
    val metadataSummary: String? = null,
    val dpopThumbprint: String? = null,
  )

  private val appContext = context.applicationContext
  private val scope = MainScope()
  private val mutableState = MutableStateFlow(State())
  val state: StateFlow<State> = mutableState.asStateFlow()

  private val mutableLog = MutableStateFlow<List<FlowLogEntry>>(emptyList())
  val flowLog: StateFlow<List<FlowLogEntry>> = mutableLog.asStateFlow()

  private val sdks = mutableMapOf<String, KeycloakNative>()
  private val hardwareKeys = KeystoreDPoPKeys(appContext)
  private val passkeyPlatform = CredentialManagerPasskeyPlatform(appContext, currentActivity)
  private val savedPasswordPlatform = CredentialManagerSavedPasswordPlatform(appContext, currentActivity)

  fun clientId(client: DemoClient): String = when (client) {
    DemoClient.STANDARD -> config.clientId
    DemoClient.PASSKEY -> config.passkeyClientId
    DemoClient.STEP_UP -> config.stepUpClientId
    DemoClient.OTP -> config.otpClientId
  }

  @Synchronized
  fun sdk(client: DemoClient): KeycloakNative = sdks.getOrPut(clientId(client)) {
    KeycloakNative.configure(
      config.issuer,
      clientId(client),
      KeycloakNative.Options(
        hardwareKeys = hardwareKeys,
        allowRpIdMismatch = config.allowRpIdMismatch,
        logger = LogcatLogger,
        flowObserver = { entry -> mutableLog.update { (it + entry).takeLast(200) } },
        secureStore = KeystoreSecureStore(appContext, namespace = clientId(client)),
        passkeyPlatform = passkeyPlatform,
        savedPasswordPlatform = savedPasswordPlatform,
        webPresenter = webPresenter,
      ),
    )
  }

  /** Push MFA belongs to the standard client's instance (its DPoP key is the device key), as on iOS. */
  val push: Push by lazy { sdk(DemoClient.STANDARD).push() }

  /** For `NativeLoginScreen`: a `push_enrollment` challenge registers the FCM token when Firebase is set up. */
  val pushRegistration: (suspend () -> PushProviderRegistration)? =
    if (config.firebaseConfigured) ({ FcmPush.registration() }) else null

  init {
    scope.launch {
      // Credentials stored by an earlier launch (KeystoreSecureStore), newest client first.
      for (client in DemoClient.entries) {
        val stored = runCatching { sdk(client).credentialsManager().stored() }.getOrNull() ?: continue
        mutableState.update { it.copy(credentials = stored, signedInClient = client, tab = DemoTab.HOME, status = "Restored the stored login (${client.title}).") }
        break
      }
      refreshEnrollment()
    }
  }

  fun select(tab: DemoTab) = mutableState.update { it.copy(tab = tab) }

  fun select(client: DemoClient) = mutableState.update { it.copy(client = client, flow = null) }

  // Login

  fun startLogin() {
    val client = state.value.client
    val flow = sdk(client).authentication().startLogin(LoginParameters(scope = "openid profile", deviceName = config.deviceName))
    mutableState.update { it.copy(flow = flow, flowClient = client, tab = DemoTab.LOGIN, status = "Login with ${clientId(client)}…") }
  }

  fun finish(result: NativeLoginResult) {
    val client = state.value.flowClient
    when (result) {
      is NativeLoginResult.Authorized -> run("Storing the tokens") {
        sdk(client).credentialsManager().store(result.credentials)
        val claims = result.credentials.accessTokenClaims
        mutableState.update {
          it.copy(
            flow = null, credentials = result.credentials, signedInClient = client, tab = DemoTab.HOME,
            status = "Signed in as ${claims["preferred_username"].stringValue ?: "?"} (token_type ${result.credentials.tokenType}, acr ${claims["acr"].stringValue ?: "-"})",
          )
        }
        refreshEnrollment()
      }
      NativeLoginResult.Cancelled -> mutableState.update { it.copy(flow = null, status = "Login cancelled.") }
      is NativeLoginResult.Failed -> mutableState.update { it.copy(flow = null, status = "${result.error.code}: ${result.error.errorDescription.orEmpty()}") }
    }
  }

  // Home (spec/06 S6, S8)

  /** S6: `GET /transfer`; on `401 insufficient_user_authentication` a step-up flow opens on the Login tab. */
  fun transfer() {
    val credentials = state.value.credentials ?: return
    val client = state.value.signedInClient ?: return
    run("GET /transfer") {
      val kc = sdk(client)
      val url = URI("${config.resourceServer.toString().trimEnd('/')}/transfer")
      val headers = kc.resourceRequestHeaders(credentials, "GET", url)
      val (code, body) = withContext(Dispatchers.IO) {
        val connection = url.toURL().openConnection() as HttpURLConnection
        headers.forEach(connection::setRequestProperty)
        val code = connection.responseCode
        val stream = if (code >= 400) connection.errorStream else connection.inputStream
        code to (stream?.bufferedReader()?.use { it.readText() } ?: "")
      }
      mutableState.update { it.copy(resourceResult = "HTTP $code: $body") }
      val json = parseJsonOrNull(body)
      if (code == 401 && json["error"].stringValue == "insufficient_user_authentication") {
        val acr = json["acr_values"].stringValue ?: "2"
        val flow = kc.authentication().stepUp(acrValues = acr, scope = "openid profile", deviceName = config.deviceName)
        mutableState.update { it.copy(flow = flow, flowClient = client, tab = DemoTab.LOGIN, status = "Stepping up to acr $acr with the stored auth_session…") }
      } else {
        mutableState.update { it.copy(status = if (code == 200) "Transfer accepted (acr satisfied)." else "Transfer answered HTTP $code.") }
      }
    }
  }

  /** Forces a refresh by marking the stored access token expired. */
  fun refreshTokens() = withSession("Refreshing tokens") { kc, _ ->
    val manager = kc.credentialsManager()
    manager.stored()?.let { manager.store(it.copy(expiresAt = Instant.EPOCH)) }
    try {
      val fresh = manager.credentials()
      mutableState.update { it.copy(credentials = fresh, status = "Tokens refreshed.") }
    } catch (e: NativeAuthError) {
      if (e.code != NativeAuthError.Code.REAUTHENTICATION_REQUIRED) throw e
      // S8: Keycloak answers invalid_grant without an auth_session, so log in again.
      mutableState.update { it.copy(credentials = null, signedInClient = null, status = "reauthentication_required: the session is gone. Start a new login.") }
    }
  }

  /** S8: revokes the refresh token on the server only; the next refresh is refused. */
  fun endSessionOnServer() = withSession("Revoking the refresh token on the server") { kc, credentials ->
    val refreshToken = credentials.refreshToken ?: return@withSession
    kc.tokens().revoke(refreshToken)
    mutableState.update { it.copy(status = "Session ended on the server; the stored tokens are now stale. Try Refresh tokens.") }
  }

  /** Registers a passkey for the signed-in user (spec/03 §6). Needs an https RP ID the app is linked to. */
  fun registerPasskey() = withSession("Registering a passkey") { kc, credentials ->
    val registered = kc.passkeys().registerNewPasskey(label = "Android demo", credentials = credentials)
    mutableState.update { it.copy(status = "Passkey registered: ${registered.label ?: registered.credentialId}") }
  }

  fun logout() = withSession("Logging out") { kc, _ ->
    kc.credentialsManager().logout()
    mutableState.update {
      it.copy(credentials = null, signedInClient = null, resourceResult = null, tab = DemoTab.LOGIN,
        status = "Logged out." + if (it.enrollment != null) " The push enrollment stays; approvals need a login again." else "")
    }
  }

  // Push (spec/03 §7)

  fun enrollPush() = run("Enrolling this device for push") {
    val label = config.deviceName
    val enrollment = if (config.firebaseConfigured) push.enrollWithFcm(label) else push.enroll(label)
    mutableState.update { it.copy(enrollment = enrollment, status = "Enrolled for push (${enrollment.pushProviderType}).") }
  }

  fun rotatePushKey() = run("Rotating the device key") {
    push.rotateKey()
    refreshEnrollment()
    mutableState.update { it.copy(credentials = null, signedInClient = null, status = "Device key rotated; sign in again to bind new tokens to it.") }
  }

  fun lockout() = run("Locking the account") {
    push.lockout()
    mutableState.update { it.copy(status = "Account locked out; an admin re-enables it.") }
  }

  fun forgetPush() = run("Forgetting the local enrollment") {
    push.forgetEnrollment()
    mutableState.update { it.copy(enrollment = null, status = "Local push enrollment removed (the server credential stays).") }
  }

  fun noteApproval(cid: String, status: String) = mutableState.update { it.copy(status = "Sign-in request $cid: $status") }

  /** `FirebaseMessagingService.onNewToken`. */
  fun onNewFcmToken(token: String) = scope.launch {
    runCatching { push.onNewFcmToken(token) }.onFailure { e -> LogcatLogger.log(io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel.WARNING) { "FCM token update failed: $e" } }
    refreshEnrollment()
  }

  /** A push-MFA message (foreground `onMessageReceived`, or the extras of a tapped notification). */
  fun messageReceived(data: Map<String, String>) = scope.launch {
    val payload = runCatching { push.handleMessage(data) }.getOrNull() ?: return@launch
    mutableState.update { it.copy(tab = DemoTab.PUSH, approvalsFocus = payload.cid, approvalsTick = it.approvalsTick + 1) }
  }

  /** On resume: a backgrounded app sees FCM data only when the user taps, so read the pending list again. */
  fun onResume() = mutableState.update { if (it.enrollment != null && it.credentials != null) it.copy(approvalsTick = it.approvalsTick + 1) else it }

  // Diagnostics

  fun loadDiagnostics() = run("Loading metadata") {
    val kc = sdk(state.value.signedInClient ?: state.value.client)
    val metadata = kc.metadata(forceRefresh = true)
    val summary = buildString {
      appendLine("issuer: ${kc.issuer}")
      appendLine("client: ${kc.clientId}")
      appendLine("protocol_version: ${metadata.protocolVersion}")
      appendLine("challenge types: ${metadata.challengeTypesSupported.joinToString()}")
      metadata.push?.let { appendLine("push: device_token ${it.deviceToken}, senders ${it.pushProviderTypes.joinToString()}") }
      append("Firebase configured in this build: ${config.firebaseConfigured}")
    }
    mutableState.update { it.copy(metadataSummary = summary, dpopThumbprint = kc.dpopKeyThumbprint()) }
  }

  fun clearLog() = mutableLog.update { emptyList() }

  // Helpers

  private suspend fun refreshEnrollment() {
    val enrollment = runCatching { push.enrollment() }.getOrNull()
    mutableState.update { it.copy(enrollment = enrollment) }
  }

  private fun withSession(what: String, body: suspend (KeycloakNative, Credentials) -> Unit) {
    val client = state.value.signedInClient ?: return
    val credentials = state.value.credentials ?: return
    run(what) { body(sdk(client), credentials) }
  }

  private fun run(what: String, body: suspend () -> Unit) {
    scope.launch {
      mutableState.update { it.copy(isBusy = true, status = "$what…") }
      try {
        body()
      } catch (e: CancellationException) {
        throw e
      } catch (e: NativeAuthError) {
        mutableState.update { it.copy(status = "${e.code}: ${e.errorDescription.orEmpty()}") }
      } catch (e: Exception) {
        mutableState.update { it.copy(status = "Unexpected: $e") }
      } finally {
        mutableState.update { it.copy(isBusy = false) }
      }
    }
  }
}
