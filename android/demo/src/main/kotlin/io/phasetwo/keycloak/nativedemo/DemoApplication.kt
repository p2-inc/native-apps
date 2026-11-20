package io.phasetwo.keycloak.nativedemo

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.util.Log
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.lang.ref.WeakReference
import java.net.URI
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Holds the [DemoModel] for the configured server and tracks the activity on screen for the
 * platform prompts. Switching servers (Settings screen) replaces the model, and with it the SDK instances.
 */
class DemoApplication : Application() {
  /** The activity on screen: Credential Manager prompts and the browser need it. */
  @Volatile
  private var current: WeakReference<Activity> = WeakReference(null)

  /** Set by `MainActivity.onCreate`: an `AuthTabWebPresenter` must be created before its activity starts. */
  @Volatile
  var webPresenter: WebAuthenticationPresenter? = null

  private val scope = MainScope()
  private lateinit var models: MutableStateFlow<DemoModel>

  /** The model for the current server; a new one after [switchServer]. */
  val modelFlow: StateFlow<DemoModel> get() = models.asStateFlow()
  val model: DemoModel get() = models.value

  /** The build's defaults (`-Pdemo.<name>=…`), what "Reset to defaults" goes back to. */
  val defaultConfig: DemoConfig by lazy { DemoConfig.fromBuildConfig() }

  override fun onCreate() {
    super.onCreate()
    registerActivityLifecycleCallbacks(
      object : ActivityLifecycleCallbacks {
        override fun onActivityResumed(activity: Activity) {
          current = WeakReference(activity)
        }

        override fun onActivityPaused(activity: Activity) {
          if (current.get() === activity) current = WeakReference(null)
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}

        override fun onActivityStarted(activity: Activity) {}

        override fun onActivityStopped(activity: Activity) {}

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

        override fun onActivityDestroyed(activity: Activity) {}
      },
    )
    models = MutableStateFlow(newModel(DemoConfig.load(this, defaultConfig)))
  }

  /**
   * Saves the server settings, signs out (the stored logins and the local push enrollment belong to
   * the old server, so they are cleared locally) and replaces the model with one for [config].
   */
  fun switchServer(config: DemoConfig, onDone: () -> Unit = {}) {
    scope.launch {
      val old = models.value
      old.clearLocalState()
      old.close()
      if (config == defaultConfig) DemoConfig.reset(this@DemoApplication) else config.save(this@DemoApplication)
      models.value = newModel(config).also { it.noteServerChanged() }
      onDone()
    }
  }

  private fun newModel(config: DemoConfig) = DemoModel(this, config, { current.get() }, delegatingPresenter)

  /** The SDK instances outlive the activity, so the browser goes through whichever activity is current. */
  private val delegatingPresenter = WebAuthenticationPresenter { url, redirectUri ->
    val presenter = webPresenter ?: throw NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_FAILED, errorDescription = "No activity to open the browser from")
    presenter.authenticate(url, redirectUri)
  }
}

/** The demo's settings, from `BuildConfig` (`-Pdemo.<name>=…`, android/demo/README.md). */
data class DemoConfig(
  val issuer: URI,
  val clientId: String,
  val passkeyClientId: String,
  val stepUpClientId: String,
  val otpClientId: String,
  val pinClientId: String,
  /** The step-up demo API (S6): `GET /transfer` demands acr 2. */
  val resourceServer: URI,
  /** Needed when the realm's passkey RP ID (a tunnel host) is not the issuer host. */
  val allowRpIdMismatch: Boolean,
  val deviceName: String,
  /** `google-services.json` was present at build time: push messages go over FCM. */
  val firebaseConfigured: Boolean,
) {
  companion object {
    fun fromBuildConfig(): DemoConfig = DemoConfig(
      issuer = URI(BuildConfig.ISSUER),
      clientId = BuildConfig.CLIENT_ID,
      passkeyClientId = BuildConfig.PASSKEY_CLIENT_ID,
      stepUpClientId = BuildConfig.STEP_UP_CLIENT_ID,
      otpClientId = BuildConfig.OTP_CLIENT_ID,
      pinClientId = BuildConfig.PIN_CLIENT_ID,
      resourceServer = URI(BuildConfig.RESOURCE_SERVER),
      allowRpIdMismatch = BuildConfig.ALLOW_RP_ID_MISMATCH,
      deviceName = BuildConfig.DEVICE_NAME,
      firebaseConfigured = BuildConfig.FIREBASE_CONFIGURED,
    )

    private const val PREFERENCES = "demo_server_settings"

    /** [defaults] with the values saved on the Settings screen on top. */
    fun load(context: Context, defaults: DemoConfig): DemoConfig {
      val prefs = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
      if (!prefs.contains("issuer")) return defaults
      return runCatching {
        defaults.copy(
          issuer = URI(prefs.getString("issuer", null) ?: defaults.issuer.toString()),
          clientId = prefs.getString("clientId", null) ?: defaults.clientId,
          passkeyClientId = prefs.getString("passkeyClientId", null) ?: defaults.passkeyClientId,
          stepUpClientId = prefs.getString("stepUpClientId", null) ?: defaults.stepUpClientId,
          otpClientId = prefs.getString("otpClientId", null) ?: defaults.otpClientId,
          pinClientId = prefs.getString("pinClientId", null) ?: defaults.pinClientId,
          resourceServer = URI(prefs.getString("resourceServer", null) ?: defaults.resourceServer.toString()),
        )
      }.getOrDefault(defaults)
    }

    fun reset(context: Context) {
      context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit().clear().apply()
    }

    /**
     * Plain HTTP only to the development hosts that the debug build's network security config allows
     * (`src/debug/res/xml/network_security_config.xml`); release builds allow no cleartext at all.
     */
    val cleartextHosts = setOf("10.0.2.2", "localhost", "127.0.0.1")

    /** `null` when [text] is a usable base URL (no `/realms/…`), else what is wrong with it. */
    fun problemWithServerUrl(text: String): String? {
      val uri = runCatching { URI(text.trim()) }.getOrNull()
      val scheme = uri?.scheme?.lowercase()
      if (uri == null || scheme == null || uri.host.isNullOrEmpty()) return "Enter a URL such as https://idp.example.com or http://10.0.2.2:8080."
      if (uri.rawQuery != null || uri.rawFragment != null) return "Leave out the query and fragment."
      if (uri.path.orEmpty().contains("/realms/")) return "Enter the server URL without /realms/…; the realm has its own field."
      return when (scheme) {
        "https" -> null
        "http" -> when {
          !BuildConfig.DEBUG -> "Release builds allow https only."
          uri.host.lowercase() in cleartextHosts -> null
          else -> "Use https for anything but 10.0.2.2 and localhost (the network security config allows plain HTTP to those only)."
        }
        else -> "The URL must start with https:// (or http:// for 10.0.2.2 and localhost)."
      }
    }

    /** `<server>/realms/<realm>`. */
    fun issuer(serverUrl: String, realm: String): URI =
      URI("${serverUrl.trim().trimEnd('/')}/realms/${java.net.URLEncoder.encode(realm.trim(), Charsets.UTF_8).replace("+", "%20")}")
  }

  /** The base URL: the issuer up to `/realms/`. */
  val serverUrl: String get() = issuer.toString().substringBefore("/realms/")

  /** The realm: the issuer's path after `/realms/`. */
  val realm: String get() = java.net.URLDecoder.decode(issuer.toString().substringAfter("/realms/", "").trimEnd('/'), Charsets.UTF_8)

  fun save(context: Context) {
    context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
      .putString("issuer", issuer.toString())
      .putString("clientId", clientId)
      .putString("passkeyClientId", passkeyClientId)
      .putString("stepUpClientId", stepUpClientId)
      .putString("otpClientId", otpClientId)
      .putString("pinClientId", pinClientId)
      .putString("resourceServer", resourceServer.toString())
      .apply()
  }
}

/** The SDK's (already redacted) log lines in Logcat under the tag `KeycloakNative`. */
object LogcatLogger : NativeAuthLogger {
  override fun log(level: LogLevel, message: () -> String) {
    val priority = when (level) {
      LogLevel.DEBUG -> Log.DEBUG
      LogLevel.INFO -> Log.INFO
      LogLevel.WARNING -> Log.WARN
      LogLevel.ERROR -> Log.ERROR
    }
    if (Log.isLoggable("KeycloakNative", priority) || priority >= Log.INFO) Log.println(priority, "KeycloakNative", message())
  }
}
