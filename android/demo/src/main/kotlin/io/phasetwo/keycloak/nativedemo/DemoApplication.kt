package io.phasetwo.keycloak.nativedemo

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.lang.ref.WeakReference
import java.net.URI

/** Holds the one [DemoModel] and tracks the activity on screen for the platform prompts. */
class DemoApplication : Application() {
  /** The activity on screen: Credential Manager prompts and the browser need it. */
  @Volatile
  private var current: WeakReference<Activity> = WeakReference(null)

  /** Set by `MainActivity.onCreate`: an `AuthTabWebPresenter` must be created before its activity starts. */
  @Volatile
  var webPresenter: WebAuthenticationPresenter? = null

  lateinit var model: DemoModel
    private set

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
    model = DemoModel(this, DemoConfig.fromBuildConfig(), { current.get() }, delegatingPresenter)
  }

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
