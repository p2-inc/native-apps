package io.phasetwo.keycloak.nativeauth.reactnative

import androidx.activity.ComponentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import io.phasetwo.keycloak.nativeauth.sdk.android.AuthTabWebPresenter
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError

/**
 * The browser fallback's hook into the app's activity. `AuthTabWebPresenter` registers an activity
 * result launcher, which Android only allows before the activity starts, so the app calls [register]
 * from its `MainActivity.onCreate` (an Expo config plugin adds the call, spec/19 §7):
 *
 * ```kotlin
 * override fun onCreate(savedInstanceState: Bundle?) {
 *   super.onCreate(savedInstanceState)
 *   KeycloakNativeActivity.register(this)
 * }
 * ```
 *
 * The callback activity (`NativeAuthRedirectActivity` with the app's `redirect_uri` intent filter)
 * is declared in the app's manifest as for the Android SDK (docs/android-integration.md).
 */
object KeycloakNativeActivity {
  @Volatile private var presenters: Pair<AuthTabWebPresenter, AuthTabWebPresenter>? = null

  @JvmStatic
  fun register(activity: ComponentActivity) {
    val registered = AuthTabWebPresenter(activity, ephemeral = false) to AuthTabWebPresenter(activity, ephemeral = true)
    presenters = registered
    activity.lifecycle.addObserver(
      object : DefaultLifecycleObserver {
        override fun onDestroy(owner: LifecycleOwner) {
          // Do not keep a destroyed activity; a recreated one registers again.
          if (presenters === registered) presenters = null
        }
      },
    )
  }

  internal fun presenter(ephemeral: Boolean): AuthTabWebPresenter {
    val registered = presenters ?: throw NativeAuthError(
      NativeAuthError.Code.WEB_FALLBACK_FAILED,
      errorDescription = "No activity to open the browser from: call KeycloakNativeActivity.register(this) in MainActivity.onCreate",
    )
    return if (ephemeral) registered.second else registered.first
  }
}
