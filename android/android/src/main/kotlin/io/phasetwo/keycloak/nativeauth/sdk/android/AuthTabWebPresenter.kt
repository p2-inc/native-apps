package io.phasetwo.keycloak.nativeauth.sdk.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.net.URI
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The browser fallback (spec/03 §3.4) on Android, the analogue of `ASWebAuthenticationSession`. Uses
 * an Auth Tab when the default browser supports one: the browser hands the callback straight back,
 * for a custom scheme or a verified `https` App Link. Otherwise it opens a Custom Tab, and the
 * callback arrives through [NativeAuthRedirectActivity], which the app declares with an intent filter
 * for its `redirect_uri`:
 *
 * ```xml
 * <activity android:name="io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity"
 *     android:exported="true" android:theme="@android:style/Theme.Translucent.NoTitleBar">
 *   <intent-filter>
 *     <action android:name="android.intent.action.VIEW" />
 *     <category android:name="android.intent.category.DEFAULT" />
 *     <category android:name="android.intent.category.BROWSABLE" />
 *     <data android:scheme="demoapp" android:host="auth" android:path="/callback" />
 *   </intent-filter>
 * </activity>
 * ```
 *
 * Create it in [activity]'s `onCreate` (it registers an activity result launcher, which must happen
 * before the activity starts). Closing the browser is `web_fallback_cancelled`; no browser, an App
 * Link that fails verification or a second concurrent call is `web_fallback_failed`.
 */
public class AuthTabWebPresenter(
  private val activity: ComponentActivity,
  /** Ask the browser for a session that shares no cookies with the user's normal browsing. */
  private val ephemeral: Boolean = false,
) : WebAuthenticationPresenter {
  private val launcher = AuthTabIntent.registerActivityResultLauncher(activity) { result ->
    // The launcher is re-registered after a configuration change, so the result may arrive on a new
    // presenter instance: the pending call is process-wide.
    when (result.resultCode) {
      AuthTabIntent.RESULT_OK -> Pending.deliver(result.resultUri)
      AuthTabIntent.RESULT_CANCELED -> Pending.fail(NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_CANCELLED, errorDescription = "The user closed the browser"))
      AuthTabIntent.RESULT_VERIFICATION_FAILED, AuthTabIntent.RESULT_VERIFICATION_TIMED_OUT ->
        Pending.fail(failed("The browser could not verify the App Link of the redirect_uri (Digital Asset Links)"))
      else -> Pending.fail(failed("The browser returned result code ${result.resultCode}"))
    }
  }

  override suspend fun authenticate(url: URI, redirectUri: URI): URI = withContext(Dispatchers.Main.immediate) {
    val deferred = Pending.begin(ComponentName(activity, activity.javaClass))
    try {
      val uri = Uri.parse(url.toString())
      val browser = CustomTabsClient.getPackageName(activity, emptyList())
      try {
        if (browser != null && CustomTabsClient.isAuthTabSupported(activity, browser)) {
          launchAuthTab(uri, redirectUri)
        } else {
          launchCustomTab(uri, browser, deferred)
        }
      } catch (e: ActivityNotFoundException) {
        throw failed("No browser is installed").apply { initCause(e) }
      }
      URI(deferred.await().toString())
    } finally {
      Pending.end(deferred)
    }
  }

  private fun launchAuthTab(uri: Uri, redirectUri: URI) {
    val intent = AuthTabIntent.Builder().setEphemeralBrowsingEnabled(ephemeral).build()
    if (redirectUri.scheme.equals("https", ignoreCase = true)) {
      intent.launch(launcher, uri, redirectUri.host, redirectUri.path.orEmpty().ifEmpty { "/" })
    } else {
      intent.launch(launcher, uri, redirectUri.scheme)
    }
  }

  private fun launchCustomTab(uri: Uri, browser: String?, deferred: CompletableDeferred<Uri>) {
    val intent = CustomTabsIntent.Builder().setEphemeralBrowsingEnabled(ephemeral).build()
    browser?.let(intent.intent::setPackage)
    intent.launchUrl(activity, uri)
    // The redirect activity delivers before it brings this activity back, so resuming without a
    // result means the user closed the tab.
    activity.lifecycle.addObserver(
      object : DefaultLifecycleObserver {
        private var paused = false

        override fun onPause(owner: LifecycleOwner) {
          paused = true
        }

        override fun onResume(owner: LifecycleOwner) {
          if (!paused) return
          owner.lifecycle.removeObserver(this)
          if (!deferred.isCompleted) {
            deferred.completeExceptionally(NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_CANCELLED, errorDescription = "The user closed the browser"))
          }
        }
      },
    )
  }

  /** The one browser login in progress, shared by the presenter and [NativeAuthRedirectActivity]. */
  internal object Pending {
    private var deferred: CompletableDeferred<Uri>? = null
    private var host: ComponentName? = null

    @Synchronized
    fun begin(host: ComponentName): CompletableDeferred<Uri> {
      if (deferred?.isActive == true) throw failed("A browser login is already in progress")
      return CompletableDeferred<Uri>().also {
        deferred = it
        this.host = host
      }
    }

    @Synchronized
    fun end(finished: CompletableDeferred<Uri>) {
      if (deferred === finished) {
        deferred = null
        host = null
      }
    }

    /** Completes the pending call; returns the activity that started it, to bring back to the front. */
    @Synchronized
    fun deliver(uri: Uri?): ComponentName? {
      val pending = deferred ?: return null
      if (uri == null) pending.completeExceptionally(failed("The browser returned no callback URL")) else pending.complete(uri)
      return host
    }

    @Synchronized
    fun fail(error: NativeAuthError) {
      deferred?.completeExceptionally(error)
    }
  }

  private companion object {
    fun failed(description: String) = NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_FAILED, errorDescription = description)
  }
}

/**
 * Receives the `redirect_uri` callback when the login ran in a Custom Tab (browsers without Auth
 * Tab), hands it to the waiting [AuthTabWebPresenter] and returns to the app's activity, closing the
 * tab. The app declares it with its own intent filter (see [AuthTabWebPresenter]).
 */
public class NativeAuthRedirectActivity : Activity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val host = AuthTabWebPresenter.Pending.deliver(intent?.data)
    // CLEAR_TOP pops the Custom Tab, which sits above the app's activity in its task.
    host?.let { startActivity(Intent().setComponent(it).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)) }
    finish()
  }
}
