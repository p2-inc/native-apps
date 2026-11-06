package io.phasetwo.keycloak.nativedemo

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import io.phasetwo.keycloak.nativeauth.sdk.android.AuthTabWebPresenter

class MainActivity : ComponentActivity() {
  private val app: DemoApplication get() = application as DemoApplication

  private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Registers an activity result launcher, so it must be created before the activity starts.
    app.webPresenter = AuthTabWebPresenter(this)
    enableEdgeToEdge()
    setContent { DemoApp(app.model) }
    askForNotifications()
    handleNotificationTap(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleNotificationTap(intent)
  }

  override fun onResume() {
    super.onResume()
    app.model.onResume()
  }

  /** A tapped FCM notification starts the launcher activity with the message's data as extras. */
  private fun handleNotificationTap(intent: Intent?) {
    val extras = intent?.extras ?: return
    val data = extras.keySet().mapNotNull { key -> extras.getString(key)?.let { key to it } }.toMap()
    if ("token" in data || "confirmToken" in data) app.model.messageReceived(data)
  }

  private fun askForNotifications() {
    if (!app.model.config.firebaseConfigured || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
      notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
  }
}
