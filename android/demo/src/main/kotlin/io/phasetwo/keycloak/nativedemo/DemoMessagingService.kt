package io.phasetwo.keycloak.nativedemo

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * FCM for push MFA (spec/03 §7). A new registration token goes to the server when this device is
 * enrolled with FCM. A message arrives here only while the app is in the foreground (it carries a
 * `notification`); then the Push tab opens on its approval. In the background Android shows the
 * notification and a tap opens `MainActivity` with the data as extras.
 */
class DemoMessagingService : FirebaseMessagingService() {
  private val model: DemoModel get() = (application as DemoApplication).model

  /** Firebase Messaging 26's callback for a new registration token. */
  override fun onRegistered(token: String) {
    model.onNewFcmToken(token)
  }

  /** Still delivered by Firebase Messaging 26 for apps that read the token with `getToken`. Idempotent with [onRegistered]. */
  @Deprecated("Firebase Messaging 26 replaces it with onRegistered")
  override fun onNewToken(token: String) {
    model.onNewFcmToken(token)
  }

  override fun onMessageReceived(message: RemoteMessage) {
    model.messageReceived(message.data)
  }
}
