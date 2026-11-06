package io.phasetwo.keycloak.nativeauth.sdk.push.fcm

import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.RemoteMessage
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PushEnrollmentParams
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.push.PreparedPushEnrollment
import io.phasetwo.keycloak.nativeauth.sdk.push.Push
import io.phasetwo.keycloak.nativeauth.sdk.push.PushEnrollment
import io.phasetwo.keycloak.nativeauth.sdk.push.PushNotificationPayload
import io.phasetwo.keycloak.nativeauth.sdk.push.PushProviderRegistration
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.tasks.await

/**
 * Firebase Cloud Messaging for push MFA (spec/03 §7 "Receive push", "Maintenance"). The server's
 * `fcm` sender (ba-itsys) sends an HTTP v1 message with a visible `notification` and `data.token`, the
 * realm-signed confirm token. The app applies the google-services Gradle plugin with its own Firebase
 * project and, on Android 13+, asks for `POST_NOTIFICATIONS`.
 *
 * Wiring, in the app's `FirebaseMessagingService`:
 * ```
 * override fun onNewToken(token: String) { scope.launch { kc.push().onNewFcmToken(token) } }
 * override fun onMessageReceived(message: RemoteMessage) {
 *   scope.launch { kc.push().handle(message)?.let { payload -> showApproval(kc.push().pendingApproval(payload)) } }
 * }
 * ```
 * A message that carries a `notification` reaches `onMessageReceived` only while the app is in the
 * foreground; in the background Android shows the notification itself and hands the data over only
 * when the user taps it. So the app also reads [Push.pendingApprovals] whenever it opens or resumes.
 */
public object FcmPush {
  /** The sender name of ba-itsys' FCM sender (`pushProviderType`). */
  public const val PROVIDER_TYPE: String = "fcm"

  /**
   * This device's FCM registration as [PushProviderRegistration] (`fcm` + the registration token), for
   * `NativeLoginScreen(pushRegistration = { FcmPush.registration() })` and [enrollWithFcm].
   * `push_unavailable` when Firebase is not set up in the app or the token cannot be fetched.
   */
  public suspend fun registration(messaging: FirebaseMessaging? = null): PushProviderRegistration =
    PushProviderRegistration(PROVIDER_TYPE, token(messaging))

  /**
   * The current FCM registration token (`FirebaseMessaging.getToken`). Firebase Messaging 26 marks
   * `getToken` deprecated beside `register()`, which delivers the token only to `onNewToken`; enrollment
   * needs the token in hand, so this still reads it directly.
   */
  @Suppress("DEPRECATION")
  public suspend fun token(messaging: FirebaseMessaging? = null): String {
    try {
      return (messaging ?: FirebaseMessaging.getInstance()).token.await()
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      // IllegalStateException without a FirebaseApp (no google-services.json), IOException offline or
      // without Google Play services.
      throw NativeAuthError(NativeAuthError.Code.PUSH_UNAVAILABLE, errorDescription = "No FCM registration token: ${e.message ?: e}", cause = e)
    }
  }
}

/** Enrolls this device from inside the app (scenario C) with its FCM registration token. */
public suspend fun Push.enrollWithFcm(deviceLabel: String, messaging: FirebaseMessaging? = null): PushEnrollment =
  enroll(deviceLabel, FcmPush.PROVIDER_TYPE, FcmPush.token(messaging))

/** The answer to a `push_enrollment` challenge (spec/03 §4.15) with this device's FCM registration token. */
public suspend fun Push.prepareFcmEnrollment(params: PushEnrollmentParams, deviceLabel: String, messaging: FirebaseMessaging? = null): PreparedPushEnrollment =
  prepareEnrollment(params, deviceLabel, FcmPush.PROVIDER_TYPE, FcmPush.token(messaging))

/**
 * Call from `FirebaseMessagingService.onNewToken`: sends the new token to the server
 * (`PUT /push-mfa/device/push-provider`) when this device is enrolled with FCM. Nothing happens when
 * it is not enrolled, enrolled without FCM, or the server already has this token.
 */
public suspend fun Push.onNewFcmToken(token: String) {
  val enrollment = enrollment() ?: return
  if (enrollment.pushProviderType != FcmPush.PROVIDER_TYPE) return
  updatePushProvider(FcmPush.PROVIDER_TYPE, token)
}

/**
 * The push-MFA content of a message (`data.token`); `null` when it is not one, or it is for another
 * credential than this device's. Resolve it with [Push.pendingApproval].
 */
public suspend fun Push.handle(message: RemoteMessage): PushNotificationPayload? = handleMessage(message.data)
