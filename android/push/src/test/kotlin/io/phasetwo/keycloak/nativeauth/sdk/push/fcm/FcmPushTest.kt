package io.phasetwo.keycloak.nativeauth.sdk.push.fcm

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.push.DeviceToken
import io.phasetwo.keycloak.nativeauth.sdk.push.StaticDeviceTokenProvider
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The token refresh rule of [onNewFcmToken]; the protocol itself is covered by core's `Phase3ReplayTest`. */
class FcmPushTest {
  private class Recording : Transport {
    val sent = mutableListOf<HttpRequest>()

    override suspend fun send(request: HttpRequest): HttpResponse {
      sent += request
      val path = request.url.path
      val body = when {
        path.endsWith("/native-auth/metadata") -> METADATA
        path.endsWith("/enroll/start") -> """{"enrollment_token":"$ENROLLMENT_TOKEN","device_api_base":"$BASE/push-mfa","user_id":"u-1"}"""
        path.endsWith("/enroll/complete") -> """{"status":"enrolled"}"""
        else -> """{"status":"updated"}"""
      }
      return HttpResponse(200, mapOf("Content-Type" to "application/json"), body.toByteArray())
    }
  }

  private companion object {
    const val BASE = "https://idp.example.com/realms/demo"
    const val METADATA =
      """{"protocol_version":"1","authorization_challenge_endpoint":"$BASE/native-auth/challenge","token_endpoint":"$BASE/protocol/openid-connect/token","push":{"enabled":true,"device_api_base":"$BASE/push-mfa","device_token":"native","push_provider_types":["fcm","none"]}}"""
    val ENROLLMENT_TOKEN = "eyJhbGciOiJub25lIn0." +
      Base64.getUrlEncoder().withoutPadding().encodeToString("""{"sub":"u-1","enrollmentId":"e-1","nonce":"n-1"}""".toByteArray()) + "."
  }

  private fun sdk(transport: Transport) =
    KeycloakNative.configure(URI(BASE), "demo", KeycloakNative.Options(dpop = DPoPMode.SOFTWARE, transport = transport))

  @Test
  fun aNewTokenIsSentOnlyForAnFcmEnrollmentAndOnlyOnce() = runTest {
    val transport = Recording()
    val push = sdk(transport).push(StaticDeviceTokenProvider(DeviceToken("t")))
    push.onNewFcmToken("before-enrollment")
    assertTrue("not enrolled: nothing sent", transport.sent.isEmpty())

    push.enroll("Pixel", FcmPush.PROVIDER_TYPE, "token-1")
    val afterEnroll = transport.sent.size
    push.onNewFcmToken("token-1")
    assertEquals("the server already has it", afterEnroll, transport.sent.size)
    push.onNewFcmToken("token-2")
    val put = transport.sent.last()
    assertEquals("PUT", put.method)
    assertTrue(put.url.path.endsWith("/push-mfa/device/push-provider"))
    assertEquals("""{"pushProviderId":"token-2","pushProviderType":"fcm"}""", String(put.body!!))
    assertEquals("token-2", push.enrollment()?.pushProviderId)
  }

  @Test
  fun aDeviceEnrolledWithoutFcmKeepsPulling() = runTest {
    val transport = Recording()
    val push = sdk(transport).push(StaticDeviceTokenProvider(DeviceToken("t")))
    push.enroll("Pixel")
    val count = transport.sent.size
    push.onNewFcmToken("token-1")
    assertEquals(count, transport.sent.size)
    assertEquals("none", push.enrollment()?.pushProviderType)
  }
}
