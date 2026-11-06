@file:OptIn(ExperimentalCoroutinesApi::class)

package io.phasetwo.keycloak.nativeauth.sdk.ui

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.push.DeviceToken
import io.phasetwo.keycloak.nativeauth.sdk.push.Push
import io.phasetwo.keycloak.nativeauth.sdk.push.PushApprovalAction
import io.phasetwo.keycloak.nativeauth.sdk.push.StaticDeviceTokenProvider
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.util.Base64
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Twin of the iOS `PushApprovalsModel` behavior: ordering, expiry, approve, a wrong number, a conflict. */
class PushApprovalsModelTest {
  /** Answers by path; `respond` answers come from [respondStatus] in order. */
  private class Device(private val pending: String, vararg respondStatus: Int) : Transport {
    private val statuses = ArrayDeque(respondStatus.toList())
    val sent = mutableListOf<HttpRequest>()

    override suspend fun send(request: HttpRequest): HttpResponse {
      sent += request
      val path = request.url.path
      val (status, body) = when {
        path.endsWith("/native-auth/metadata") -> 200 to METADATA
        path.endsWith("/enroll/start") -> 200 to """{"enrollment_token":"$ENROLLMENT_TOKEN","device_api_base":"$BASE/push-mfa","user_id":"u-1"}"""
        path.endsWith("/enroll/complete") -> 200 to """{"status":"enrolled"}"""
        path.endsWith("/login/pending") -> 200 to pending
        path.endsWith("/respond") -> when (val s = statuses.removeFirstOrNull() ?: 200) {
          200 -> 200 to """{"status":"approved"}"""
          else -> s to """{"error":"refused $s"}"""
        }
        else -> 404 to "{}"
      }
      return HttpResponse(status, mapOf("Content-Type" to "application/json"), body.toByteArray())
    }
  }

  private companion object {
    const val BASE = "https://idp.example.com/realms/demo"
    const val METADATA =
      """{"protocol_version":"1","authorization_challenge_endpoint":"$BASE/native-auth/challenge","token_endpoint":"$BASE/protocol/openid-connect/token","push":{"enabled":true,"device_api_base":"$BASE/push-mfa","device_token":"native"}}"""
    val ENROLLMENT_TOKEN = "eyJhbGciOiJub25lIn0." + Base64.getUrlEncoder().withoutPadding().encodeToString("""{"sub":"u-1","enrollmentId":"e","nonce":"n"}""".toByteArray()) + "."
    const val FUTURE = 4102444800L

    fun approval(cid: String, expires: Long = FUTURE, numbers: String = "") =
      """{"cid":"$cid","username":"alice","clientId":"web-app","expiresAt":$expires${if (numbers.isEmpty()) "" else ""","userVerification":{"type":"number_match","numbers":[$numbers]}"""}}"""
  }

  private suspend fun enrolled(device: Device): Push {
    val kc = KeycloakNative.configure(URI(BASE), "demo", KeycloakNative.Options(dpop = DPoPMode.SOFTWARE, transport = device))
    return kc.push(StaticDeviceTokenProvider(DeviceToken("t"))).also { it.enroll("Pixel") }
  }

  @Test
  fun theFocusedApprovalComesFirstAndExpiredOnesAreHidden() = runTest {
    val device = Device("""{"challenges":[${approval("a")},${approval("old", expires = 1)},${approval("b")}]}""")
    val model = PushApprovalsModel(enrolled(device), focus = "b", this) { _, _ -> }
    model.refresh()
    assertEquals(listOf("b", "a"), model.state.value.approvals.map { it.cid })
  }

  @Test
  fun approvingRemovesTheCardAndReportsTheStatus() = runTest {
    val device = Device("""{"challenges":[${approval("a")}]}""", 200)
    val responded = mutableListOf<String>()
    val model = PushApprovalsModel(enrolled(device), null, this) { a, status -> responded += "${a.cid}:$status" }
    model.refresh()
    model.respond(model.state.value.approvals.single(), PushApprovalAction.Approve())
    advanceUntilIdle()
    assertTrue(model.state.value.approvals.isEmpty())
    assertEquals(listOf("a:approved"), responded)
    assertNull(model.state.value.message)
  }

  @Test
  fun aWrongNumberKeepsTheCardForAnotherTry() = runTest {
    val device = Device("""{"challenges":[${approval("a", numbers = "\"12\",\"34\",\"56\"")}]}""", 403, 200)
    val model = PushApprovalsModel(enrolled(device), null, this) { _, _ -> }
    model.refresh()
    val card = model.state.value.approvals.single()
    assertEquals(listOf("12", "34", "56"), card.numbers)
    val pendingReads = device.sent.count { it.url.path.endsWith("/login/pending") }
    model.respond(card, PushApprovalAction.Approve("12"))
    advanceUntilIdle()
    assertEquals("refused 403", model.state.value.message)
    assertEquals(listOf("a"), model.state.value.approvals.map { it.cid })
    assertEquals("no refresh after a mismatch", pendingReads, device.sent.count { it.url.path.endsWith("/login/pending") })
    model.respond(card, PushApprovalAction.Approve("34"))
    advanceUntilIdle()
    assertTrue(model.state.value.approvals.isEmpty())
  }

  @Test
  fun aConflictRefreshesTheList() = runTest {
    val device = Device("""{"challenges":[${approval("a")}]}""", 409)
    val model = PushApprovalsModel(enrolled(device), null, this) { _, _ -> }
    model.refresh()
    val before = device.sent.count { it.url.path.endsWith("/login/pending") }
    model.respond(model.state.value.approvals.single(), PushApprovalAction.Deny)
    advanceUntilIdle()
    assertEquals(before + 1, device.sent.count { it.url.path.endsWith("/login/pending") })
    assertNotNull(model.state.value.approvals.singleOrNull())
  }
}
