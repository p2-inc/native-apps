@file:OptIn(ExperimentalCoroutinesApi::class)

package io.phasetwo.keycloak.nativeauth.sdk.ui

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPassword
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.push.PushProviderRegistration
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.util.Base64
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Twin of `NativeLoginModelTests.swift`: the model behind `NativeLoginScreen` (which entry is shown,
 * switching, submitting, cancelling, terminal errors) plus the Android save-password step. Screens are
 * not rendered; the model is what they bind to.
 */
class NativeLoginModelTest {
  private class Scripted(vararg handlers: (HttpRequest) -> HttpResponse) : Transport {
    private val handlers = ArrayDeque(handlers.toList())
    val sent = mutableListOf<HttpRequest>()

    override suspend fun send(request: HttpRequest): HttpResponse {
      sent += request
      val handler = if (handlers.size > 1) handlers.removeFirst() else handlers.first()
      return handler(request)
    }

    fun field(index: Int, name: String): String? = sent[index].formFields?.firstOrNull { it.first == name }?.second
  }

  private class RecordingPasswords(private val picked: Result<SavedPassword>) : SavedPasswordPlatform {
    val saved = mutableListOf<SavedPassword>()

    override suspend fun pick(): SavedPassword = picked.getOrThrow()

    override suspend fun save(password: SavedPassword) {
      saved += password
    }
  }

  private companion object {
    const val METADATA =
      """{"protocol_version":"1","authorization_challenge_endpoint":"https://idp.example.com/realms/demo/native-auth/challenge","token_endpoint":"https://idp.example.com/realms/demo/protocol/openid-connect/token","passkey":{"rp_id":"idp.example.com"}}"""
    const val USERNAME = """{"type":"username","id":"u","required":true,"params":{"allow_email":true}}"""
    const val PASSWORD = """{"type":"password","id":"p","required":false,"params":{"username_known":true}}"""
    const val TOTP = """{"type":"totp","id":"t","required":false,"params":{"digits":6}}"""
    const val AUTHORIZED = """{"authorization_code":"code","auth_session":"post"}"""

    fun json(status: Int, body: String) = HttpResponse(status, mapOf("Content-Type" to "application/json"), body.toByteArray())

    fun set(vararg challenges: String, session: String = "s", username: String? = "alice") =
      json(403, """{"error":"insufficient_authorization","auth_session":"$session","expires_in":500,"challenges":[${challenges.joinToString(",")}]${username?.let { ""","context":{"username":"$it"}""" } ?: ""}}""")

    fun tokens(): HttpResponse {
      val claims = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"preferred_username":"alice","acr":"1"}""".toByteArray())
      val jwt = "eyJhbGciOiJub25lIn0.$claims."
      return json(200, """{"access_token":"$jwt","token_type":"Bearer","expires_in":300,"refresh_token":"r","id_token":"$jwt","scope":"openid"}""")
    }
  }

  private class Fixture(val kc: KeycloakNative, val model: NativeLoginModel, val transport: Scripted, val results: MutableList<NativeLoginResult>)

  private fun TestScope.fixture(
    vararg handlers: (HttpRequest) -> HttpResponse,
    passwords: SavedPasswordPlatform? = null,
    offerToSavePassword: Boolean = true,
    dpop: DPoPMode = DPoPMode.DISABLED,
    pushRegistration: (suspend () -> PushProviderRegistration)? = null,
  ): Fixture {
    val transport = Scripted(*handlers)
    val kc = KeycloakNative.configure(
      URI("https://idp.example.com/realms/demo"),
      "c",
      KeycloakNative.Options(dpop = dpop, transport = transport, savedPasswordPlatform = passwords),
    )
    val results = mutableListOf<NativeLoginResult>()
    val model = NativeLoginModel(kc, kc.authentication().startLogin(), this, offersToSavePassword = offerToSavePassword, pushRegistration = pushRegistration) { results += it }
    return Fixture(kc, model, transport, results)
  }

  private val NativeLoginModel.selected get() = (state.value.phase as? NativeLoginModel.Phase.Challenges)?.selected

  @Test
  fun startShowsTheFirstSupportedEntryAndSwitchingKeepsTheSet() = runTest {
    val f = fixture({ json(200, METADATA) }, { set("""{"type":"x-vendor-foo","id":"x","required":false}""", PASSWORD, TOTP) })
    f.model.startIfNeeded()
    advanceUntilIdle()
    val phase = f.model.state.value.phase as NativeLoginModel.Phase.Challenges
    assertEquals("unknown types are skipped", ChallengeType.Password, phase.selected.type)
    assertEquals(3, phase.challenges.size)
    assertEquals("alice", phase.context.username)
    f.model.select(phase.challenges.first { it.type == ChallengeType.Totp })
    assertEquals(ChallengeType.Totp, f.model.selected?.type)
  }

  @Test
  fun aFailedEntryIsShownAgainAndSuccessReportsCredentials() = runTest {
    val failedTotp = """{"type":"totp","id":"t","required":false,"error":{"code":"invalid_credential","message":"Invalid code"},"retry":{"remaining":2},"params":{"digits":6}}"""
    val f = fixture({ json(200, METADATA) }, { set(PASSWORD, TOTP) }, { set(PASSWORD, failedTotp, session = "s2") }, { json(200, AUTHORIZED) }, { tokens() })
    f.model.startIfNeeded()
    advanceUntilIdle()
    val totp = (f.model.state.value.phase as NativeLoginModel.Phase.Challenges).challenges.first { it.type == ChallengeType.Totp }
    f.model.submit(ChallengeAnswer.Totp("000000"), totp)
    advanceUntilIdle()
    val failed = f.model.selected!!
    assertEquals("the entry that failed is shown, not the first one", ChallengeType.Totp, failed.type)
    assertEquals(2, failed.retry?.remaining)
    f.model.submit(ChallengeAnswer.Totp("123456"), failed)
    advanceUntilIdle()
    assertTrue(f.results.single() is NativeLoginResult.Authorized)
    assertEquals("000000", f.transport.field(2, "totp"))
  }

  @Test
  fun aSavedPasswordAnswersTheUsernameAndThenThePasswordAndIsNotSavedAgain() = runTest {
    val passwords = RecordingPasswords(Result.success(SavedPassword("alice", "s3cret")))
    val f = fixture({ json(200, METADATA) }, { set(USERNAME, username = null) }, { set(PASSWORD, TOTP, session = "s2") }, { json(200, AUTHORIZED) }, { tokens() }, passwords = passwords)
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.useSavedPassword(f.model.selected!!)
    advanceUntilIdle()
    assertTrue(f.results.single() is NativeLoginResult.Authorized)
    assertEquals("alice", f.transport.field(2, "username"))
    assertEquals("the picked password answers the password challenge without a tap", "s3cret", f.transport.field(3, "password"))
    assertTrue("a picked password is already saved", passwords.saved.isEmpty())
  }

  @Test
  fun closingTheSavedPasswordSheetKeepsTheUsernameScreen() = runTest {
    val passwords = RecordingPasswords(Result.failure(NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_CANCELLED, errorDescription = "closed")))
    val f = fixture({ json(200, METADATA) }, { set(USERNAME, username = null) }, passwords = passwords)
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.useSavedPassword(f.model.selected!!)
    advanceUntilIdle()
    assertEquals(ChallengeType.Username, f.model.selected?.type)
    assertNull(f.model.state.value.message)
    assertEquals("nothing is sent when the sheet is closed", 2, f.transport.sent.size)
  }

  @Test
  fun aTypedPasswordIsOfferedForSavingWithTheUsernameAfterSignIn() = runTest {
    val passwords = RecordingPasswords(Result.failure(IllegalStateException("unused")))
    val f = fixture({ json(200, METADATA) }, { set(PASSWORD) }, { json(200, AUTHORIZED) }, { tokens() }, passwords = passwords)
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.submit(ChallengeAnswer.Password("typed"), f.model.selected!!)
    advanceUntilIdle()
    assertEquals(listOf(SavedPassword("alice", "typed")), passwords.saved)
    assertTrue(f.results.single() is NativeLoginResult.Authorized)
  }

  @Test
  fun aWrongPasswordIsNeverOfferedAndTheOfferCanBeTurnedOff() = runTest {
    val wrong = """{"type":"password","id":"p","required":true,"error":{"code":"invalid_credential"},"retry":{"remaining":2},"params":{}}"""
    val passwords = RecordingPasswords(Result.failure(IllegalStateException("unused")))
    val f = fixture({ json(200, METADATA) }, { set(PASSWORD, TOTP) }, { set(wrong, TOTP, session = "s2") }, { json(200, AUTHORIZED) }, { tokens() }, passwords = passwords)
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.submit(ChallengeAnswer.Password("wrong"), f.model.selected!!)
    advanceUntilIdle()
    val totp = (f.model.state.value.phase as NativeLoginModel.Phase.Challenges).challenges.first { it.type == ChallengeType.Totp }
    f.model.submit(ChallengeAnswer.Totp("123456"), totp)
    advanceUntilIdle()
    assertTrue(f.results.single() is NativeLoginResult.Authorized)
    assertTrue("the rejected password is not saved", passwords.saved.isEmpty())

    val off = RecordingPasswords(Result.failure(IllegalStateException("unused")))
    val g = fixture({ json(200, METADATA) }, { set(PASSWORD) }, { json(200, AUTHORIZED) }, { tokens() }, passwords = off, offerToSavePassword = false)
    g.model.startIfNeeded()
    advanceUntilIdle()
    g.model.submit(ChallengeAnswer.Password("typed"), g.model.selected!!)
    advanceUntilIdle()
    assertTrue(off.saved.isEmpty())
  }

  @Test
  fun terminalErrorsEndTheScreenAndTransientOnesKeepIt() = runTest {
    val f = fixture(
      { json(200, METADATA) },
      { set(PASSWORD, TOTP) },
      { throw NativeAuthError(NativeAuthError.Code.NETWORK_ERROR, errorDescription = "offline", isNetworkError = true, isRetryable = true) },
      { json(403, """{"error":"access_denied","error_description":"Account temporarily locked"}""") },
    )
    f.model.startIfNeeded()
    advanceUntilIdle()
    val password = f.model.selected!!
    f.model.submit(ChallengeAnswer.Password("x"), password)
    advanceUntilIdle()
    assertEquals("a network error is shown inline, the set stays", "offline", f.model.state.value.message)
    assertTrue(f.results.isEmpty())
    f.model.submit(ChallengeAnswer.Password("x"), password)
    advanceUntilIdle()
    assertEquals(NativeAuthError.Code.ACCESS_DENIED, (f.results.single() as NativeLoginResult.Failed).error.code)
  }

  @Test
  fun cancelSendsActionCancelAndReportsCancelled() = runTest {
    val f = fixture({ json(200, METADATA) }, { set(PASSWORD) }, { json(400, """{"error":"invalid_session"}""") })
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.cancel()
    advanceUntilIdle()
    assertEquals(NativeLoginResult.Cancelled, f.results.single())
    assertEquals("cancel", f.transport.field(2, "action"))
  }

  private fun pinSet(type: String = "pin", error: String? = null, remaining: Int? = null): HttpResponse {
    val id = if (type == "pin") "pin-exec" else "native-configure-pin"
    val extra = (error?.let { ""","error":{"code":"$it"}""" } ?: "") + (remaining?.let { ""","retry":{"remaining":$it}""" } ?: "")
    return set("""{"type":"$type","id":"$id","required":true$extra,"params":{"length":6}}""")
  }

  @Test
  fun aWrongPinStaysOnThePinAndALockedPinOnlyOffersCancel() = runTest {
    val f = fixture(
      { json(200, METADATA) },
      { pinSet() },
      { pinSet(error = "invalid_credential", remaining = 1) },
      { pinSet(error = "credential_locked", remaining = 0) },
      { json(400, """{"error":"invalid_session"}""") },
    )
    f.model.startIfNeeded()
    advanceUntilIdle()
    val pin = f.model.selected!!
    assertEquals(ChallengeType.Pin, pin.type)
    assertEquals(6, pin.pinParams?.length)
    f.model.submit(ChallengeAnswer.Pin("000000"), pin)
    advanceUntilIdle()
    val wrong = f.model.selected!!
    assertEquals(1, wrong.retry?.remaining)
    assertTrue(!wrong.isLocked && pinErrorText(wrong.error?.code) == R.string.nl_pin_incorrect)
    f.model.submit(ChallengeAnswer.Pin("111111"), wrong)
    advanceUntilIdle()
    val locked = f.model.selected!!
    assertTrue(locked.isLocked && locked.retry?.remaining == 0)
    f.model.cancel()
    advanceUntilIdle()
    assertEquals(NativeLoginResult.Cancelled, f.results.single())
    assertEquals(listOf("000000", "111111"), (2..3).map { f.transport.field(it, "pin") })
  }

  @Test
  fun setPinAnswersBothFieldsAndItsErrorsAreLocalized() = runTest {
    val f = fixture({ json(200, METADATA) }, { pinSet("pin_setup") }, { pinSet("pin_setup", error = "weak_pin") })
    f.model.startIfNeeded()
    advanceUntilIdle()
    val setup = f.model.selected!!
    assertEquals(ChallengeType.PinSetup, setup.type)
    assertEquals(6, setup.pinSetupParams?.length)
    f.model.submit(ChallengeAnswer.PinSetup("135790", "135790"), setup)
    advanceUntilIdle()
    assertEquals("weak_pin", f.model.selected?.error?.code)
    assertEquals(listOf("135790", "135790", "pin_setup"), listOf(f.transport.field(2, "pin"), f.transport.field(2, "pin_confirm"), f.transport.field(2, "challenge_type")))
    assertEquals(R.string.nl_pin_mismatch, pinErrorText("pin_mismatch"))
    assertEquals(R.string.nl_pin_weak, pinErrorText("weak_pin"))
    assertEquals(R.string.nl_pin_invalid_format, pinErrorText("invalid_format"))
    assertNull("unknown codes keep the server's message", pinErrorText("x-other"))
  }

  @Test
  fun everyStringHasAGermanTranslation() {
    fun names(dir: String): Set<String> =
      Regex("""<(?:string|plurals) name="([a-z_]+)"""").findAll(java.io.File("src/main/res/$dir/strings.xml").readText()).map { it.groupValues[1] }.toSet()
    val english = names("values")
    assertTrue(english.containsAll(listOf("nl_use_pin", "nl_pin_title", "nl_pin_locked", "nl_pin_weak", "nl_delete")))
    assertEquals(emptySet<String>(), english - names("values-de"))
  }

  @Test
  fun redirectToWebBecomesItsOwnPhase() = runTest {
    val f = fixture(
      { json(200, METADATA) },
      { json(403, """{"error":"redirect_to_web","request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60,"redirect_uri":"demoapp://auth/callback","state":"st","reason":"required_action:UPDATE_PROFILE"}""") },
    )
    f.model.startIfNeeded()
    advanceUntilIdle()
    val phase = f.model.state.value.phase as NativeLoginModel.Phase.RedirectToWeb
    assertEquals("required_action:UPDATE_PROFILE", phase.request.reason)
  }

  @Test
  fun pushEnrollmentSignsWithTheDPoPKeyRegistersTheFcmTokenAndIsStoredOnceAccepted() = runTest {
    val b64 = { text: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray()) }
    val enrollmentToken = "eyJhbGciOiJub25lIn0." + b64("""{"sub":"u-1","username":"judy","enrollmentId":"e-1","nonce":"n-1","exp":4102444800}""") + "."
    val enroll = """{"type":"push_enrollment","id":"native-push-enroll","required":true,"params":{"enrollment_token":"$enrollmentToken","device_api_base":"https://idp.example.com/realms/demo/push-mfa","user_id":"u-1"}}"""
    val f = fixture(
      { json(200, METADATA) }, { set(enroll) }, { json(200, AUTHORIZED) }, { tokens() },
      dpop = DPoPMode.SOFTWARE,
      pushRegistration = { PushProviderRegistration("fcm", "fcm-token-1") },
    )
    f.model.startIfNeeded()
    advanceUntilIdle()
    assertEquals(ChallengeType.PushEnrollment, f.model.selected?.type)
    f.model.enrollPush(f.model.selected!!, "Judy's Pixel")
    advanceUntilIdle()
    assertTrue(f.results.single() is NativeLoginResult.Authorized)
    val claims = String(Base64.getUrlDecoder().decode(f.transport.field(2, "token")!!.split('.')[1]))
    for (expected in listOf("\"deviceType\":\"android\"", "\"pushProviderType\":\"fcm\"", "\"pushProviderId\":\"fcm-token-1\"", "\"enrollmentId\":\"e-1\"", "\"deviceLabel\":\"Judy's Pixel\"")) {
      assertTrue("$expected in $claims", claims.contains(expected))
    }
    val enrollment = f.kc.push().enrollment()!!
    assertEquals("u-1" to "judy", enrollment.userId to enrollment.username)
    assertEquals("fcm-token-1", enrollment.pushProviderId)
    assertEquals(f.kc.dpopKeyThumbprint(), enrollment.keyThumbprint)
  }

  @Test
  fun aRefusedPushEnrollmentIsNotStored() = runTest {
    val enrollmentToken = "eyJhbGciOiJub25lIn0." + Base64.getUrlEncoder().withoutPadding().encodeToString("""{"sub":"u-1","enrollmentId":"e-1","nonce":"n-1"}""".toByteArray()) + "."
    val enroll = """{"type":"push_enrollment","id":"native-push-enroll","required":true,"params":{"enrollment_token":"$enrollmentToken"}}"""
    val refused = """{"type":"push_enrollment","id":"native-push-enroll","required":true,"error":{"code":"invalid_credential"},"params":{"enrollment_token":"$enrollmentToken"}}"""
    val f = fixture({ json(200, METADATA) }, { set(enroll) }, { set(refused, session = "s2") }, dpop = DPoPMode.SOFTWARE)
    f.model.startIfNeeded()
    advanceUntilIdle()
    f.model.enrollPush(f.model.selected!!, "x")
    advanceUntilIdle()
    assertEquals("invalid_credential", f.model.selected?.error?.code)
    assertNull(f.kc.push().enrollment())
    val claims = String(Base64.getUrlDecoder().decode(f.transport.field(2, "token")!!.split('.')[1]))
    assertTrue("no registration: none", claims.contains("\"pushProviderType\":\"none\"") && !claims.contains("pushProviderId"))
  }
}
