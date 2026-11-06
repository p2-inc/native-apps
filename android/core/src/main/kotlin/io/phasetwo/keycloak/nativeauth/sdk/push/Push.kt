package io.phasetwo.keycloak.nativeauth.sdk.push

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PushEnrollmentParams
import io.phasetwo.keycloak.nativeauth.sdk.config.NativeAuthMetadata
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DeviceJwt
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Base64Url
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.arrayValue
import io.phasetwo.keycloak.nativeauth.sdk.json.doubleValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.longValue
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Push MFA for this device (spec/05 §5, spec/03 §4.7, §4.15, §7; spec/14 D9): enrollment from inside
 * the app or mid-flow, the pending approvals of the user, approve / deny with number match, push
 * token sync, key rotation and the panic lockout. The device key is the SDK's DPoP key and the
 * device token is the user's DPoP-bound native access token ([DeviceTokenProvider]). The FCM side
 * (registration token, messages) is in the `push` module.
 */
public class Push internal constructor(
  private val kc: KeycloakNative,
  private val tokenProvider: DeviceTokenProvider,
  /** `deviceType` of the device JWT: `android`, or `ios` for a client that speaks for an iPhone. */
  private val deviceType: String,
) {
  private val logger = kc.options.logger
  private val storeKey = kc.scopedStorageKey("push-enrollment")

  // Local state

  /** The stored enrollment of this device, if any. */
  public suspend fun enrollment(): PushEnrollment? = kc.secureStore.data(storeKey)?.let(::decode)

  public suspend fun isEnrolled(): Boolean = enrollment() != null

  /** Forgets the local enrollment (the server credential stays; an admin removes it). */
  public suspend fun forgetEnrollment() {
    kc.secureStore.remove(storeKey)
  }

  internal suspend fun store(enrollment: PushEnrollment) {
    kc.secureStore.set(storeKey, encode(enrollment))
  }

  /** The server's `push` metadata block; `push_unavailable` when the extension is not installed. */
  public suspend fun metadata(): NativeAuthMetadata.Push {
    val push = kc.metadata().push
    if (push == null || !push.enabled) throw NativeAuthError(NativeAuthError.Code.PUSH_UNAVAILABLE, errorDescription = "The server advertises no push block (spec/03 §1.1)")
    return push
  }

  // Enrollment

  /**
   * Scenario C (spec/02 §3): `POST /native-auth/push/enroll/start` with the native token, then
   * `POST {device_api_base}/enroll/complete` with a device JWT signed by the DPoP key. The enrollment
   * is stored on success. [pushProviderType] `fcm` needs the FCM registration token as
   * [pushProviderId]; `none` enrolls a device that pulls its approvals.
   */
  public suspend fun enroll(deviceLabel: String, pushProviderType: String = "none", pushProviderId: String? = null): PushEnrollment {
    val push = metadata()
    val startUrl = push.enrollStartEndpoint ?: kc.issuer.resolvePath("native-auth/push/enroll/start")
    val token = tokenProvider.deviceToken()
    val start = send("POST", startUrl, null, token, deviceId = null, userId = null)
    val json = start.json
    val enrollmentToken = json["enrollment_token"].stringValue
    if (start.statusCode != 200 || enrollmentToken == null) throw error(start, NativeAuthError.Code.INVALID_RESPONSE)
    val base = json["device_api_base"].stringValue?.let { runCatching { URI(it) }.getOrNull() } ?: push.deviceApiBase ?: kc.issuer.resolvePath("push-mfa")
    val prepared = prepare(enrollmentToken, json["user_id"].stringValue, base, deviceLabel, pushProviderType, pushProviderId)
    val body = jsonBody("token" to JsonPrimitive(prepared.answer.token))
    val complete = send("POST", base.resolvePath("enroll/complete"), body, token, prepared.enrollment.deviceId, prepared.enrollment.userId)
    if (complete.statusCode != 200 && complete.statusCode != 201) throw error(complete, NativeAuthError.Code.INVALID_RESPONSE)
    store(prepared.enrollment)
    logger.log(LogLevel.INFO) { "Push MFA enrolled (credential ${prepared.enrollment.credentialId}, provider $pushProviderType)" }
    return prepared.enrollment
  }

  /**
   * The §4.15 answer for a `push_enrollment` challenge: the device JWT signed by the DPoP key. Call
   * [commit] once the flow accepted it (the next step is not an error on this challenge).
   */
  public suspend fun prepareEnrollment(
    params: PushEnrollmentParams,
    deviceLabel: String,
    pushProviderType: String = "none",
    pushProviderId: String? = null,
  ): PreparedPushEnrollment {
    val token = params.enrollmentToken
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "push_enrollment challenge without enrollment_token")
    val base = params.deviceApiBase ?: runCatching { metadata().deviceApiBase }.getOrNull() ?: kc.issuer.resolvePath("push-mfa")
    return prepare(token, params.userId, base, deviceLabel, pushProviderType, pushProviderId)
  }

  /** Stores a prepared mid-flow enrollment the server accepted. */
  public suspend fun commit(prepared: PreparedPushEnrollment) {
    store(prepared.enrollment)
    logger.log(LogLevel.INFO) { "Push MFA enrolled in-flow (credential ${prepared.enrollment.credentialId})" }
  }

  private suspend fun prepare(
    enrollmentToken: String,
    userId: String?,
    deviceApiBase: URI,
    deviceLabel: String,
    pushProviderType: String,
    pushProviderId: String?,
  ): PreparedPushEnrollment {
    val claims = Jwt.decodePayload(enrollmentToken)
    val enrollmentId = claims["enrollmentId"].stringValue
    val nonce = claims["nonce"].stringValue
    if (enrollmentId == null || nonce == null) {
      throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "Enrollment token without enrollmentId / nonce")
    }
    claims["exp"].doubleValue?.let { exp ->
      // The server is the authority (it answers expired_code / 400); this only helps diagnostics.
      if (exp <= Instant.now().epochSecond) logger.log(LogLevel.WARNING) { "The enrollment token looks expired (exp ${exp.toLong()}); the server will decide" }
    }
    val sub = claims["sub"].stringValue ?: userId
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "Enrollment token without sub")
    if (pushProviderType != "none" && pushProviderId.isNullOrEmpty()) {
      throw NativeAuthError(NativeAuthError.Code.INVALID_REQUEST, errorDescription = "pushProviderId (the push token) is required for pushProviderType $pushProviderType")
    }
    val key = kc.dpopKey()
    val deviceId = enrollment()?.deviceId ?: UUID.randomUUID().toString()
    val credentialId = Base64Url.encode(ByteArray(16).also(random::nextBytes))
    val jwk = JsonObject(key.publicJwk.json + ("alg" to JsonPrimitive(key.algorithm)))
    val payload = linkedMapOf<String, JsonElement>(
      "sub" to JsonPrimitive(sub),
      "enrollmentId" to JsonPrimitive(enrollmentId),
      "nonce" to JsonPrimitive(nonce),
      "exp" to JsonPrimitive(Instant.now().epochSecond + 120),
      "cnf" to JsonObject(mapOf("jwk" to jwk)),
      "credentialId" to JsonPrimitive(credentialId),
      "deviceId" to JsonPrimitive(deviceId),
      "deviceType" to JsonPrimitive(deviceType),
      "deviceLabel" to JsonPrimitive(deviceLabel),
      "pushProviderType" to JsonPrimitive(pushProviderType),
    )
    if (!pushProviderId.isNullOrEmpty()) payload["pushProviderId"] = JsonPrimitive(pushProviderId)
    val enrollment = PushEnrollment(
      credentialId = credentialId,
      deviceId = deviceId,
      userId = sub,
      username = claims["username"].stringValue,
      deviceLabel = deviceLabel,
      pushProviderType = pushProviderType,
      pushProviderId = pushProviderId,
      deviceApiBase = deviceApiBase,
      keyThumbprint = key.publicJwk.thumbprint,
    )
    return PreparedPushEnrollment(ChallengeAnswer.PushEnrollment(DeviceJwt.sign(payload, key)), enrollment)
  }

  // Approvals

  /**
   * `GET {device_api_base}/login/pending?userId=…`: what is waiting for this user. Poll it when the
   * app opens or resumes: a backgrounded app only sees the FCM data when the user taps the
   * notification, and pushes may be delayed or dropped (spec/03 §7 "Receive push").
   */
  public suspend fun pendingApprovals(): List<PendingApproval> {
    val enrollment = requireEnrollment()
    val token = tokenProvider.deviceToken()
    val url = URI.create(enrollment.deviceApiBase.resolvePath("login/pending").toString() + "?userId=" + URLEncoder.encode(enrollment.userId, "UTF-8"))
    val response = send("GET", url, null, token, enrollment.deviceId, enrollment.userId)
    val json = response.json
    if (response.statusCode != 200 || json == null) throw error(response, NativeAuthError.Code.INVALID_RESPONSE)
    return json["challenges"].arrayValue.orEmpty().mapNotNull(PendingApproval::parse)
  }

  /**
   * `POST …/login/challenges/{cid}/respond` with a device JWT (`cid`, `credId`, `deviceId`, `action`,
   * `userVerification?`, `exp`). Returns the server's `status` (`approved` / `denied`). Number
   * mismatch → `user_verification_mismatch`; resolved meanwhile → `push_conflict`.
   */
  public suspend fun respond(approval: PendingApproval, action: PushApprovalAction): String = respond(approval.cid, action)

  public suspend fun respond(cid: String, action: PushApprovalAction): String {
    val enrollment = requireEnrollment()
    val token = tokenProvider.deviceToken()
    val key = kc.dpopKey()
    val payload = linkedMapOf<String, JsonElement>(
      "cid" to JsonPrimitive(cid),
      "credId" to JsonPrimitive(enrollment.credentialId),
      "deviceId" to JsonPrimitive(enrollment.deviceId),
      "action" to JsonPrimitive(action.wire),
      "exp" to JsonPrimitive(Instant.now().epochSecond + 120),
    )
    if (action is PushApprovalAction.Approve && action.userVerification != null) payload["userVerification"] = JsonPrimitive(action.userVerification)
    val body = jsonBody("token" to JsonPrimitive(DeviceJwt.sign(payload, key)))
    val response = send("POST", enrollment.deviceApiBase.resolvePath("login/challenges/$cid/respond"), body, token, enrollment.deviceId, enrollment.userId)
    val status = response.json["status"].stringValue
    if (response.statusCode != 200 || status == null) {
      throw when (response.statusCode) {
        403 -> error(response, NativeAuthError.Code.USER_VERIFICATION_MISMATCH)
        409 -> error(response, NativeAuthError.Code.PUSH_CONFLICT)
        else -> error(response, NativeAuthError.Code.INVALID_RESPONSE)
      }
    }
    logger.log(LogLevel.INFO) { "Push challenge $cid: $status" }
    return status
  }

  /**
   * Decodes a push-MFA message (`RemoteMessage.data`). `null` when it is not one, or it is for another
   * credential than this device's.
   */
  public suspend fun handleMessage(data: Map<String, String>): PushNotificationPayload? {
    val payload = PushNotificationPayload.parse(data) ?: return null
    val enrollment = enrollment()
    if (payload.credentialId != null && enrollment != null && payload.credentialId != enrollment.credentialId) {
      logger.log(LogLevel.INFO) { "Push message for another credential; ignored" }
      return null
    }
    return payload
  }

  /** The pending approval a message refers to, if it is still open. */
  public suspend fun pendingApproval(payload: PushNotificationPayload): PendingApproval? = pendingApprovals().firstOrNull { it.cid == payload.cid }

  // Maintenance (spec/03 §7 "Maintenance")

  /**
   * `PUT …/device/push-provider`, e.g. from `FirebaseMessagingService.onNewToken` with `fcm`; `none`
   * tells the server to skip delivery (the app then pulls its approvals). No request when nothing
   * changed locally.
   */
  public suspend fun updatePushProvider(type: String, id: String) {
    val enrollment = requireEnrollment()
    if (enrollment.pushProviderType == type && enrollment.pushProviderId == id) return
    val token = tokenProvider.deviceToken()
    val body = jsonBody("pushProviderId" to JsonPrimitive(id), "pushProviderType" to JsonPrimitive(type))
    val response = send("PUT", enrollment.deviceApiBase.resolvePath("device/push-provider"), body, token, enrollment.deviceId, enrollment.userId)
    if (response.statusCode != 200) throw error(response, NativeAuthError.Code.INVALID_RESPONSE)
    store(enrollment.copy(pushProviderType = type, pushProviderId = id))
    logger.log(LogLevel.INFO) { "Push provider updated ($type): ${response.json["status"].stringValue ?: "?"}" }
  }

  /**
   * `PUT …/device/rotate-key`: a fresh DPoP key is registered with a proof signed by the current one,
   * then becomes the DPoP key (spec/14 D9). The stored native tokens were bound to the old key and are
   * cleared: the user signs in again, which binds new tokens to the new key.
   */
  public suspend fun rotateKey() {
    val enrollment = requireEnrollment()
    val token = tokenProvider.deviceToken()
    val newKey = kc.prepareDPoPKeyRotation()
    val jwk = JsonObject(newKey.publicJwk.json + ("alg" to JsonPrimitive(newKey.algorithm)))
    val response = send("PUT", enrollment.deviceApiBase.resolvePath("device/rotate-key"), jsonBody("publicKeyJwk" to jwk), token, enrollment.deviceId, enrollment.userId)
    if (response.statusCode != 200) throw error(response, NativeAuthError.Code.INVALID_RESPONSE)
    kc.commitDPoPKeyRotation(newKey)
    store(enrollment.copy(keyThumbprint = newKey.publicJwk.thumbprint))
    runCatching { kc.credentialsManager().clear() }
    logger.log(LogLevel.INFO) { "Push device key rotated; a new login is needed to bind tokens to it" }
  }

  /** `POST …/login/lockout`: the panic button. ba-itsys disables the user account; an admin re-enables it. */
  public suspend fun lockout() {
    val enrollment = requireEnrollment()
    val token = tokenProvider.deviceToken()
    val response = send("POST", enrollment.deviceApiBase.resolvePath("login/lockout"), null, token, enrollment.deviceId, enrollment.userId)
    if (response.statusCode != 200) throw error(response, NativeAuthError.Code.INVALID_RESPONSE)
    logger.log(LogLevel.WARNING) { "Account locked out from this device" }
  }

  // Transport

  private suspend fun requireEnrollment(): PushEnrollment =
    enrollment() ?: throw NativeAuthError(NativeAuthError.Code.PUSH_NOT_ENROLLED, errorDescription = "This device is not enrolled for push MFA")

  /** `Authorization: <scheme> <token>` plus a DPoP proof with `ath`, `sub` and `deviceId` (spec/03 §7.1); one retry on `use_dpop_nonce`. */
  private suspend fun send(method: String, url: URI, body: ByteArray?, token: DeviceToken, deviceId: String?, userId: String?): HttpResponse {
    var response = kc.transport.send(request(method, url, body, token, deviceId, userId))
    response.dpopNonceChallenge?.let { nonce ->
      kc.rememberDPoPNonce(nonce, url)
      response = kc.transport.send(request(method, url, body, token, deviceId, userId))
    }
    return response
  }

  private suspend fun request(method: String, url: URI, body: ByteArray?, token: DeviceToken, deviceId: String?, userId: String?): HttpRequest {
    val headers = linkedMapOf("Accept" to "application/json", "Authorization" to "${token.scheme} ${token.accessToken}")
    if (body != null) headers["Content-Type"] = "application/json"
    val extra = buildMap<String, JsonElement> {
      userId?.let { put("sub", JsonPrimitive(it)) }
      deviceId?.let { put("deviceId", JsonPrimitive(it)) }
    }
    kc.dpopProof(method, url, token.accessToken, extra)?.let { headers["DPoP"] = it }
    return HttpRequest(method, url, headers, body)
  }

  /**
   * ba-itsys puts a sentence in `error` ("User verification mismatch"), not a code, so the code is
   * chosen here from the status and the server's text becomes the description.
   */
  private fun error(response: HttpResponse, code: String): NativeAuthError {
    val json = response.json
    return NativeAuthError(
      code = if (response.statusCode == 401) NativeAuthError.Code.INVALID_TOKEN else code,
      statusCode = response.statusCode,
      errorDescription = json["error_description"].stringValue ?: json["error"].stringValue ?: "HTTP ${response.statusCode} from the push device API",
      details = json,
      isRetryable = response.statusCode >= 500,
    )
  }

  private companion object {
    val random = SecureRandom()

    fun jsonBody(vararg fields: Pair<String, JsonElement>): ByteArray = JsonObject(linkedMapOf(*fields)).serialized().toByteArray(StandardCharsets.UTF_8)

    fun URI.resolvePath(path: String): URI = URI.create(toString().trimEnd('/') + "/" + path)

    fun encode(e: PushEnrollment): ByteArray = JsonObject(
      linkedMapOf(
        "credentialId" to JsonPrimitive(e.credentialId),
        "deviceId" to JsonPrimitive(e.deviceId),
        "userId" to JsonPrimitive(e.userId),
        "username" to (e.username?.let(::JsonPrimitive) ?: JsonNull),
        "deviceLabel" to JsonPrimitive(e.deviceLabel),
        "pushProviderType" to JsonPrimitive(e.pushProviderType),
        "pushProviderId" to (e.pushProviderId?.let(::JsonPrimitive) ?: JsonNull),
        "deviceApiBase" to JsonPrimitive(e.deviceApiBase.toString()),
        "keyThumbprint" to JsonPrimitive(e.keyThumbprint),
        "enrolledAt" to JsonPrimitive(e.enrolledAt.toEpochMilli()),
      ),
    ).serialized().toByteArray(StandardCharsets.UTF_8)

    /** `null` for an entry this version cannot read; the device is then treated as not enrolled. */
    fun decode(bytes: ByteArray): PushEnrollment? {
      val json = parseJsonOrNull(bytes) ?: return null
      return PushEnrollment(
        credentialId = json["credentialId"].stringValue ?: return null,
        deviceId = json["deviceId"].stringValue ?: return null,
        userId = json["userId"].stringValue ?: return null,
        username = json["username"].stringValue,
        deviceLabel = json["deviceLabel"].stringValue.orEmpty(),
        pushProviderType = json["pushProviderType"].stringValue ?: "none",
        pushProviderId = json["pushProviderId"].stringValue,
        deviceApiBase = json["deviceApiBase"].stringValue?.let { runCatching { URI(it) }.getOrNull() } ?: return null,
        keyThumbprint = json["keyThumbprint"].stringValue.orEmpty(),
        enrolledAt = json["enrolledAt"].longValue?.let(Instant::ofEpochMilli) ?: Instant.EPOCH,
      )
    }
  }
}
