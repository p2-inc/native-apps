package io.phasetwo.keycloak.nativeauth.flutter

import android.app.Activity
import android.content.Context
import androidx.activity.ComponentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.android.AuthTabWebPresenter
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerPasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerSavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreSecureStore
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FormField
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.RedirectToWebRequest
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.push.PushApprovalAction
import io.phasetwo.keycloak.nativeauth.sdk.push.PushEnrollment
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowLogEntry
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowObserver
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.lang.ref.WeakReference
import java.net.URI
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * The Android side of the Flutter plugin (spec/18): a thin bridge from the Pigeon host API to the
 * Android SDK. SDK instances, flows and credentials live here and are named to Dart by handles; the
 * refresh token and the post-login `auth_session` never cross the channel.
 *
 * Credential Manager prompts and the browser need the activity on screen. The browser fallback needs
 * a `ComponentActivity` (`FlutterFragmentActivity`), because `AuthTabWebPresenter` registers an
 * activity result launcher while the activity is created.
 */
public class KeycloakNativePlugin : FlutterPlugin, ActivityAware, KeycloakNativeHostApi {
  private lateinit var context: Context

  @Volatile
  private var activity: WeakReference<Activity> = WeakReference(null)

  /** Auth Tab presenters of the current activity, the normal one and the ephemeral one (no shared cookies). */
  @Volatile
  private var authTabs: Pair<AuthTabWebPresenter, AuthTabWebPresenter>? = null

  /** Why [authTabs] is missing, for the `web_fallback_failed` description. */
  @Volatile
  private var authTabUnavailable: String = "No activity is attached"

  private class Flow(val instance: KeycloakNative, val flow: NativeLoginFlow) {
    @Volatile
    var redirect: RedirectToWebRequest? = null
    val handles: MutableSet<String> = ConcurrentHashMap.newKeySet()
  }

  private val instances = ConcurrentHashMap<String, KeycloakNative>()

  /**
   * Per instance, the last error that handed back an `auth_session` (`reauthentication_required`,
   * `insufficient_authorization`): `continueAfterTokenChallenge` steps up with it, so the session
   * value never reaches Dart.
   */
  private val tokenChallenges = ConcurrentHashMap<String, NativeAuthError>()

  private var flutterApi: KeycloakNativeFlutterApi? = null
  private val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
  private val flows = ConcurrentHashMap<String, Flow>()

  /** Credentials a flow produced that Dart has not stored yet, by handle. */
  private val pendingCredentials = ConcurrentHashMap<String, Credentials>()

  // FlutterPlugin

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    context = binding.applicationContext
    KeycloakNativeHostApi.setUp(binding.binaryMessenger, this)
    flutterApi = KeycloakNativeFlutterApi(binding.binaryMessenger)
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    KeycloakNativeHostApi.setUp(binding.binaryMessenger, null)
    flutterApi = null
    flows.clear()
    pendingCredentials.clear()
  }

  // ActivityAware

  override fun onAttachedToActivity(binding: ActivityPluginBinding) = attach(binding.activity)

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = attach(binding.activity)

  override fun onDetachedFromActivityForConfigChanges() = detach()

  override fun onDetachedFromActivity() = detach()

  private fun attach(activity: Activity) {
    this.activity = WeakReference(activity)
    authTabs = null
    if (activity !is ComponentActivity) {
      authTabUnavailable = "The browser fallback needs a ComponentActivity: make MainActivity extend FlutterFragmentActivity"
      return
    }
    try {
      authTabs = AuthTabWebPresenter(activity) to AuthTabWebPresenter(activity, ephemeral = true)
    } catch (e: IllegalStateException) {
      // registerForActivityResult after the activity started (an engine attached late).
      authTabUnavailable = "The browser fallback could not register with the activity: ${e.message}"
    }
  }

  private fun detach() {
    activity = WeakReference(null)
    authTabs = null
    authTabUnavailable = "No activity is attached"
  }

  /** The SDK instances outlive the activity, so the browser goes through whichever activity is current. */
  private fun webPresenter(ephemeral: Boolean) = WebAuthenticationPresenter { url, redirectUri ->
    val presenters = authTabs ?: throw NativeAuthError(NativeAuthError.Code.WEB_FALLBACK_FAILED, errorDescription = authTabUnavailable)
    (if (ephemeral) presenters.second else presenters.first).authenticate(url, redirectUri)
  }

  // KeycloakNativeHostApi

  override fun configure(config: ConfigureMessage): String = bridged {
    val issuer = try {
      URI(config.issuer)
    } catch (e: Exception) {
      throw NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = "issuer is not a URI: ${config.issuer}", cause = e)
    }
    val current = { activity.get() }
    val options = KeycloakNative.Options(
      dpop = when (config.dpop) {
        DPoPModeMessage.AUTOMATIC -> DPoPMode.AUTOMATIC
        DPoPModeMessage.HARDWARE -> DPoPMode.HARDWARE
        DPoPModeMessage.SOFTWARE -> DPoPMode.SOFTWARE
        DPoPModeMessage.DISABLED -> DPoPMode.DISABLED
      },
      hardwareKeys = KeystoreDPoPKeys(context),
      allowRpIdMismatch = config.allowRpIdMismatch,
      secureStore = KeystoreSecureStore(context, namespace = config.storageNamespace ?: config.clientId),
      passkeyPlatform = CredentialManagerPasskeyPlatform(context, current),
      savedPasswordPlatform = CredentialManagerSavedPasswordPlatform(context, current),
      webPresenter = webPresenter(config.ephemeralWebSession),
      metadataCacheTtl = config.metadataCacheTtlSeconds?.seconds ?: KeycloakNative.Options().metadataCacheTtl,
    )
    val handle = UUID.randomUUID().toString()
    val observed = if (config.observeFlow == true) options.copy(flowObserver = flowObserver(handle)) else options
    instances[handle] = KeycloakNative.configure(issuer, config.clientId, observed)
    handle
  }

  /** Forwards the SDK's redacted flow log to Dart, on the main thread the channel needs. */
  private fun flowObserver(instance: String) = FlowObserver { entry ->
    mainScope.launch { runCatching { flutterApi?.onFlowLog(instance, entry.message()) } }
  }

  override fun startLogin(instance: String, parameters: LoginParametersMessage): String = bridged {
    val kc = instance(instance)
    register(kc, kc.authentication().startLogin(parameters.toSdk()))
  }

  override suspend fun stepUp(instance: String, parameters: LoginParametersMessage): String = bridgedSuspend {
    val kc = instance(instance)
    register(kc, kc.authentication().stepUp(parameters.toSdk()))
  }

  override suspend fun continueAfterTokenChallenge(instance: String, parameters: LoginParametersMessage): String = bridgedSuspend {
    val kc = instance(instance)
    val error = tokenChallenges.remove(instance)
      ?: throw NativeAuthError(NativeAuthError.Code.REAUTHENTICATION_REQUIRED, errorDescription = "No token challenge with an auth_session is pending; start a new login")
    register(kc, kc.authentication().continueAfterTokenChallenge(error, parameters.toSdk()))
  }

  override suspend fun start(flow: String): FlowStepMessage = bridgedSuspend {
    val record = flow(flow)
    record.message(record.flow.start())
  }

  override suspend fun respond(
    flow: String,
    challengeId: String,
    challengeType: String,
    answer: AnswerMessage,
    additionalFields: Map<String, String>,
  ): FlowStepMessage = bridgedSuspend {
    val record = flow(flow)
    val challenge = record.flow.pendingChallenges.firstOrNull { it.id == challengeId && it.type.wire == challengeType }
      ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Challenge $challengeType ($challengeId) is not in the pending set")
    record.message(record.flow.respond(answer.toSdk(), challenge, additionalFields))
  }

  override suspend fun cancel(flow: String) {
    flows[flow]?.flow?.cancel()
  }

  override fun disposeFlow(flow: String) {
    flows.remove(flow)?.handles?.forEach(pendingCredentials::remove)
  }

  override suspend fun completeWebFallback(flow: String): CredentialsMessage = bridgedSuspend {
    val record = flow(flow)
    val request = record.redirect ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "The flow has no redirect_to_web step")
    val credentials = record.instance.webFallback().complete(request, record.flow)
    record.redirect = null
    record.hold(credentials)
  }

  override suspend fun storeCredentials(instance: String, handle: String) = bridgedSuspend {
    val credentials = pendingCredentials.remove(handle)
      ?: throw NativeAuthError(NativeAuthError.Code.CREDENTIALS_NOT_FOUND, errorDescription = "Unknown or already stored credentials")
    instance(instance).credentialsManager().store(credentials)
  }

  override suspend fun storedCredentials(instance: String): CredentialsMessage? = bridgedSuspend {
    instance(instance).credentialsManager().stored()?.let { message(it, handle = "") }
  }

  override suspend fun credentials(instance: String, minTtlSeconds: Long): CredentialsMessage = bridgedSuspend {
    rememberingTokenChallenge(instance) { message(instance(instance).credentialsManager().credentials(minTtlSeconds.seconds), handle = "") }
  }

  override suspend fun hasValidCredentials(instance: String, minTtlSeconds: Long): Boolean = bridgedSuspend {
    instance(instance).credentialsManager().hasValid(minTtlSeconds.seconds)
  }

  override suspend fun logout(instance: String) = bridgedSuspend { instance(instance).credentialsManager().logout() }

  override suspend fun clearCredentials(instance: String) = bridgedSuspend { instance(instance).credentialsManager().clear() }

  override suspend fun resourceRequestHeaders(instance: String, method: String, url: String): Map<String, String> = bridgedSuspend {
    val kc = instance(instance)
    rememberingTokenChallenge(instance) { kc.resourceRequestHeaders(kc.credentialsManager().credentials(), method, URI(url)) }
  }

  override suspend fun dpopKeyThumbprint(instance: String): String? = bridgedSuspend { instance(instance).dpopKeyThumbprint() }

  override suspend fun metadataJson(instance: String, forceRefresh: Boolean): String = bridgedSuspend {
    instance(instance).metadata(forceRefresh).raw?.toString() ?: "{}"
  }

  // Ceremonies that answer a challenge natively

  override suspend fun usePasskey(flow: String, challengeId: String, preferImmediatelyAvailableCredentials: Boolean): FlowStepMessage = bridgedSuspend {
    val record = flow(flow)
    val challenge = record.pending(challengeId, ChallengeType.Passkey)
    val params = challenge.passkeyParams ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "passkey challenge without usable params")
    val assertion = record.instance.passkeys().assert(params, preferImmediatelyAvailableCredentials)
    record.message(record.flow.respond(ChallengeAnswer.Passkey(assertion), challenge))
  }

  override suspend fun registerPasskey(flow: String, challengeId: String, label: String?): FlowStepMessage = bridgedSuspend {
    val record = flow(flow)
    val challenge = record.pending(challengeId, ChallengeType.PasskeyRegistration)
    val params = challenge.passkeyRegistrationParams
      ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "passkey_registration challenge without usable params")
    val attestation = record.instance.passkeys().register(params)
    record.message(record.flow.respond(ChallengeAnswer.PasskeyRegistration(attestation, label), challenge))
  }

  override suspend fun enrollPush(
    flow: String,
    challengeId: String,
    deviceLabel: String,
    pushProviderType: String,
    pushProviderId: String?,
  ): FlowStepMessage = bridgedSuspend {
    val record = flow(flow)
    val challenge = record.pending(challengeId, ChallengeType.PushEnrollment)
    val params = challenge.pushEnrollmentParams ?: throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, errorDescription = "push_enrollment challenge without params")
    val push = record.instance.push()
    val prepared = push.prepareEnrollment(params, deviceLabel, pushProviderType, pushProviderId)
    val step = record.flow.respond(prepared.answer, challenge)
    // Kept only once the server moved on from the challenge (the iOS and Android UI models do the same).
    if (step.challenges.orEmpty().none { it.type == ChallengeType.PushEnrollment && it.error != null }) push.commit(prepared)
    record.message(step)
  }

  // Passkeys and passwords outside a flow

  override suspend fun registerNewPasskey(instance: String, label: String?): RegisteredPasskeyMessage = bridgedSuspend {
    val kc = instance(instance)
    rememberingTokenChallenge(instance) {
      val registered = kc.passkeys().registerNewPasskey(label, kc.credentialsManager().credentials())
      RegisteredPasskeyMessage(registered.credentialId, registered.label)
    }
  }

  override suspend fun pickSavedPassword(instance: String): SavedPasswordMessage = bridgedSuspend {
    val saved = instance(instance).pickSavedPassword()
    SavedPasswordMessage(saved.username, saved.password)
  }

  override suspend fun savePassword(instance: String, username: String, password: String) = bridgedSuspend {
    instance(instance).savePassword(username, password)
  }

  // Push

  override suspend fun pushEnrollment(instance: String): PushEnrollmentMessage? = bridgedSuspend { instance(instance).push().enrollment()?.message() }

  override suspend fun pushEnroll(instance: String, deviceLabel: String, pushProviderType: String, pushProviderId: String?): PushEnrollmentMessage = bridgedSuspend {
    instance(instance).push().enroll(deviceLabel, pushProviderType, pushProviderId).message()
  }

  override suspend fun pushForgetEnrollment(instance: String) = bridgedSuspend { instance(instance).push().forgetEnrollment() }

  override suspend fun pushPendingApprovals(instance: String): List<PendingApprovalMessage> = bridgedSuspend {
    instance(instance).push().pendingApprovals().map { PendingApprovalMessage(it.cid, it.raw.toString()) }
  }

  override suspend fun pushRespond(instance: String, cid: String, approve: Boolean, userVerification: String?): String = bridgedSuspend {
    instance(instance).push().respond(cid, if (approve) PushApprovalAction.Approve(userVerification) else PushApprovalAction.Deny)
  }

  override suspend fun pushHandleMessage(instance: String, data: Map<String, String>): PushNotificationMessage? = bridgedSuspend {
    instance(instance).push().handleMessage(data)?.let { PushNotificationMessage(it.cid, it.credentialId, it.expiresAt?.dartMillis()) }
  }

  override suspend fun pushUpdateProvider(instance: String, type: String, id: String) = bridgedSuspend { instance(instance).push().updatePushProvider(type, id) }

  override suspend fun pushRotateKey(instance: String) = bridgedSuspend { instance(instance).push().rotateKey() }

  override suspend fun pushLockout(instance: String) = bridgedSuspend { instance(instance).push().lockout() }

  // ---

  /** Keeps an error that carries an `auth_session` for `continueAfterTokenChallenge`. */
  private suspend fun <T> rememberingTokenChallenge(instance: String, body: suspend () -> T): T = try {
    body()
  } catch (e: NativeAuthError) {
    if (e.authSession != null) tokenChallenges[instance] = e
    throw e
  }

  private fun Flow.pending(challengeId: String, type: ChallengeType) =
    flow.pendingChallenges.firstOrNull { it.id == challengeId && it.type == type }
      ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Challenge ${type.wire} ($challengeId) is not in the pending set")

  private fun instance(handle: String): KeycloakNative =
    instances[handle] ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Unknown KeycloakNative instance; call configure first")

  private fun flow(handle: String): Flow =
    flows[handle] ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Unknown or disposed flow")

  private fun register(kc: KeycloakNative, flow: NativeLoginFlow): String {
    val handle = UUID.randomUUID().toString()
    flows[handle] = Flow(kc, flow)
    return handle
  }

  private fun Flow.message(step: FlowStep): FlowStepMessage = when (step) {
    is FlowStep.Challenges -> FlowStepMessage(
      kind = FlowStepKind.CHALLENGES,
      challenges = step.challenges.map { it.message() },
      contextJson = step.context.raw.toString(),
    )
    is FlowStep.Authorized -> FlowStepMessage(kind = FlowStepKind.AUTHORIZED, challenges = emptyList(), credentials = hold(step.credentials))
    is FlowStep.RedirectToWeb -> {
      redirect = step.request
      FlowStepMessage(kind = FlowStepKind.REDIRECT_TO_WEB, challenges = emptyList(), redirectToWeb = step.request.message())
    }
  }

  private fun Flow.hold(credentials: Credentials): CredentialsMessage {
    val handle = UUID.randomUUID().toString()
    pendingCredentials[handle] = credentials
    handles += handle
    return message(credentials, handle)
  }
}

/** Wraps a host call so a [NativeAuthError] reaches Dart as a `PlatformException` with its code. */
private inline fun <T> bridged(body: () -> T): T = try {
  body()
} catch (e: NativeAuthError) {
  throw e.toFlutterError()
}

private suspend inline fun <T> bridgedSuspend(crossinline body: suspend () -> T): T = try {
  body()
} catch (e: CancellationException) {
  throw e
} catch (e: NativeAuthError) {
  throw e.toFlutterError()
}

internal fun NativeAuthError.toFlutterError(): FlutterError = FlutterError(
  code,
  errorDescription ?: code,
  mapOf(
    "statusCode" to statusCode?.toLong(),
    "isNetworkError" to isNetworkError,
    "isRetryable" to isRetryable,
    "retryAfter" to retryAfter,
    "maxAge" to maxAge?.toLong(),
    "detailsJson" to details?.toString(),
  ),
)

internal fun LoginParametersMessage.toSdk(): LoginParameters = LoginParameters(
  scope = scope,
  acrValues = acrValues,
  loginHint = loginHint,
  prompt = prompt,
  maxAge = maxAge?.toInt(),
  nonce = nonce,
  uiLocales = uiLocales,
  deviceName = deviceName,
  deviceId = deviceId,
  additionalParameters = additionalParameters,
  continuationParameters = continuationParameters,
)

internal fun AnswerMessage.toSdk(): ChallengeAnswer {
  fun required(name: String, value: String?): String =
    value ?: throw NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = "A $kind answer needs $name")
  return when (kind) {
    AnswerKind.USERNAME -> ChallengeAnswer.Username(required("value", value))
    AnswerKind.PASSWORD -> ChallengeAnswer.Password(required("value", value))
    AnswerKind.TOTP -> ChallengeAnswer.Totp(required("value", value), credentialId)
    AnswerKind.OTP -> ChallengeAnswer.Otp(required("value", value))
    AnswerKind.OTP_RESEND -> ChallengeAnswer.OtpResend
    AnswerKind.UPDATE_PASSWORD -> ChallengeAnswer.UpdatePassword(required("value", value), required("confirm", confirm))
    AnswerKind.VERIFY_EMAIL -> ChallengeAnswer.VerifyEmail(required("value", value))
    AnswerKind.VERIFY_EMAIL_RESEND -> ChallengeAnswer.VerifyEmailResend
    AnswerKind.TERMS -> ChallengeAnswer.Terms(accepted ?: false)
    AnswerKind.RECOVERY_CODE -> ChallengeAnswer.RecoveryCode(required("value", value))
    AnswerKind.PUSH_RESEND -> ChallengeAnswer.PushResend
    AnswerKind.PUSH_POLL -> ChallengeAnswer.PushPoll
    AnswerKind.PUSH_ENROLLMENT_CHECK -> ChallengeAnswer.PushEnrollmentCheck
    AnswerKind.SKIP -> ChallengeAnswer.Skip(ChallengeType.fromWire(required("type", type)))
    AnswerKind.CUSTOM -> ChallengeAnswer.Custom(ChallengeType.fromWire(required("type", type)), fields.orEmpty().map { FormField(it.name, it.value) })
  }
}

internal fun io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge.message(): ChallengeMessage = ChallengeMessage(
  id = id,
  type = type.wire,
  label = label,
  required = required,
  errorCode = error?.code,
  errorMessage = error?.message,
  hasRetry = retry != null,
  retryRemaining = retry?.remaining?.toLong(),
  skippable = isSkippable,
  paramsJson = params.toString(),
)

internal fun RedirectToWebRequest.message(): RedirectToWebMessage = RedirectToWebMessage(
  redirectUri = redirectUri,
  expiresIn = expiresIn?.toLong(),
  state = state,
  reason = reason,
  errorDescription = errorDescription,
  rawJson = raw.toString(),
)

/** Dart's `DateTime` ends at 8.64e15 ms; offline tokens carry `Instant.MAX`. */
private const val MAX_DART_MILLIS = 8_640_000_000_000_000L

internal fun Instant.dartMillis(): Long = if (epochSecond >= MAX_DART_MILLIS / 1000) MAX_DART_MILLIS else toEpochMilli()

internal fun message(credentials: Credentials, handle: String): CredentialsMessage = CredentialsMessage(
  handle = handle,
  accessToken = credentials.accessToken,
  tokenType = credentials.tokenType,
  idToken = credentials.idToken,
  scope = credentials.scope,
  expiresAtMillis = credentials.expiresAt.dartMillis(),
  refreshExpiresAtMillis = credentials.refreshExpiresAt?.dartMillis(),
  issuedAtMillis = credentials.issuedAt.dartMillis(),
  hasRefreshToken = credentials.refreshToken != null,
)

internal fun PushEnrollment.message(): PushEnrollmentMessage = PushEnrollmentMessage(
  credentialId = credentialId,
  deviceId = deviceId,
  userId = userId,
  username = username,
  deviceLabel = deviceLabel,
  pushProviderType = pushProviderType,
  pushProviderId = pushProviderId,
  deviceApiBase = deviceApiBase.toString(),
  keyThumbprint = keyThumbprint,
  enrolledAtMillis = enrolledAt.dartMillis(),
)

internal fun FlowLogEntry.message(): FlowLogMessage = FlowLogMessage(
  id = id.toString(),
  timestampMillis = timestamp.dartMillis(),
  method = method,
  url = url.toString(),
  requestHeaders = requestHeaders,
  requestBody = requestBody,
  statusCode = statusCode?.toLong(),
  responseHeaders = responseHeaders,
  responseBody = responseBody,
  durationMilliseconds = durationMilliseconds,
  errorCode = errorCode,
)
