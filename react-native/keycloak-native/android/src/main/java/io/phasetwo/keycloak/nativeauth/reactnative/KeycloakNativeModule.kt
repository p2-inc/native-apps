package io.phasetwo.keycloak.nativeauth.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerPasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.CredentialManagerSavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.android.KeystoreSecureStore
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.RedirectToWebRequest
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.net.URI
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The TurboModule over the Android SDK (spec/19 §4–§5). Each JavaScript `KeycloakNative` is one SDK
 * instance here, with the `android` module's platform pieces: `KeystoreSecureStore`,
 * `KeystoreDPoPKeys`, the Credential Manager passkey and saved-password platforms (anchored on the
 * React activity on screen) and the Auth Tab browser fallback registered by [KeycloakNativeActivity].
 * Each flow stays here, with its PKCE verifier and pending challenges; JavaScript holds its id.
 *
 * Suspend functions run on [scope] and settle the promise; the scope is cancelled with the React
 * instance. The SDK switches to the main thread itself where a platform API needs it.
 */
class KeycloakNativeModule(private val reactContext: ReactApplicationContext) : NativeKeycloakNativeSpec(reactContext) {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
  private val instances = ConcurrentHashMap<String, KeycloakNative>()
  private val flows = ConcurrentHashMap<String, FlowHandle>()

  /** A flow and what it ended with, for the browser fallback and `storeCredentials`. */
  private class FlowHandle(val kc: KeycloakNative, val flow: NativeLoginFlow) {
    @Volatile var redirect: RedirectToWebRequest? = null

    @Volatile var credentials: Credentials? = null
  }

  override fun configure(instanceId: String, config: String, promise: Promise) = settle(promise) {
    val c = BridgeJson.config(config)
    val context = reactContext.applicationContext
    val currentActivity = { reactContext.currentActivity }
    val options = KeycloakNative.Options(
      dpop = c.dpop,
      hardwareKeys = KeystoreDPoPKeys(context),
      allowRpIdMismatch = c.allowRpIdMismatch,
      secureStore = KeystoreSecureStore(context, namespace = c.storageNamespace ?: c.clientId),
      passkeyPlatform = CredentialManagerPasskeyPlatform(context, currentActivity),
      savedPasswordPlatform = CredentialManagerSavedPasswordPlatform(context, currentActivity),
      webPresenter = WebAuthenticationPresenter { url, redirectUri ->
        KeycloakNativeActivity.presenter(c.ephemeralWebSession).authenticate(url, redirectUri)
      },
      metadataCacheTtl = (c.metadataCacheTtlSeconds ?: 300L).seconds,
    )
    instances[instanceId] = KeycloakNative.configure(URI(c.issuer), c.clientId, options)
    null
  }

  override fun createFlow(instanceId: String, parameters: String, stepUp: Boolean, promise: Promise) = settle(promise) {
    val kc = instance(instanceId)
    val loginParameters = BridgeJson.loginParameters(parameters)
    val flow = if (stepUp) kc.authentication().stepUp(loginParameters) else kc.authentication().startLogin(loginParameters)
    val id = UUID.randomUUID().toString()
    flows[id] = FlowHandle(kc, flow)
    id
  }

  override fun start(flowId: String, promise: Promise) = settle(promise) {
    val handle = flow(flowId)
    handle.encode(handle.flow.start())
  }

  override fun respond(flowId: String, challengeId: String, challengeType: String, answer: String, additionalFields: String, promise: Promise) =
    settle(promise) {
      val handle = flow(flowId)
      val type = ChallengeType.fromWire(challengeType)
      val challenge = handle.flow.pendingChallenges.firstOrNull { it.id == challengeId && it.type == type }
        ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Challenge $challengeType is not in the pending set")
      val step = handle.flow.respond(BridgeJson.answer(answer, type), challenge, BridgeJson.stringMap(BridgeJson.parseObject(additionalFields)))
      handle.encode(step)
    }

  override fun cancel(flowId: String, promise: Promise) = settle(promise) {
    flows[flowId]?.flow?.cancel()
    null
  }

  override fun completeWebFallback(flowId: String, promise: Promise) = settle(promise) {
    val handle = flow(flowId)
    val request = handle.redirect
      ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "This flow did not end in redirectToWeb")
    val credentials = handle.kc.webFallback().complete(request, handle.flow)
    handle.credentials = credentials
    BridgeJson.credentials(credentials).toString()
  }

  override fun storeCredentials(flowId: String, promise: Promise) = settle(promise) {
    val handle = flow(flowId)
    val credentials = handle.credentials
      ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "This flow has not produced credentials")
    handle.kc.credentialsManager().store(credentials)
    null
  }

  override fun releaseFlow(flowId: String) {
    flows.remove(flowId)
  }

  override fun credentials(instanceId: String, minTtlSeconds: Double, promise: Promise) = settle(promise) {
    BridgeJson.credentials(instance(instanceId).credentialsManager().credentials(minTtlSeconds.seconds)).toString()
  }

  override fun storedCredentials(instanceId: String, promise: Promise) = settle(promise) {
    instance(instanceId).credentialsManager().stored()?.let { BridgeJson.credentials(it).toString() }
  }

  override fun hasValidCredentials(instanceId: String, minTtlSeconds: Double, promise: Promise) = settle(promise) {
    instance(instanceId).credentialsManager().hasValid(minTtlSeconds.seconds)
  }

  override fun resourceRequestHeaders(instanceId: String, method: String, url: String, promise: Promise) = settle(promise) {
    val kc = instance(instanceId)
    BridgeJson.headers(kc.resourceRequestHeaders(kc.credentialsManager().credentials(), method, URI(url)))
  }

  override fun logout(instanceId: String, promise: Promise) = settle(promise) {
    instance(instanceId).credentialsManager().logout()
    null
  }

  override fun clearCredentials(instanceId: String, promise: Promise) = settle(promise) {
    instance(instanceId).credentialsManager().clear()
    null
  }

  override fun metadata(instanceId: String, forceRefresh: Boolean, promise: Promise) = settle(promise) {
    instance(instanceId).metadata(forceRefresh).raw?.toString() ?: "{}"
  }

  override fun dpopKeyThumbprint(instanceId: String, promise: Promise) = settle(promise) {
    instance(instanceId).dpopKeyThumbprint()
  }

  override fun invalidate() {
    scope.cancel()
    flows.clear()
    super.invalidate()
  }

  // ---

  private fun FlowHandle.encode(step: FlowStep): String {
    when (step) {
      is FlowStep.Authorized -> credentials = step.credentials
      is FlowStep.RedirectToWeb -> redirect = step.request
      is FlowStep.Challenges -> {}
    }
    return BridgeJson.step(step, flow.expiresIn)
  }

  private fun instance(id: String): KeycloakNative =
    instances[id] ?: throw NativeAuthError(NOT_CONFIGURED, errorDescription = "KeycloakNative instance $id is not configured")

  private fun flow(id: String): FlowHandle =
    flows[id] ?: throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Unknown or released flow $id")

  /** Runs [body] on [scope] and resolves with its result, or rejects with the SDK's error code. */
  private fun settle(promise: Promise, body: suspend () -> Any?) {
    scope.launch {
      try {
        promise.resolve(body())
      } catch (e: CancellationException) {
        promise.reject(NativeAuthError.Code.FLOW_STATE, "Cancelled", e)
        throw e
      } catch (e: NativeAuthError) {
        promise.reject(e.code, e.errorDescription ?: e.code, e, userInfo(e))
      } catch (e: Exception) {
        promise.reject(NativeAuthError.Code.INVALID_RESPONSE, e.message ?: e.toString(), e)
      }
    }
  }

  private fun userInfo(e: NativeAuthError) = Arguments.createMap().apply {
    e.statusCode?.let { putInt("statusCode", it) }
    putBoolean("isNetworkError", e.isNetworkError)
    putBoolean("isRetryable", e.isRetryable)
    e.retryAfter?.let { putDouble("retryAfter", it) }
  }

  companion object {
    const val NAME = NativeKeycloakNativeSpec.NAME

    /** `NativeAuthErrorCode.notConfigured` of `src/model.ts`. */
    const val NOT_CONFIGURED = "not_configured"
  }
}
