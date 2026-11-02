package io.phasetwo.keycloak.nativeauth.sdk.challenge

import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Pkce
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import kotlin.coroutines.cancellation.CancellationException

/** Parameters of the initial request (spec/03 §2.1). */
public data class LoginParameters(
  public val scope: String? = "openid",
  public val acrValues: String? = null,
  public val loginHint: String? = null,
  public val prompt: String? = null,
  public val maxAge: Int? = null,
  public val nonce: String? = null,
  public val uiLocales: String? = null,
  /** Free-text device label shown in events / push prompts. */
  public val deviceName: String? = null,
  /** Stable app-generated UUID. */
  public val deviceId: String? = null,
  /**
   * Extra fields of the initial request (spec/03 §2.3), e.g. a device or risk signal from another
   * on-device SDK. Use the reserved `x_` prefix so a future profile parameter cannot collide; the
   * Keycloak implementation keeps them for the whole login. Sent in key order.
   */
  public val additionalParameters: Map<String, String> = emptyMap(),
  /**
   * Extra fields appended to every continuation request of the flow; per-answer fields go through
   * `respond(answer, challenge, additionalFields)`.
   */
  public val continuationParameters: Map<String, String> = emptyMap(),
)

/** The challenge-driven state machine (spec/05 §2): `start() -> Challenges -> respond(...) -> Authorized`. */
public interface LoginFlow {
  public suspend fun start(): FlowStep

  /**
   * Answers [challenge], which must be in [pendingChallenges]. [additionalFields] are sent with this
   * request only (spec/03 §2.3), after `LoginParameters.continuationParameters`.
   */
  public suspend fun respond(answer: ChallengeAnswer, challenge: Challenge, additionalFields: Map<String, String> = emptyMap()): FlowStep

  /** `action=cancel`: the server invalidates the session. Safe to call at any point. */
  public suspend fun cancel()

  /** The current `auth_session` (replaced on every response, spec/03 §5). Exposed for diagnostics. */
  public val authSession: String?
  public val pendingChallenges: List<Challenge>
}

public class NativeLoginFlow internal constructor(
  public val clientId: String,
  public val parameters: LoginParameters,
  public val pkce: Pkce,
  /**
   * The post-login `auth_session` this flow steps up / re-authenticates (spec/03 §5), `null` for a
   * fresh login.
   */
  public val stepUpSession: String?,
  private val metadata: MetadataClient,
  private val transport: Transport,
  private val dpop: DPoPSigner?,
  private val tokens: Tokens,
  private val logger: NativeAuthLogger,
) : LoginFlow {
  public enum class State { IDLE, AWAITING_ANSWER, FINISHED }

  // State changes are short critical sections; no lock is held across a request, like the iOS actor.
  private val lock = Any()
  private var client: ChallengeEndpointClient? = null
  private var state = State.IDLE
  private var session: String? = null
  private var pending: List<Challenge> = emptyList()
  private var lastExpiresIn: Int? = null

  public val currentState: State get() = synchronized(lock) { state }
  override val authSession: String? get() = synchronized(lock) { session }
  public val isStepUp: Boolean get() = stepUpSession != null
  override val pendingChallenges: List<Challenge> get() = synchronized(lock) { pending }

  /** Remaining lifetime of the authentication session as last reported. */
  public val expiresIn: Int? get() = synchronized(lock) { lastExpiresIn }

  override suspend fun start(): FlowStep {
    synchronized(lock) {
      if (state != State.IDLE || client != null) {
        throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "start() can only be called once per flow")
      }
    }
    val document = metadata.metadata()
    val major = document.protocolMajorVersion
    if (major != null && major != 1) {
      logger.log(LogLevel.WARNING) { "Server protocol_version ${document.protocolVersion} is not 1.x; continuing best-effort" }
    }
    val client = ChallengeEndpointClient(document.authorizationChallengeEndpoint, transport, dpop)
    synchronized(lock) { this.client = client }

    val fields = mutableListOf("client_id" to clientId, "response_type" to "code")
    parameters.scope?.takeIf { it.isNotEmpty() }?.let { fields += "scope" to it }
    fields += "code_challenge" to pkce.challenge
    fields += "code_challenge_method" to Pkce.METHOD
    parameters.acrValues?.let { fields += "acr_values" to it }
    parameters.loginHint?.let { fields += "login_hint" to it }
    parameters.prompt?.let { fields += "prompt" to it }
    parameters.maxAge?.let { fields += "max_age" to it.toString() }
    parameters.nonce?.let { fields += "nonce" to it }
    parameters.uiLocales?.let { fields += "ui_locales" to it }
    parameters.deviceName?.let { fields += "device_name" to it }
    parameters.deviceId?.let { fields += "device_id" to it }
    fields += extraFields(parameters.additionalParameters, fields)
    // spec/03 §5: a §2.1 request plus the post-login auth_session = step-up / re-authentication.
    stepUpSession?.let { fields += "auth_session" to it }

    return send(client, fields)
  }

  override suspend fun respond(answer: ChallengeAnswer, challenge: Challenge, additionalFields: Map<String, String>): FlowStep {
    val (client, session) = synchronized(lock) {
      val client = this.client
      val session = this.session
      if (state != State.AWAITING_ANSWER || session == null || client == null) {
        throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "No challenge is pending (state: $state)")
      }
      if (pending.none { it.id == challenge.id && it.type == challenge.type }) {
        throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Challenge ${challenge.type} is not in the pending set")
      }
      client to session
    }
    if (answer.challengeType != challenge.type) {
      throw NativeAuthError(
        NativeAuthError.Code.UNSUPPORTED_CHALLENGE,
        errorDescription = "A ${answer.challengeType} answer cannot be sent for a ${challenge.type} challenge",
      )
    }
    if (answer is ChallengeAnswer.Skip && !challenge.isSkippable) {
      throw NativeAuthError(NativeAuthError.Code.FLOW_STATE, errorDescription = "Challenge ${challenge.type} is not skippable")
    }
    val answerFields = answer.formFields
    answerFields.firstOrNull { it.first in CONTINUATION_FIELD_NAMES }?.let {
      throw NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = "An answer may not set '${it.first}'")
    }
    val fields = mutableListOf("auth_session" to session, "challenge_type" to challenge.type.wire, "challenge_id" to challenge.id)
    fields += answerFields
    fields += extraFields(parameters.continuationParameters, fields)
    fields += extraFields(additionalFields, fields)
    return send(client, fields)
  }

  override suspend fun cancel() {
    val (client, session) = synchronized(lock) {
      val previous = state
      val client = this.client
      val session = this.session
      state = State.FINISHED
      pending = emptyList()
      if (previous != State.AWAITING_ANSWER || session == null || client == null) return
      this.session = null
      client to session
    }
    try {
      // The server answers invalid_session once the session is cancelled (spec/03 §2.2).
      client.send(listOf("auth_session" to session, "action" to "cancel"))
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      logger.log(LogLevel.DEBUG) { "cancel: $e" }
    }
  }

  private suspend fun send(client: ChallengeEndpointClient, fields: List<Pair<String, String>>): FlowStep {
    val outcome = try {
      client.post(fields)
    } catch (error: NativeAuthError) {
      noteFailure(error)
      throw error
    }
    return handle(outcome)
  }

  private suspend fun handle(outcome: ChallengeOutcome): FlowStep = when (outcome) {
    is ChallengeOutcome.Challenges -> {
      val set = outcome.set
      synchronized(lock) {
        session = set.authSession
        pending = set.challenges
        lastExpiresIn = set.expiresIn
        state = State.AWAITING_ANSWER
      }
      val unsupported = set.challenges.filter { !it.type.isSupported }
      if (unsupported.isNotEmpty()) {
        logger.log(LogLevel.INFO) { "Challenge set contains unsupported types: ${unsupported.map { it.type.wire }}" }
      }
      FlowStep.Challenges(set.challenges, set.context)
    }
    is ChallengeOutcome.AuthorizationCode -> {
      synchronized(lock) {
        state = State.FINISHED
        pending = emptyList()
        session = outcome.authSession
      }
      FlowStep.Authorized(tokens.exchange(outcome.code, pkce.verifier, authSession = outcome.authSession))
    }
    is ChallengeOutcome.RedirectToWeb -> {
      // The server removed the native authentication session (spec/03 §3.4); the PKCE pair of this
      // flow is what WebFallback exchanges the browser's code with.
      synchronized(lock) {
        state = State.FINISHED
        pending = emptyList()
        session = null
      }
      logger.log(LogLevel.INFO) { "Server asks for a browser fallback (${outcome.request.reason ?: "no reason"})" }
      FlowStep.RedirectToWeb(outcome.request)
    }
  }

  private fun noteFailure(error: NativeAuthError) = synchronized(lock) {
    when (error.code) {
      NativeAuthError.Code.INVALID_SESSION, NativeAuthError.Code.ACCESS_DENIED, NativeAuthError.Code.INVALID_CLIENT,
      NativeAuthError.Code.REDIRECT_TO_WEB, NativeAuthError.Code.SERVER_ERROR,
      -> {
        // Terminal for this flow (spec/03 §3.5): the server removed the authentication session.
        state = State.FINISHED
        pending = emptyList()
        session = null
      }
      // The session survives; a fresh auth_session may have been handed back.
      NativeAuthError.Code.INVALID_REQUEST -> error.authSession?.let { session = it }
      else -> {}
    }
  }

  internal companion object {
    /** Names the SDK itself sends on some request (spec/03 §2.1, §2.2); callers may not override them. */
    val RESERVED_FIELD_NAMES: Set<String> = setOf(
      "client_id", "response_type", "scope", "code_challenge", "code_challenge_method", "acr_values", "login_hint",
      "prompt", "max_age", "nonce", "ui_locales", "device_name", "device_id", "auth_session", "challenge_type",
      "challenge_id", "action",
    )

    /** The fields every continuation request starts with; an answer never sets them. */
    val CONTINUATION_FIELD_NAMES: Set<String> = setOf("auth_session", "challenge_type", "challenge_id")

    /** [extra] in key order, refusing names that are reserved or already in [existing]. */
    fun extraFields(extra: Map<String, String>, existing: List<Pair<String, String>>): List<Pair<String, String>> {
      val taken = existing.map { it.first }.toSet()
      extra.keys.firstOrNull { it.isEmpty() || it in RESERVED_FIELD_NAMES || it in taken }?.let {
        throw NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = "Extra field '$it' is empty, reserved or already set by the request")
      }
      return extra.entries.sortedBy { it.key }.map { it.key to it.value }
    }
  }
}
