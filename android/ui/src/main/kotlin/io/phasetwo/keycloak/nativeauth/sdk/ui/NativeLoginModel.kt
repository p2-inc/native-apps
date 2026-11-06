package io.phasetwo.keycloak.nativeauth.sdk.ui

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowContext
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.RedirectToWebRequest
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPassword
import io.phasetwo.keycloak.nativeauth.sdk.push.PushProviderRegistration
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Outcome of a `NativeLoginScreen` (spec/05 §4). */
public sealed class NativeLoginResult {
  public data class Authorized(public val credentials: Credentials) : NativeLoginResult()

  public data object Cancelled : NativeLoginResult()

  public data class Failed(public val error: NativeAuthError) : NativeLoginResult()
}

/**
 * State behind `NativeLoginScreen`, the twin of the iOS `NativeLoginModel`: drives the flow, picks the
 * screen, runs the platform ceremonies. Plain Kotlin over [StateFlow], so it is tested on the JVM.
 */
internal class NativeLoginModel(
  private val kc: KeycloakNative,
  private val flow: NativeLoginFlow,
  private val scope: CoroutineScope,
  private val autoSelectPasskey: Boolean = false,
  val offersSavedPasswords: Boolean = true,
  private val offersToSavePassword: Boolean = true,
  /** The push provider a `push_enrollment` registers; `null` enrolls without delivery (`none`). */
  private val pushRegistration: (suspend () -> PushProviderRegistration)? = null,
  private val onResult: (NativeLoginResult) -> Unit,
) {
  sealed class Phase {
    data object Starting : Phase()

    data class Challenges(val challenges: List<Challenge>, val context: FlowContext, val selected: Challenge) : Phase()

    data class RedirectToWeb(val request: RedirectToWebRequest) : Phase()

    data object Finished : Phase()
  }

  data class State(
    val phase: Phase = Phase.Starting,
    val isSubmitting: Boolean = false,
    /** A user-facing error that is not attached to a challenge (network, passkey failure…). */
    val message: String? = null,
  )

  private val mutableState = MutableStateFlow(State())
  val state: StateFlow<State> = mutableState.asStateFlow()

  private var started = false
  private var done = false

  /** Ceremonies and requests in progress; one may start another (an automatic passkey prompt). */
  private var inFlight = 0

  /**
   * The password of a saved password picked on the `username` step, answered once to the `password`
   * challenge that follows (and dropped if none does).
   */
  private var pendingSavedPassword: String? = null

  /**
   * A password the user typed (or set through `update_password`), offered to the password manager
   * once the flow is authorized. Android has no system prompt that reliably saves a login whose
   * username and password were typed on different screens.
   */
  private var typedPassword: SavedPassword? = null
  private var typedUsername: String? = null

  fun startIfNeeded() {
    if (started) return
    started = true
    perform { flow.start() }
  }

  fun submit(answer: ChallengeAnswer, challenge: Challenge) {
    when (answer) {
      is ChallengeAnswer.Username -> typedUsername = answer.username
      is ChallengeAnswer.Password -> remember(answer.password)
      is ChallengeAnswer.UpdatePassword -> remember(answer.password)
      else -> {}
    }
    perform { flow.respond(answer, challenge) }
  }

  fun usePasskey(challenge: Challenge, preferImmediatelyAvailable: Boolean = false) {
    val params = challenge.passkeyParams ?: return
    perform {
      val assertion = kc.passkeys().assert(params, preferImmediatelyAvailable)
      flow.respond(ChallengeAnswer.Passkey(assertion), challenge)
    }
  }

  fun registerPasskey(challenge: Challenge, label: String?) {
    val params = challenge.passkeyRegistrationParams ?: return
    perform {
      val attestation = kc.passkeys().register(params)
      flow.respond(ChallengeAnswer.PasskeyRegistration(attestation, label), challenge)
    }
  }

  /**
   * `push_enrollment` (spec/03 §4.15): the device JWT is signed with the DPoP key and the enrollment
   * stored once the server moved on from the challenge.
   */
  fun enrollPush(challenge: Challenge, deviceLabel: String) {
    val params = challenge.pushEnrollmentParams ?: return
    perform {
      val registration = pushRegistration?.invoke() ?: PushProviderRegistration.NONE
      val push = kc.push()
      val prepared = push.prepareEnrollment(params, deviceLabel, registration.type, registration.id)
      val step = flow.respond(prepared.answer, challenge)
      if (step.challenges.orEmpty().none { it.type == ChallengeType.PushEnrollment && it.error != null }) push.commit(prepared)
      step
    }
  }

  /**
   * Shows the saved-password sheet. On the `username` step the picked username is answered and its
   * password kept for the `password` challenge that follows; on the `password` step the password is
   * answered directly. A picked password is already saved, so it is not offered for saving again.
   */
  fun useSavedPassword(challenge: Challenge) {
    perform {
      val saved = kc.pickSavedPassword()
      typedPassword = null
      if (challenge.type == ChallengeType.Password) {
        flow.respond(ChallengeAnswer.Password(saved.password), challenge)
      } else {
        pendingSavedPassword = saved.password
        flow.respond(ChallengeAnswer.Username(saved.username), challenge)
      }
    }
  }

  fun openBrowser() {
    val request = (state.value.phase as? Phase.RedirectToWeb)?.request ?: return
    perform { FlowStep.Authorized(kc.webFallback().complete(request, flow)) }
  }

  fun select(challenge: Challenge) {
    val phase = state.value.phase as? Phase.Challenges ?: return
    if (phase.challenges.none { it.id == challenge.id }) return
    mutableState.update { it.copy(phase = phase.copy(selected = challenge), message = null) }
  }

  fun cancel() {
    if (done) return
    done = true
    scope.launch {
      runCatching { flow.cancel() }
      mutableState.update { it.copy(phase = Phase.Finished) }
      onResult(NativeLoginResult.Cancelled)
    }
  }

  // ---

  private fun remember(password: String) {
    val context = (state.value.phase as? Phase.Challenges)?.context
    val username = context?.username ?: typedUsername ?: return
    typedPassword = SavedPassword(username, password)
  }

  private fun perform(body: suspend () -> FlowStep) {
    if (done) return
    inFlight += 1
    mutableState.update { it.copy(isSubmitting = true, message = null) }
    scope.launch {
      try {
        apply(body())
      } catch (e: CancellationException) {
        throw e
      } catch (e: NativeAuthError) {
        pendingSavedPassword = null
        when (e.code) {
          // Not a flow failure: the set stays, the user may pick another way (spec/12 D4).
          NativeAuthError.Code.PASSKEY_CANCELLED, NativeAuthError.Code.WEB_FALLBACK_CANCELLED, NativeAuthError.Code.SAVED_PASSWORD_CANCELLED -> {}
          NativeAuthError.Code.PASSKEY_FAILED, NativeAuthError.Code.PASSKEY_UNAVAILABLE, NativeAuthError.Code.RP_ID_MISMATCH,
          NativeAuthError.Code.NETWORK_ERROR, NativeAuthError.Code.WEB_FALLBACK_FAILED, NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE ->
            mutableState.update { it.copy(message = e.errorDescription ?: e.code) }
          else -> {
            // Terminal (invalid_session, access_denied, …): the flow is over.
            done = true
            mutableState.update { it.copy(phase = Phase.Finished) }
            onResult(NativeLoginResult.Failed(e))
          }
        }
      } catch (e: Exception) {
        pendingSavedPassword = null
        mutableState.update { it.copy(message = e.message ?: e.toString()) }
      } finally {
        inFlight -= 1
        mutableState.update { it.copy(isSubmitting = inFlight > 0) }
      }
    }
  }

  private suspend fun apply(step: FlowStep) {
    when (step) {
      is FlowStep.Challenges -> {
        val challenges = step.challenges
        // A password that came back with an error was wrong: never offer it for saving.
        if (challenges.any { it.type == ChallengeType.Password && it.error != null }) typedPassword = null
        pendingSavedPassword?.let { password ->
          pendingSavedPassword = null
          challenges.firstOrNull { it.type == ChallengeType.Password && it.error == null }?.let { challenge ->
            mutableState.update { it.copy(phase = Phase.Challenges(challenges, step.context, challenge)) }
            // In the same coroutine, so the screen stays busy until the answer is in.
            apply(flow.respond(ChallengeAnswer.Password(password), challenge))
            return
          }
        }
        val selected = pick(challenges, (state.value.phase as? Phase.Challenges)?.selected)
        mutableState.update { it.copy(phase = Phase.Challenges(challenges, step.context, selected)) }
        if (autoSelectPasskey && selected.type == ChallengeType.Passkey && selected.error == null) {
          usePasskey(selected)
        }
      }
      is FlowStep.Authorized -> {
        done = true
        typedPassword?.takeIf { offersToSavePassword }?.let { password ->
          // Closing the prompt or having no password manager does not change the outcome.
          runCatching { kc.savePassword(password.username, password.password) }
        }
        typedPassword = null
        mutableState.update { it.copy(phase = Phase.Finished) }
        onResult(NativeLoginResult.Authorized(step.credentials))
      }
      is FlowStep.RedirectToWeb -> mutableState.update { it.copy(phase = Phase.RedirectToWeb(step.request)) }
    }
  }

  /**
   * The entry to show: the one that just failed (it carries `error`), else the previously shown type
   * when it is still offered, else the first supported entry (server order = flow order).
   */
  private fun pick(challenges: List<Challenge>, previous: Challenge?): Challenge =
    challenges.firstOrNull { it.error != null && it.type.isSupported }
      ?: previous?.let { p -> challenges.firstOrNull { it.type == p.type && it.type.isSupported } }
      ?: challenges.firstOrNull { it.type.isSupported }
      ?: challenges.first()
}
