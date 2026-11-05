package io.phasetwo.keycloak.nativeauth.sdk.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowContext
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow

/**
 * What a challenge screen gets (spec/05 §4): the challenge, the set it belongs to, the flow context and
 * the actions it may trigger. Replacement screens are plain composables built from this.
 */
public class ChallengePresentationContext internal constructor(
  public val challenge: Challenge,
  public val challenges: List<Challenge>,
  public val flowContext: FlowContext,
  public val isSubmitting: Boolean,
  private val model: NativeLoginModel,
) {
  /** The step is a step-up / re-authentication (`context.step_up`). */
  public val isStepUp: Boolean get() = flowContext.stepUp

  /** Entries of the set other than this one, in server order. */
  public val alternatives: List<Challenge> get() = challenges.filter { it.id != challenge.id }

  /** The default `username` and `password` screens show "Use a saved password". */
  public val offersSavedPasswords: Boolean get() = model.offersSavedPasswords

  public fun submit(answer: ChallengeAnswer) {
    model.submit(answer, challenge)
  }

  /** Runs the platform passkey prompt for a `passkey` challenge and submits the assertion. */
  public fun usePasskey(preferImmediatelyAvailableCredentials: Boolean = false) {
    model.usePasskey(challenge, preferImmediatelyAvailableCredentials)
  }

  /** Runs the platform registration for a `passkey_registration` challenge and submits it. */
  public fun registerPasskey(label: String?) {
    model.registerPasskey(challenge, label)
  }

  /**
   * Shows the system sheet of saved passwords. On a `username` challenge the picked username is
   * submitted and its password answers the `password` challenge that follows; on a `password`
   * challenge the password is submitted. Closing the sheet leaves the screen as it was.
   */
  public fun useSavedPassword() {
    model.useSavedPassword(challenge)
  }

  /** Show another entry of the current set instead. */
  public fun switchTo(other: Challenge) {
    model.select(other)
  }

  public fun cancel() {
    model.cancel()
  }
}

/** Input of a chooser (the "Try another way" list). */
public class ChallengeChooserContext internal constructor(
  public val current: Challenge,
  public val alternatives: List<Challenge>,
  private val model: NativeLoginModel,
) {
  public fun select(challenge: Challenge) {
    model.select(challenge)
  }
}

/** A replacement screen for one challenge type (spec/05 §4 option 2). */
public typealias ChallengePresenter = @Composable (ChallengePresentationContext) -> Unit

/** A replacement "Try another way" list. */
public typealias ChallengeChooser = @Composable (ChallengeChooserContext) -> Unit

/**
 * Drives a [NativeLoginFlow] with the default screens, the twin of the iOS `NativeLoginView`: `start()`,
 * one screen per challenge (the first supported entry of each set, with "Try another way" for the rest),
 * passkey prompts, the browser fallback, and [onResult] at the end.
 *
 * The SDK instance must be configured with the `android` module's platforms for the ceremonies the
 * realm uses: `CredentialManagerPasskeyPlatform`, `CredentialManagerSavedPasswordPlatform` and
 * `AuthTabWebPresenter`. Without one, that ceremony fails inline with its `*_unavailable` error.
 *
 * Password managers: every field carries its autofill content type; the password screens repeat the
 * username read-only (Keycloak asks for it on the previous screen, and autofill services pair a
 * password with a username on the same screen); "Use a saved password" opens Credential Manager's
 * sheet; after a sign-in with a typed password, [offerToSavePassword] shows its "Save password?" prompt.
 *
 * @param flow a flow from `authentication().startLogin(...)` or `stepUp(...)`, not yet started.
 * @param presenters replacement screens by challenge type.
 * @param chooser a replacement "Try another way" list.
 * @param header shown above every screen (a logo).
 * @param autoSelectPasskey when a set contains `passkey`, run the prompt right away.
 * @param offerSavedPasswords show "Use a saved password" on the `username` and `password` screens.
 * @param offerToSavePassword after a sign-in with a typed (or newly set) password, offer to save it.
 */
@Composable
public fun NativeLoginScreen(
  kc: KeycloakNative,
  flow: NativeLoginFlow,
  onResult: (NativeLoginResult) -> Unit,
  modifier: Modifier = Modifier,
  presenters: Map<ChallengeType, ChallengePresenter> = emptyMap(),
  chooser: ChallengeChooser = { DefaultChallengeChooser(it) },
  header: (@Composable () -> Unit)? = null,
  autoSelectPasskey: Boolean = false,
  offerSavedPasswords: Boolean = true,
  offerToSavePassword: Boolean = true,
) {
  val scope = rememberCoroutineScope()
  val currentOnResult by rememberUpdatedState(onResult)
  val model = remember(kc, flow) {
    NativeLoginModel(kc, flow, scope, autoSelectPasskey, offerSavedPasswords, offerToSavePassword) { currentOnResult(it) }
  }
  LaunchedEffect(model) { model.startIfNeeded() }
  val state by model.state.collectAsState()

  Box(modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    when (val phase = state.phase) {
      NativeLoginModel.Phase.Starting -> Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
        header?.invoke()
        CircularProgressIndicator()
        Text(stringResource(R.string.nl_contacting_server), style = MaterialTheme.typography.bodyMedium)
      }
      is NativeLoginModel.Phase.Challenges -> {
        val presentation = ChallengePresentationContext(phase.selected, phase.challenges, phase.context, state.isSubmitting, model)
        Column(Modifier.widthIn(max = 480.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
          header?.invoke()
          val custom = presenters[phase.selected.type]
          if (custom != null) custom(presentation) else DefaultChallengeScreen(presentation)
          state.message?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
          if (presentation.alternatives.any { it.type.isSupported }) {
            chooser(ChallengeChooserContext(phase.selected, presentation.alternatives, model))
          }
        }
      }
      is NativeLoginModel.Phase.RedirectToWeb -> Column(Modifier.widthIn(max = 480.dp).padding(16.dp)) {
        header?.invoke()
        RedirectToWebScreen(phase.request, state.isSubmitting, state.message, open = model::openBrowser, cancel = model::cancel)
      }
      NativeLoginModel.Phase.Finished -> CircularProgressIndicator(Modifier.padding(24.dp))
    }
  }
}
