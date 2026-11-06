package io.phasetwo.keycloak.nativeauth.sdk.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.platform.LocalAutofillManager
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentType
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.RedirectToWebRequest
import java.time.Instant
import kotlin.math.ceil
import kotlinx.coroutines.delay

/** Routes a challenge to its default screen (spec/05 §4 "Provided default screens"). */
@Composable
internal fun DefaultChallengeScreen(presentation: ChallengePresentationContext) {
  when (presentation.challenge.type) {
    ChallengeType.Username -> UsernameScreen(presentation)
    ChallengeType.Password -> PasswordScreen(presentation)
    ChallengeType.Totp -> TotpScreen(presentation)
    ChallengeType.Otp -> OtpScreen(presentation)
    ChallengeType.Passkey -> PasskeyScreen(presentation)
    ChallengeType.PasskeyRegistration -> PasskeyRegistrationScreen(presentation)
    ChallengeType.UpdatePassword -> UpdatePasswordScreen(presentation)
    ChallengeType.VerifyEmail -> VerifyEmailScreen(presentation)
    ChallengeType.Terms -> TermsScreen(presentation)
    ChallengeType.RecoveryCode -> RecoveryCodeScreen(presentation)
    ChallengeType.Push -> PushScreen(presentation)
    ChallengeType.PushEnrollment -> PushEnrollmentScreen(presentation)
    else -> UnsupportedScreen(presentation)
  }
}

/** Shared frame: title, context line, the descriptor's error, the content, a cancel button. */
@Composable
internal fun ChallengeFrame(
  presentation: ChallengePresentationContext,
  title: String,
  subtitle: String?,
  content: @Composable () -> Unit,
) {
  Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
    presentation.flowContext.username?.let { user ->
      val name = presentation.flowContext.displayName ?: user
      Text(
        if (presentation.isStepUp) stringResource(R.string.nl_confirm_its_you, name) else stringResource(R.string.nl_signing_in_as, name),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    subtitle?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    presentation.challenge.error?.let { error ->
      Text(error.message ?: error.code, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("challengeError"))
      presentation.challenge.retry?.remaining?.let { remaining ->
        // spec/03 §3.3: attempts left before the realm's brute-force protection locks the account.
        Text(pluralStringResource(R.plurals.nl_attempts_left, remaining, remaining), style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("retryRemaining"))
      }
    }
    content()
    TextButton(onClick = presentation::cancel, enabled = !presentation.isSubmitting) { Text(stringResource(R.string.nl_cancel)) }
  }
}

/** A single-line field with its autofill content type (password managers, SMS code autofill). */
@Composable
internal fun AutofillField(
  value: String,
  onValueChange: (String) -> Unit,
  label: String,
  contentType: ContentType?,
  tag: String,
  modifier: Modifier = Modifier,
  secret: Boolean = false,
  keyboardType: KeyboardType = KeyboardType.Text,
  capitalization: KeyboardCapitalization = KeyboardCapitalization.None,
  readOnly: Boolean = false,
  onDone: (() -> Unit)? = null,
) {
  OutlinedTextField(
    value = value,
    onValueChange = onValueChange,
    label = { Text(label) },
    singleLine = true,
    readOnly = readOnly,
    enabled = true,
    visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
    keyboardOptions = KeyboardOptions(
      keyboardType = if (secret) KeyboardType.Password else keyboardType,
      capitalization = capitalization,
      autoCorrectEnabled = false,
      imeAction = if (onDone != null) ImeAction.Done else ImeAction.Default,
    ),
    keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
    modifier = modifier
      .fillMaxWidth()
      .testTag(tag)
      .then(if (contentType != null) Modifier.semantics { this.contentType = contentType } else Modifier),
  )
}

/**
 * The account the password belongs to, read-only with the `Username` content type. Keycloak asks
 * for the username and the password on separate screens; autofill services pair a password with the
 * username field on the same screen, so without it they cannot match or save the entry.
 */
@Composable
internal fun AutofillUsernameField(username: String?) {
  if (username == null) return
  AutofillField(value = username, onValueChange = {}, label = stringResource(R.string.nl_username), contentType = ContentType.Username, tag = "autofillUsername", readOnly = true)
}

/** "Use a saved password": Credential Manager's sheet of passwords saved for the app. */
@Composable
internal fun SavedPasswordButton(presentation: ChallengePresentationContext) {
  if (!presentation.offersSavedPasswords) return
  TextButton(onClick = presentation::useSavedPassword, enabled = !presentation.isSubmitting, modifier = Modifier.testTag("useSavedPassword")) {
    Text(stringResource(R.string.nl_use_saved_password))
  }
}

/** androidx.autofill `HintConstants.AUTOFILL_HINT_2FA_APP_OTP`: a code from an authenticator. */
internal val AppOtpCode = ContentType("2faAppOTPCode")

/** androidx.autofill `HintConstants.AUTOFILL_HINT_EMAIL_OTP`: a code sent by email. */
internal val EmailOtpCode = ContentType("emailOTPCode")

/** The current time, ticking every second, for resend cooldowns. */
@Composable
internal fun rememberNow() = produceState(Instant.now()) {
  while (true) {
    delay(1_000)
    value = Instant.now()
  }
}

private fun seconds(duration: kotlin.time.Duration): Int = ceil(duration.inWholeMilliseconds / 1000.0).toInt()

@Composable
internal fun UsernameScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.usernameParams
  var username by rememberSaveable { mutableStateOf(params?.hint.orEmpty()) }
  val submit = { if (username.isNotEmpty()) presentation.submit(ChallengeAnswer.Username(username)) }
  ChallengeFrame(presentation, stringResource(R.string.nl_sign_in), stringResource(if (params?.allowEmail == true) R.string.nl_username_or_email else R.string.nl_username)) {
    AutofillField(
      value = username,
      onValueChange = { username = it },
      label = stringResource(R.string.nl_username),
      contentType = if (params?.allowEmail == true) ContentType.Username + ContentType.EmailAddress else ContentType.Username,
      tag = "username",
      keyboardType = if (params?.allowEmail == true) KeyboardType.Email else KeyboardType.Text,
      onDone = submit,
    )
    Button(onClick = submit, enabled = username.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_continue)) }
    SavedPasswordButton(presentation)
  }
}

@Composable
internal fun PasswordScreen(presentation: ChallengePresentationContext) {
  var password by rememberSaveable { mutableStateOf("") }
  val autofill = LocalAutofillManager.current
  val submit = {
    if (password.isNotEmpty()) {
      // Ends the autofill session with the username and password on screen, for services that save from it.
      autofill?.commit()
      presentation.submit(ChallengeAnswer.Password(password))
    }
  }
  ChallengeFrame(presentation, stringResource(R.string.nl_enter_password), null) {
    AutofillUsernameField(presentation.flowContext.username)
    AutofillField(value = password, onValueChange = { password = it }, label = stringResource(R.string.nl_password), contentType = ContentType.Password, tag = "password", secret = true, onDone = submit)
    Button(onClick = submit, enabled = password.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_sign_in)) }
    SavedPasswordButton(presentation)
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TotpScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.totpParams
  var code by rememberSaveable { mutableStateOf("") }
  var credentialId by rememberSaveable { mutableStateOf<String?>(null) }
  val submit = { if (code.isNotEmpty()) presentation.submit(ChallengeAnswer.Totp(code, credentialId)) }
  ChallengeFrame(presentation, stringResource(R.string.nl_authenticator_code), stringResource(R.string.nl_enter_totp, params?.digits ?: 6)) {
    val credentials = params?.credentials.orEmpty()
    if (credentials.size > 1) {
      var expanded by rememberSaveable { mutableStateOf(false) }
      val default = stringResource(R.string.nl_default)
      ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
          value = credentials.firstOrNull { it.id == credentialId }?.label ?: default,
          onValueChange = {},
          readOnly = true,
          label = { Text(stringResource(R.string.nl_authenticator)) },
          trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
          modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
          DropdownMenuItem(text = { Text(default) }, onClick = { credentialId = null; expanded = false })
          credentials.forEach { credential ->
            DropdownMenuItem(text = { Text(credential.label) }, onClick = { credentialId = credential.id; expanded = false })
          }
        }
      }
    }
    // Password managers that keep the account's TOTP secret (1Password, Bitwarden…) fill this.
    AutofillField(value = code, onValueChange = { code = it }, label = stringResource(R.string.nl_code), contentType = AppOtpCode, tag = "totp", keyboardType = KeyboardType.NumberPassword, onDone = submit)
    Button(onClick = submit, enabled = code.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_verify)) }
  }
}

/**
 * `otp` (spec/03 §4.6): the masked destination, a resend button with the server's cooldown, and a
 * "Send me a code" button first when the server has not sent one yet (`sent: false`).
 */
@Composable
internal fun OtpScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.otpParams
  val now by rememberNow()
  var code by rememberSaveable { mutableStateOf("") }
  val sent = params?.sent ?: false
  val wait = params?.let { seconds(it.resendWait(now)) } ?: 0
  val digits = params?.digits ?: 6
  val sms = params?.channel == "sms"
  val destination = params?.destinationMasked ?: stringResource(if (sms) R.string.nl_your_phone else R.string.nl_your_email)
  val submit = { if (code.isNotEmpty()) presentation.submit(ChallengeAnswer.Otp(code)) }
  ChallengeFrame(
    presentation,
    stringResource(if (sms) R.string.nl_text_message_code else R.string.nl_email_code),
    if (sent) stringResource(R.string.nl_we_sent_code, digits, destination) else stringResource(R.string.nl_we_can_send_code, digits, destination),
  ) {
    if (sent) {
      AutofillField(value = code, onValueChange = { code = it }, label = stringResource(R.string.nl_code), contentType = if (sms) ContentType.SmsOtpCode else EmailOtpCode, tag = "otp", keyboardType = KeyboardType.NumberPassword, onDone = submit)
      Button(onClick = submit, enabled = code.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_verify)) }
      OutlinedButton(onClick = { presentation.submit(ChallengeAnswer.OtpResend) }, enabled = wait <= 0 && !presentation.isSubmitting, modifier = Modifier.testTag("otpResend")) {
        Text(if (wait > 0) stringResource(R.string.nl_resend_code_in, wait) else stringResource(R.string.nl_resend_code))
      }
    } else {
      Button(onClick = { presentation.submit(ChallengeAnswer.OtpResend) }, enabled = wait <= 0 && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("otpSend")) {
        Text(if (wait > 0) stringResource(R.string.nl_send_me_code_in, wait) else stringResource(R.string.nl_send_me_code))
      }
    }
  }
}

@Composable
internal fun PasskeyScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.passkeyParams
  ChallengeFrame(presentation, stringResource(R.string.nl_passkey_title), stringResource(if (params?.discoverable == true) R.string.nl_passkey_discoverable else R.string.nl_passkey_allow_list)) {
    Button(onClick = { presentation.usePasskey() }, enabled = !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("usePasskey")) {
      Text(stringResource(R.string.nl_continue_with_passkey))
    }
  }
}

@Composable
internal fun PasskeyRegistrationScreen(presentation: ChallengePresentationContext) {
  val challenge = presentation.challenge
  val params = challenge.passkeyRegistrationParams
  var label by rememberSaveable { mutableStateOf("") }
  val user = params?.user?.name ?: stringResource(R.string.nl_your_account)
  // spec/03 §4.11: a skippable registration is an offer ("Not now"), not a requirement.
  val subtitle =
    if (challenge.isSkippable) stringResource(R.string.nl_passkey_offer, user)
    else stringResource(R.string.nl_passkey_required, params?.rp?.name ?: stringResource(R.string.nl_this_service), user)
  ChallengeFrame(presentation, stringResource(R.string.nl_create_a_passkey), subtitle) {
    AutofillField(value = label, onValueChange = { label = it }, label = stringResource(R.string.nl_passkey_name), contentType = null, tag = "passkeyLabel")
    Button(onClick = { presentation.registerPasskey(label.ifEmpty { null }) }, enabled = !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("createPasskey")) {
      Text(stringResource(R.string.nl_create_passkey))
    }
    if (challenge.isSkippable) {
      TextButton(onClick = { presentation.submit(ChallengeAnswer.Skip(challenge.type)) }, enabled = !presentation.isSubmitting, modifier = Modifier.testTag("skipChallenge")) {
        Text(stringResource(R.string.nl_not_now))
      }
    }
  }
}

/**
 * `push_enrollment` (spec/03 §4.15): enrolls this device with the SDK's DPoP key. Messages reach it
 * through the screen's `pushRegistration` (the `push` module's FCM token); without one the device
 * reads its approvals itself (`none`).
 */
@Composable
internal fun PushEnrollmentScreen(presentation: ChallengePresentationContext) {
  var label by rememberSaveable { mutableStateOf("") }
  val client = presentation.flowContext.clientName ?: stringResource(R.string.nl_this_service)
  val fallbackLabel = stringResource(R.string.nl_this_device)
  ChallengeFrame(presentation, stringResource(R.string.nl_push_enroll_title), stringResource(R.string.nl_push_enroll_subtitle, client)) {
    AutofillField(value = label, onValueChange = { label = it }, label = stringResource(R.string.nl_device_name), contentType = null, tag = "pushDeviceLabel")
    Button(onClick = { presentation.enrollPush(label.ifEmpty { fallbackLabel }) }, enabled = !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("pushEnroll")) {
      Text(stringResource(R.string.nl_push_enroll))
    }
  }
}

/** `recovery_code` (spec/03 §4.8): one single-use code, with the remaining count and a warning. */
@Composable
internal fun RecoveryCodeScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.recoveryCodeParams
  var code by rememberSaveable { mutableStateOf("") }
  val submit = { if (code.isNotEmpty()) presentation.submit(ChallengeAnswer.RecoveryCode(code)) }
  val subtitle = params?.remaining?.let { stringResource(R.string.nl_recovery_code_left, it) } ?: stringResource(R.string.nl_recovery_code_enter)
  ChallengeFrame(presentation, stringResource(R.string.nl_recovery_code), subtitle) {
    if (params?.shouldWarn == true) {
      Text(stringResource(R.string.nl_recovery_code_low), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
    }
    AutofillField(value = code, onValueChange = { code = it }, label = "XXXX-XXXX-XXXX", contentType = null, tag = "recoveryCode", capitalization = KeyboardCapitalization.Characters, onDone = submit)
    Button(onClick = submit, enabled = code.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_sign_in)) }
  }
}

/** `update_password` (spec/03 §4.12): the new password twice, with the realm's policy as hints. */
@Composable
internal fun UpdatePasswordScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.updatePasswordParams
  var password by rememberSaveable { mutableStateOf("") }
  var confirm by rememberSaveable { mutableStateOf("") }
  val canSubmit = password.isNotEmpty() && confirm == password && !presentation.isSubmitting
  val autofill = LocalAutofillManager.current
  val submit = {
    if (canSubmit) {
      autofill?.commit()
      presentation.submit(ChallengeAnswer.UpdatePassword(password, confirm))
    }
  }
  ChallengeFrame(presentation, stringResource(R.string.nl_choose_new_password), stringResource(R.string.nl_password_must_update)) {
    AutofillUsernameField(presentation.flowContext.username ?: params?.username)
    AutofillField(value = password, onValueChange = { password = it }, label = stringResource(R.string.nl_new_password), contentType = ContentType.NewPassword, tag = "newPassword", secret = true)
    AutofillField(value = confirm, onValueChange = { confirm = it }, label = stringResource(R.string.nl_confirm_new_password), contentType = ContentType.NewPassword, tag = "newPasswordConfirm", secret = true, onDone = submit)
    params?.hints?.takeIf { it.isNotEmpty() }?.let { hints ->
      Column { hints.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) } }
    }
    if (confirm.isNotEmpty() && confirm != password) {
      Text(stringResource(R.string.nl_passwords_do_not_match), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
    Button(onClick = submit, enabled = canSubmit, modifier = Modifier.fillMaxWidth().testTag("updatePassword")) { Text(stringResource(R.string.nl_update_password)) }
  }
}

/** `verify_email` (spec/03 §4.13): the code sent to the masked address, with resend and cooldown. */
@Composable
internal fun VerifyEmailScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.verifyEmailParams
  val now by rememberNow()
  var code by rememberSaveable { mutableStateOf("") }
  val sent = params?.sent ?: false
  val wait = params?.let { seconds(it.resendWait(now)) } ?: 0
  val digits = params?.digits ?: 6
  val destination = params?.emailMasked ?: stringResource(R.string.nl_your_email)
  val submit = { if (code.isNotEmpty()) presentation.submit(ChallengeAnswer.VerifyEmail(code)) }
  ChallengeFrame(
    presentation,
    stringResource(R.string.nl_verify_email),
    if (sent) stringResource(R.string.nl_we_sent_code, digits, destination) else stringResource(R.string.nl_we_need_to_send_code, digits, destination),
  ) {
    if (sent) {
      AutofillField(value = code, onValueChange = { code = it }, label = stringResource(R.string.nl_code), contentType = EmailOtpCode, tag = "verifyEmailCode", keyboardType = KeyboardType.NumberPassword, onDone = submit)
      Button(onClick = submit, enabled = code.isNotEmpty() && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nl_verify)) }
    }
    val label = when {
      sent && wait > 0 -> stringResource(R.string.nl_resend_code_in, wait)
      sent -> stringResource(R.string.nl_resend_code)
      wait > 0 -> stringResource(R.string.nl_send_code_in, wait)
      else -> stringResource(R.string.nl_send_code)
    }
    OutlinedButton(onClick = { presentation.submit(ChallengeAnswer.VerifyEmailResend) }, enabled = wait <= 0 && !presentation.isSubmitting, modifier = Modifier.testTag("verifyEmailResend")) { Text(label) }
  }
}

/** `terms` (spec/03 §4.14): the text and/or a link, then accept or decline (decline ends the login). */
@Composable
internal fun TermsScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.termsParams
  val uriHandler = LocalUriHandler.current
  ChallengeFrame(presentation, stringResource(R.string.nl_terms), params?.version?.let { stringResource(R.string.nl_terms_version, it) }) {
    params?.text?.let {
      Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.heightIn(max = 220.dp).verticalScroll(rememberScrollState()).testTag("termsText"))
    }
    params?.url?.let { url ->
      TextButton(onClick = { uriHandler.openUri(url.toString()) }) { Text(stringResource(R.string.nl_read_full_terms)) }
    }
    Button(onClick = { presentation.submit(ChallengeAnswer.Terms(accepted = true)) }, enabled = !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("acceptTerms")) {
      Text(stringResource(R.string.nl_accept))
    }
    OutlinedButton(onClick = { presentation.submit(ChallengeAnswer.Terms(accepted = false)) }, enabled = !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("declineTerms")) {
      Text(stringResource(R.string.nl_decline), color = MaterialTheme.colorScheme.error)
    }
  }
}

/**
 * `push` (spec/03 §4.7): sends the push when the user asks (or shows the one already sent), shows the
 * number for number match, and polls every `poll_interval` seconds until the device answers.
 */
@Composable
internal fun PushScreen(presentation: ChallengePresentationContext) {
  val params = presentation.challenge.pushParams
  val now by rememberNow()
  val sent = params?.sent ?: false
  val wait = params?.let { seconds(it.resendWait(now)) } ?: 0
  val device = params?.devices?.firstOrNull() ?: stringResource(R.string.nl_your_phone)
  ChallengeFrame(
    presentation,
    stringResource(R.string.nl_approve_on_phone),
    if (sent) stringResource(R.string.nl_push_sent, device) else stringResource(R.string.nl_push_can_send, device),
  ) {
    if (sent) {
      params.userVerificationNumber?.let { number ->
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
          Text(stringResource(R.string.nl_push_choose_number), style = MaterialTheme.typography.bodySmall)
          Text(number, fontSize = 44.sp, fontWeight = FontWeight.Bold, modifier = Modifier.testTag("pushNumber"))
        }
      }
      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        Text(stringResource(R.string.nl_push_waiting), style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("pushWaiting"))
      }
      OutlinedButton(onClick = { presentation.submit(ChallengeAnswer.PushPoll) }, enabled = !presentation.isSubmitting, modifier = Modifier.testTag("pushPoll")) {
        Text(stringResource(R.string.nl_check_now))
      }
    } else {
      Button(onClick = { presentation.submit(ChallengeAnswer.PushResend) }, enabled = wait <= 0 && !presentation.isSubmitting, modifier = Modifier.fillMaxWidth().testTag("pushSend")) {
        Text(if (wait > 0) stringResource(R.string.nl_send_request_in, wait) else stringResource(R.string.nl_send_request))
      }
    }
  }
  // Poll while the challenge is pending; the server advances on `approved` (spec/03 §4.7).
  val latest by androidx.compose.runtime.rememberUpdatedState(presentation)
  LaunchedEffect(params?.cid, params?.isPending) {
    if (params == null || !params.isPending) return@LaunchedEffect
    while (true) {
      delay(params.pollInterval * 1_000L)
      if (!latest.isSubmitting) latest.submit(ChallengeAnswer.PushPoll)
    }
  }
}

@Composable
internal fun UnsupportedScreen(presentation: ChallengePresentationContext) {
  ChallengeFrame(presentation, stringResource(R.string.nl_update_required), stringResource(R.string.nl_unsupported, presentation.challenge.type.wire)) {}
}

/** The default "Try another way" list under a screen. */
@Composable
public fun DefaultChallengeChooser(context: ChallengeChooserContext) {
  Column(Modifier.fillMaxWidth()) {
    Text(stringResource(R.string.nl_try_another_way), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    context.alternatives.filter { it.type.isSupported }.forEach { challenge ->
      TextButton(onClick = { context.select(challenge) }, modifier = Modifier.testTag("switchTo-${challenge.type.wire}")) {
        Text(chooserTitle(challenge))
      }
    }
  }
}

/** The chooser's label for [challenge]. */
@Composable
public fun chooserTitle(challenge: Challenge): String = when (challenge.type) {
  ChallengeType.Passkey -> stringResource(R.string.nl_use_passkey)
  ChallengeType.Password -> stringResource(R.string.nl_use_password)
  ChallengeType.Totp -> stringResource(R.string.nl_use_authenticator)
  ChallengeType.Otp -> stringResource(if (challenge.otpParams?.channel == "sms") R.string.nl_text_me_code else R.string.nl_email_me_code)
  ChallengeType.RecoveryCode -> stringResource(R.string.nl_use_recovery_code)
  ChallengeType.Push -> stringResource(R.string.nl_approve_on_phone)
  else -> challenge.label ?: challenge.type.wire
}

/** `redirect_to_web` (spec/03 §3.4): explains and opens the browser. */
@Composable
internal fun RedirectToWebScreen(request: RedirectToWebRequest, isSubmitting: Boolean, message: String?, open: () -> Unit, cancel: () -> Unit) {
  val reason = request.reason
  val explanation =
    if (reason != null && reason.startsWith("required_action:")) {
      stringResource(R.string.nl_account_needs_attention, reason.removePrefix("required_action:").replace('_', ' ').lowercase())
    } else {
      request.errorDescription ?: stringResource(R.string.nl_complete_on_web)
    }
  Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    Text(stringResource(R.string.nl_continue_in_browser), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
    Text(explanation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    message?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Button(onClick = open, enabled = !isSubmitting, modifier = Modifier.fillMaxWidth().testTag("openBrowser")) { Text(stringResource(R.string.nl_open_browser)) }
    TextButton(onClick = cancel) { Text(stringResource(R.string.nl_cancel)) }
  }
}
