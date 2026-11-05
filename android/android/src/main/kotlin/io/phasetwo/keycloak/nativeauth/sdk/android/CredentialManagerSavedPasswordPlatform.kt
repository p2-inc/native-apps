package io.phasetwo.keycloak.nativeauth.sdk.android

import android.app.Activity
import android.content.Context
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPassword
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPasswordPlatform
import java.lang.ref.WeakReference

/**
 * Saved passwords through Credential Manager: [pick] shows the sheet of passwords saved for the app
 * (Google Password Manager, and on Android 14+ any credential provider such as 1Password or
 * Bitwarden), [save] shows the "Save password?" prompt. The analogue of the iOS
 * `ASAuthorizationPasswordProvider` picker; iOS saves through its own system prompt.
 *
 * Passwords saved by the website on the RP id appear when `https://<rp_id>/.well-known/assetlinks.json`
 * grants the app `delegate_permission/common.get_login_creds`, the statement passkeys already need.
 *
 * The sheet needs the activity on screen, as [CredentialManagerPasskeyPlatform]. Closing it is
 * `saved_password_cancelled`; anything else `saved_password_unavailable`.
 */
public class CredentialManagerSavedPasswordPlatform(
  context: Context,
  private val currentActivity: () -> Activity?,
) : SavedPasswordPlatform {
  /** For apps with a single activity: holds it weakly. */
  public constructor(activity: Activity) : this(activity.applicationContext, WeakReference(activity)::get)

  private val credentialManager = CredentialManager.create(context.applicationContext)

  override suspend fun pick(): SavedPassword {
    val credential = try {
      credentialManager.getCredential(activity(), GetCredentialRequest(listOf(GetPasswordOption()))).credential
    } catch (e: GetCredentialException) {
      throw map(e, cancelled = e is GetCredentialCancellationException)
    }
    val password = credential as? PasswordCredential
      ?: throw NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, errorDescription = "Unexpected credential type for a saved password: ${credential.type}")
    return SavedPassword(password.id, password.password)
  }

  override suspend fun save(password: SavedPassword) {
    try {
      credentialManager.createCredential(activity(), CreatePasswordRequest(password.username, password.password))
    } catch (e: CreateCredentialException) {
      throw map(e, cancelled = e is CreateCredentialCancellationException)
    }
  }

  private fun activity(): Activity =
    currentActivity()?.takeUnless { it.isFinishing || it.isDestroyed }
      ?: throw NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, errorDescription = "No activity is on screen to show the password sheet")

  private fun map(e: Exception, cancelled: Boolean): NativeAuthError =
    if (cancelled) NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_CANCELLED, errorDescription = "The user closed the password sheet", cause = e)
    else NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, errorDescription = e.message ?: "No saved password is available", cause = e)
}
