package io.phasetwo.keycloak.nativeauth.sdk.android

import android.app.Activity
import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAssertion
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.WebAuthnJson
import java.lang.ref.WeakReference

/**
 * Passkeys through Credential Manager (spec/17 §3), the analogue of the iOS
 * `ASAuthorizationPlatformPublicKeyCredentialProvider` bridge. The server's params go out as WebAuthn
 * JSON ([WebAuthnJson]) and the platform's response comes back as the spec/03 fields.
 *
 * The prompt needs the activity on screen: [currentActivity] returns it, or `null` when the app is
 * not in the foreground, which fails as `passkey_unavailable`. For the RP id to work, the app must be
 * listed in `https://<rp_id>/.well-known/assetlinks.json` and its `android:apk-key-hash:` origin in the
 * realm's Passwordless policy (spec/03 §4.3).
 *
 * Cancellation is `passkey_cancelled`; no matching passkey, no provider or an unsupported device is
 * `passkey_unavailable`; anything else `passkey_failed`.
 */
public class CredentialManagerPasskeyPlatform(
  context: Context,
  private val currentActivity: () -> Activity?,
) : PasskeyPlatform {
  /** For apps with a single activity: holds it weakly. */
  public constructor(activity: Activity) : this(activity.applicationContext, WeakReference(activity)::get)

  private val credentialManager = CredentialManager.create(context.applicationContext)

  override suspend fun assert(params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Boolean): PasskeyAssertion {
    val activity = activity()
    val request = GetCredentialRequest(
      credentialOptions = listOf(GetPublicKeyCredentialOption(WebAuthnJson.requestOptions(params))),
      preferImmediatelyAvailableCredentials = preferImmediatelyAvailableCredentials,
    )
    val credential = try {
      credentialManager.getCredential(activity, request).credential
    } catch (e: GetCredentialException) {
      throw map(e)
    }
    val publicKey = credential as? PublicKeyCredential
      ?: throw NativeAuthError(NativeAuthError.Code.PASSKEY_FAILED, errorDescription = "Unexpected credential type for an assertion: ${credential.type}")
    return WebAuthnJson.assertion(publicKey.authenticationResponseJson)
  }

  override suspend fun register(params: PasskeyRegistrationParams): PasskeyAttestation {
    val activity = activity()
    val response = try {
      credentialManager.createCredential(activity, CreatePublicKeyCredentialRequest(WebAuthnJson.creationOptions(params)))
    } catch (e: CreateCredentialException) {
      throw map(e)
    }
    val publicKey = response as? CreatePublicKeyCredentialResponse
      ?: throw NativeAuthError(NativeAuthError.Code.PASSKEY_FAILED, errorDescription = "Unexpected credential type for a registration: ${response.type}")
    return WebAuthnJson.attestation(publicKey.registrationResponseJson)
  }

  private fun activity(): Activity =
    currentActivity()?.takeUnless { it.isFinishing || it.isDestroyed }
      ?: throw NativeAuthError(NativeAuthError.Code.PASSKEY_UNAVAILABLE, errorDescription = "No activity is on screen to show the passkey prompt")

  private fun map(e: GetCredentialException): NativeAuthError = when (e) {
    is GetCredentialCancellationException -> error(NativeAuthError.Code.PASSKEY_CANCELLED, "The user cancelled the passkey prompt", e)
    is NoCredentialException -> error(NativeAuthError.Code.PASSKEY_UNAVAILABLE, "No passkey for this account is available on the device", e)
    is GetCredentialProviderConfigurationException, is GetCredentialUnsupportedException ->
      error(NativeAuthError.Code.PASSKEY_UNAVAILABLE, "Passkeys are not available on this device", e)
    else -> error(NativeAuthError.Code.PASSKEY_FAILED, e.errorMessage?.toString() ?: e.type, e)
  }

  private fun map(e: CreateCredentialException): NativeAuthError = when (e) {
    is CreateCredentialCancellationException -> error(NativeAuthError.Code.PASSKEY_CANCELLED, "The user cancelled the passkey prompt", e)
    is CreateCredentialNoCreateOptionException, is CreateCredentialProviderConfigurationException, is CreateCredentialUnsupportedException ->
      error(NativeAuthError.Code.PASSKEY_UNAVAILABLE, "Passkeys cannot be created on this device", e)
    else -> error(NativeAuthError.Code.PASSKEY_FAILED, e.errorMessage?.toString() ?: e.type, e)
  }

  private fun error(code: String, description: String, cause: Throwable) = NativeAuthError(code, errorDescription = description, cause = cause)
}
