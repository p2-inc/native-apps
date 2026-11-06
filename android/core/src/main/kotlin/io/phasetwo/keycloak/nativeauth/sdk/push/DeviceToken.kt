package io.phasetwo.keycloak.nativeauth.sdk.push

import io.phasetwo.keycloak.nativeauth.sdk.credentials.CredentialsManager
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** The access token the push device API is called with (spec/03 §7.1). */
public data class DeviceToken(
  public val accessToken: String,
  /** `DPoP` or `Bearer`; ba-itsys needs `DPoP` with the enrolled key. */
  public val scheme: String = "DPoP",
) {
  override fun toString(): String = "DeviceToken(scheme=$scheme)"
}

/**
 * How the SDK obtains the device token (spec/05 §5, spec/08 Q6, spec/14 D9). The strategy is
 * abstract so a deployment can swap it without touching callers:
 *
 * - [NativeDeviceTokenProvider] (default, metadata `push.device_token = "native"`): the user's own
 *   DPoP-bound native access token; the DPoP key is the device key, nothing else is needed.
 * - EXTENSION POINT: a `client_credentials` provider for a stock ba-itsys install (metadata
 *   `device_token = "client_credentials"`, `device_client_id`). It needs a confidential client, i.e.
 *   a secret the app must get from somewhere (a backend, not the APK); it is not shipped here.
 */
public fun interface DeviceTokenProvider {
  public suspend fun deviceToken(): DeviceToken
}

/**
 * The stored credentials of the `KeycloakNative` instance, refreshed when needed. Fails with
 * `device_token_unavailable` when nobody is signed in or the tokens are not DPoP-bound.
 */
public class NativeDeviceTokenProvider(
  private val credentials: CredentialsManager,
  private val minTtl: Duration = 30.seconds,
) : DeviceTokenProvider {
  override suspend fun deviceToken(): DeviceToken {
    val stored = try {
      credentials.credentials(minTtl)
    } catch (e: NativeAuthError) {
      throw NativeAuthError(NativeAuthError.Code.DEVICE_TOKEN_UNAVAILABLE, errorDescription = "No usable native login for the push device API (${e.code})", cause = e)
    }
    if (!stored.isDPoPBound) {
      throw NativeAuthError(
        NativeAuthError.Code.DEVICE_TOKEN_UNAVAILABLE,
        errorDescription = "The native tokens are not DPoP-bound; the push device API needs a DPoP-bound token (spec/03 §7.1)",
      )
    }
    return DeviceToken(stored.accessToken, stored.authorizationScheme)
  }
}

/** A fixed token (tests, or an app that manages the login itself). */
public class StaticDeviceTokenProvider(private val token: DeviceToken) : DeviceTokenProvider {
  public constructor(credentials: Credentials) : this(DeviceToken(credentials.accessToken, credentials.authorizationScheme))

  override suspend fun deviceToken(): DeviceToken = token
}
