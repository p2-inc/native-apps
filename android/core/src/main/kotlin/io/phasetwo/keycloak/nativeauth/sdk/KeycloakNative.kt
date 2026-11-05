package io.phasetwo.keycloak.nativeauth.sdk

import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.challenge.NativeLoginFlow
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.config.MetadataClient
import io.phasetwo.keycloak.nativeauth.sdk.config.NativeAuthMetadata
import io.phasetwo.keycloak.nativeauth.sdk.credentials.CredentialsManager
import io.phasetwo.keycloak.nativeauth.sdk.credentials.InMemorySecureStore
import io.phasetwo.keycloak.nativeauth.sdk.credentials.SecureStore
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPKey
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPSigner
import io.phasetwo.keycloak.nativeauth.sdk.dpop.HardwareDPoPKeys
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.jose.Pkce
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.logging.NoopLogger
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAssertion
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyRegistrationClient
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.Passkeys
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPassword
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.SavedPasswordPlatform
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Tokens
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowObserver
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpUrlConnectionTransport
import io.phasetwo.keycloak.nativeauth.sdk.transport.ObservingTransport
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import io.phasetwo.keycloak.nativeauth.sdk.web.WebFallback
import java.net.URI
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlinx.serialization.json.JsonElement

/** The configured SDK instance (spec/05 §2): one per issuer + client. */
public class KeycloakNative private constructor(issuer: URI, public val clientId: String, public val options: Options) {
  /**
   * The platform pieces live in the `android` module, which fills these in; on the JVM the defaults
   * are an in-memory store, software DPoP keys and no passkey platform or browser.
   */
  public data class Options(
    public val dpop: DPoPMode = DPoPMode.AUTOMATIC,
    /** The platform key store behind [DPoPMode.HARDWARE] / [DPoPMode.AUTOMATIC] (Android Keystore). */
    public val hardwareKeys: HardwareDPoPKeys? = null,
    /**
     * Accept a passkey `rp_id` that is neither the issuer host nor a registrable suffix of it. Only for
     * development against a tunnel/port-forward (spec/12).
     */
    public val allowRpIdMismatch: Boolean = false,
    public val logger: NativeAuthLogger = NoopLogger,
    /** Overrides the `HttpURLConnection` transport (tests, custom pinning). */
    public val transport: Transport? = null,
    /** Receives redacted request/response entries (Diagnostics flow log). */
    public val flowObserver: FlowObserver? = null,
    /** Persistent storage for the DPoP key reference, push enrolment and (by default) the credentials. */
    public val secureStore: SecureStore? = null,
    /**
     * Store for the credentials only (tokens), e.g. one that requires user authentication; defaults to
     * [secureStore]. The DPoP key reference and push enrolment stay in [secureStore], which the SDK
     * reads without user interaction.
     */
    public val credentialsStore: SecureStore? = null,
    public val passkeyPlatform: PasskeyPlatform? = null,
    /** The password manager behind [pickSavedPassword] and [savePassword]. */
    public val savedPasswordPlatform: SavedPasswordPlatform? = null,
    /** The browser used by `WebFallback`. */
    public val webPresenter: WebAuthenticationPresenter? = null,
    public val metadataCacheTtl: Duration = 5.minutes,
  )

  /** The issuer without a trailing slash. */
  public val issuer: URI = URI.create(issuer.toString().trimEnd('/'))

  /** The (observing, redacting) transport every module of this instance sends through. */
  public val transport: Transport = ObservingTransport(options.transport ?: HttpUrlConnectionTransport(), options.logger, options.flowObserver)

  /** The secure store of this instance, for state other modules persist next to the credentials. */
  public val secureStore: SecureStore = options.secureStore ?: InMemorySecureStore().also {
    options.logger.log(LogLevel.WARNING) { "No secureStore configured: credentials and the DPoP key live in memory only" }
  }

  internal val metadataClient = MetadataClient(this.issuer, transport, options.metadataCacheTtl)
  internal val dpopSigner: DPoPSigner? =
    if (options.dpop == DPoPMode.DISABLED) null
    else DPoPSigner(options.dpop, secureStore, scopedStorageKey("dpop-key"), options.logger, options.hardwareKeys)
  private val credentialsManager = CredentialsManager(options.credentialsStore ?: secureStore, scopedStorageKey("credentials"), tokens(), options.logger)

  public fun authentication(): Authentication = Authentication(this)

  public fun passkeys(): Passkeys = Passkeys(
    platform = options.passkeyPlatform ?: UnavailablePasskeyPlatform,
    issuerHost = issuer.host.orEmpty(),
    allowRpIdMismatch = options.allowRpIdMismatch,
    registration = PasskeyRegistrationClient(issuer, metadataClient, transport, dpopSigner),
    logger = options.logger,
  )

  /**
   * Shows the system sheet of passwords saved for the app and returns the one the user picked. Answer
   * the `username` challenge with its `username`, then the `password` challenge with its `password`.
   * Errors: `saved_password_cancelled`, `saved_password_unavailable` (also without a configured
   * [Options.savedPasswordPlatform]).
   */
  public suspend fun pickSavedPassword(): SavedPassword = savedPasswords().pick()

  /**
   * Offers to store the username and password the user typed, after the flow ended in
   * `FlowStep.Authorized`. The autofill framework's own save prompt is unreliable when the username and
   * the password were typed on different screens.
   * Errors as [pickSavedPassword]; a closed prompt is `saved_password_cancelled`.
   */
  public suspend fun savePassword(username: String, password: String): Unit = savedPasswords().save(SavedPassword(username, password))

  private fun savedPasswords(): SavedPasswordPlatform = options.savedPasswordPlatform
    ?: throw NativeAuthError(NativeAuthError.Code.SAVED_PASSWORD_UNAVAILABLE, errorDescription = "No SavedPasswordPlatform is configured")

  /** Completes `FlowStep.RedirectToWeb` through the browser (spec/03 §3.4). */
  public fun webFallback(): WebFallback = WebFallback(clientId, issuer, metadataClient, options.webPresenter, tokens(), options.logger)

  /**
   * Headers for a request to a resource server with the stored tokens: `Authorization: Bearer …`, or
   * `Authorization: DPoP …` plus a `DPoP` proof with `ath` when the tokens are bound (spec/03 §8).
   */
  public suspend fun resourceRequestHeaders(credentials: Credentials, method: String, url: URI): Map<String, String> {
    val headers = linkedMapOf("Authorization" to "${credentials.authorizationScheme} ${credentials.accessToken}")
    if (credentials.isDPoPBound) dpopSigner?.proof(method, url, credentials.accessToken)?.let { headers["DPoP"] = it }
    return headers
  }

  public fun tokens(): Tokens = Tokens(clientId, issuer, metadataClient, transport, dpopSigner)

  /** The single credentials manager of this instance (refreshes are serialized). */
  public fun credentialsManager(): CredentialsManager = credentialsManager

  public suspend fun metadata(forceRefresh: Boolean = false): NativeAuthMetadata = metadataClient.metadata(forceRefresh)

  /** RFC 7638 thumbprint of the DPoP public key (`jkt`), `null` when DPoP is disabled. */
  public suspend fun dpopKeyThumbprint(): String? = dpopSigner?.publicJwk()?.thumbprint

  // Surface for the push module (spec/14 D9: the DPoP key is the device key).

  /** The DPoP key (created on first use). Throws `dpop_key_error` when DPoP is disabled. */
  public suspend fun dpopKey(): DPoPKey = requireSigner("DPoP is disabled; the push device API needs a DPoP-bound token (spec/03 §7.1)").currentKey()

  /**
   * A proof for a request outside core (the push device API), with extra claims; `null` when DPoP is
   * disabled. Server nonces remembered per origin are included; register a new one with
   * [rememberDPoPNonce].
   */
  public suspend fun dpopProof(method: String, url: URI, accessToken: String?, extraClaims: Map<String, JsonElement> = emptyMap()): String? =
    dpopSigner?.proof(method, url, accessToken, extraClaims)

  public suspend fun rememberDPoPNonce(nonce: String, url: URI) {
    dpopSigner?.setNonce(nonce, url)
  }

  /**
   * Key rotation in two steps: a fresh key to register with the server (signing that request with the
   * current key), then [commitDPoPKeyRotation] once the server accepted it.
   */
  public fun prepareDPoPKeyRotation(): DPoPKey = requireSigner("DPoP is disabled").prepareRotation()

  public suspend fun commitDPoPKeyRotation(key: DPoPKey) {
    requireSigner("DPoP is disabled").commitRotation(key)
  }

  /** A key under this instance's issuer + client scope in [secureStore]. */
  public fun scopedStorageKey(suffix: String): String = "$issuer|$clientId|$suffix"

  private fun requireSigner(message: String): DPoPSigner =
    dpopSigner ?: throw NativeAuthError(NativeAuthError.Code.DPOP_KEY_ERROR, errorDescription = message)

  public companion object {
    public fun configure(issuer: URI, clientId: String, options: Options = Options()): KeycloakNative = KeycloakNative(issuer, clientId, options)
  }
}

/** Entry point for logins, step-ups and the browser fallback (spec/05 §2.2). */
public class Authentication internal constructor(private val core: KeycloakNative) {
  /** Creates a flow; nothing is sent until `start()`. */
  public fun startLogin(parameters: LoginParameters = LoginParameters()): NativeLoginFlow = flow(parameters, stepUpSession = null)

  /**
   * Step-up / re-authentication inside the existing user session (spec/03 §5): a §2.1 request with a
   * new PKCE pair plus the stored post-login `auth_session` (`Credentials.authSession`, kept by the
   * `CredentialsManager`). The server skips the username step and asks only for what the requested
   * level still needs; `maxAge`/`prompt=login` force every factor again. `Authorized` then carries
   * tokens for the same session with the new `acr`. Throws `credentials_not_found` when no post-login
   * `auth_session` is stored; the server answers `invalid_session` when the user session has ended
   * (start a fresh login then).
   */
  public suspend fun stepUp(parameters: LoginParameters, authSession: String? = null): NativeLoginFlow {
    val session = authSession
      ?: core.credentialsManager().authSession()
      ?: throw NativeAuthError(NativeAuthError.Code.CREDENTIALS_NOT_FOUND, errorDescription = "No post-login auth_session is stored; log in first")
    return flow(parameters, session)
  }

  /** Convenience: [stepUp] with `acr_values` and/or `max_age` (the §6 answer names the `max_age` to use). */
  public suspend fun stepUp(acrValues: String? = null, maxAge: Int? = null, scope: String? = "openid", deviceName: String? = null): NativeLoginFlow =
    stepUp(LoginParameters(scope = scope, acrValues = acrValues, maxAge = maxAge, deviceName = deviceName))

  /**
   * Continues after an endpoint refused a token with `insufficient_authorization` and handed back an
   * `auth_session` (`reauthentication_required` from `CredentialsManager.credentials()`, or the §6
   * registration endpoints): a step-up flow with that session, `max_age` taken from the error when the
   * server named one.
   */
  public fun continueAfterTokenChallenge(error: NativeAuthError, parameters: LoginParameters = LoginParameters()): NativeLoginFlow {
    val session = error.authSession ?: throw NativeAuthError(
      NativeAuthError.Code.REAUTHENTICATION_REQUIRED, errorDescription = "The server returned no auth_session; start a new login", cause = error,
    )
    return flow(if (parameters.maxAge == null && error.maxAge != null) parameters.copy(maxAge = error.maxAge) else parameters, session)
  }

  public suspend fun metadata(forceRefresh: Boolean = false): NativeAuthMetadata = core.metadataClient.metadata(forceRefresh)

  private fun flow(parameters: LoginParameters, stepUpSession: String?): NativeLoginFlow = NativeLoginFlow(
    clientId = core.clientId,
    parameters = parameters,
    pkce = Pkce.generate(),
    stepUpSession = stepUpSession,
    metadata = core.metadataClient,
    transport = core.transport,
    dpop = core.dpopSigner,
    tokens = core.tokens(),
    logger = core.options.logger,
  )
}

/** The JVM default: there is no platform authenticator. */
private object UnavailablePasskeyPlatform : PasskeyPlatform {
  private fun unavailable() = NativeAuthError(NativeAuthError.Code.PASSKEY_UNAVAILABLE, errorDescription = "No PasskeyPlatform is configured")

  override suspend fun assert(params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Boolean): PasskeyAssertion = throw unavailable()

  override suspend fun register(params: PasskeyRegistrationParams): PasskeyAttestation = throw unavailable()
}
