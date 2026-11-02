package io.phasetwo.keycloak.nativeauth.sdk.config

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.boolValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.parseJsonOrNull
import io.phasetwo.keycloak.nativeauth.sdk.json.stringArray
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import java.net.URI
import java.net.URISyntaxException
import kotlin.time.Duration
import kotlin.time.TimeSource
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** `GET /realms/{realm}/native-auth/metadata` (spec/03 §1.1). Unknown fields are ignored. */
public data class NativeAuthMetadata(
  public val protocolVersion: String,
  public val fipaDraft: String? = null,
  public val authorizationChallengeEndpoint: URI,
  public val tokenEndpoint: URI,
  /** The realm's OIDC authorization endpoint (spec/03 §1.1), used by `WebFallback`. */
  public val authorizationEndpoint: URI? = null,
  public val codeExchange: CodeExchange = CodeExchange(),
  public val passkey: Passkey? = null,
  public val challengeTypesSupported: List<String> = emptyList(),
  /**
   * Proof algorithms the challenge endpoint verifies and binds to (spec/03 §8); empty when it does not
   * verify proofs. The SDK sends ES256 proofs either way and reads `token_type` for the result.
   */
  public val dpopSigningAlgValuesSupported: List<String> = emptyList(),
  public val clientAttestation: ClientAttestation? = null,
  public val push: Push? = null,
  /** The raw document, for fields this version of the SDK does not model. */
  public val raw: JsonElement? = null,
) {
  public data class CodeExchange(public val redirectUriRequired: Boolean = false, public val redirectUri: String? = null)

  public data class Passkey(public val rpId: String, public val registerOptionsEndpoint: URI? = null, public val registerFinishEndpoint: URI? = null)

  public data class ClientAttestation(public val required: Boolean = false, public val methods: List<String> = emptyList())

  /** spec/03 §1.1 `push`: present when the push-MFA extension is installed (spec/03 §7). */
  public data class Push(
    public val enabled: Boolean = true,
    public val enrollStartEndpoint: URI? = null,
    /** ba-itsys device API root (`…/realms/{realm}/push-mfa`). */
    public val deviceApiBase: URI? = null,
    /** `native` (the user's DPoP-bound native token, spec/03 §7.1) or `client_credentials`. */
    public val deviceToken: String = "native",
    public val deviceClientId: String? = null,
    /** Installed senders (`apns`, `fcm`, `log`, `none`). */
    public val pushProviderTypes: List<String> = emptyList(),
  )

  /** Major version only (spec/03 §10). */
  public val protocolMajorVersion: Int? get() = protocolVersion.substringBefore('.').toIntOrNull()

  public fun supports(type: ChallengeType): Boolean = type.wire in challengeTypesSupported

  public companion object {
    /** Parses the document; throws [IllegalArgumentException] when a required field is missing. */
    public fun parse(json: JsonElement): NativeAuthMetadata {
      require(json is JsonObject) { "metadata is not a JSON object" }
      fun string(key: String) = requireNotNull(json[key].stringValue) { "metadata without $key" }
      fun uri(value: JsonElement?): URI? = value.stringValue?.let(::URI)
      return NativeAuthMetadata(
        protocolVersion = string("protocol_version"),
        fipaDraft = json["fipa_draft"].stringValue,
        authorizationChallengeEndpoint = URI(string("authorization_challenge_endpoint")),
        tokenEndpoint = URI(string("token_endpoint")),
        authorizationEndpoint = uri(json["authorization_endpoint"]),
        codeExchange = json["code_exchange"]?.let {
          CodeExchange(it["redirect_uri_required"].boolValue ?: false, it["redirect_uri"].stringValue)
        } ?: CodeExchange(),
        passkey = json["passkey"]?.let {
          Passkey(
            requireNotNull(it["rp_id"].stringValue) { "passkey without rp_id" },
            uri(it["register_options_endpoint"]),
            uri(it["register_finish_endpoint"]),
          )
        },
        challengeTypesSupported = json["challenge_types_supported"].stringArray.orEmpty(),
        dpopSigningAlgValuesSupported = json["dpop_signing_alg_values_supported"].stringArray.orEmpty(),
        clientAttestation = json["client_attestation"]?.let {
          ClientAttestation(it["required"].boolValue ?: false, it["methods"].stringArray.orEmpty())
        },
        push = json["push"]?.let {
          Push(
            enabled = it["enabled"].boolValue ?: true,
            enrollStartEndpoint = uri(it["enroll_start_endpoint"]),
            deviceApiBase = uri(it["device_api_base"]),
            deviceToken = it["device_token"].stringValue ?: "native",
            deviceClientId = it["device_client_id"].stringValue,
            pushProviderTypes = it["push_provider_types"].stringArray.orEmpty(),
          )
        },
        raw = json,
      )
    }
  }
}

/** Fetches and caches the metadata document per `KeycloakNative` instance; concurrent callers share one fetch. */
internal class MetadataClient(issuer: URI, private val transport: Transport, private val ttl: Duration) {
  private val url = URI.create("$issuer/native-auth/metadata")
  private val mutex = Mutex()
  private var cached: Pair<NativeAuthMetadata, TimeSource.Monotonic.ValueTimeMark>? = null
  private var inFlight: CompletableDeferred<NativeAuthMetadata>? = null

  suspend fun metadata(forceRefresh: Boolean = false): NativeAuthMetadata {
    val (pending, owner) = mutex.withLock {
      val current = cached
      if (!forceRefresh && current != null && current.second.elapsedNow() < ttl) return current.first
      inFlight?.let { return@withLock it to false }
      CompletableDeferred<NativeAuthMetadata>().also { inFlight = it } to true
    }
    if (!owner) return pending.await()
    try {
      val metadata = fetch()
      mutex.withLock {
        cached = metadata to TimeSource.Monotonic.markNow()
        inFlight = null
      }
      pending.complete(metadata)
      return metadata
    } catch (e: Throwable) {
      mutex.withLock { inFlight = null }
      pending.completeExceptionally(e)
      throw e
    }
  }

  suspend fun invalidate() = mutex.withLock { cached = null }

  private suspend fun fetch(): NativeAuthMetadata {
    val response = transport.send(HttpRequest("GET", url, mapOf("Accept" to "application/json")))
    if (response.statusCode != 200) {
      throw NativeAuthError(
        NativeAuthError.Code.METADATA_UNAVAILABLE,
        statusCode = response.statusCode,
        errorDescription = "GET $url answered HTTP ${response.statusCode}",
        details = response.json,
      )
    }
    try {
      return NativeAuthMetadata.parse(parseJsonOrNull(response.body) ?: throw IllegalArgumentException("metadata is not JSON"))
    } catch (e: Exception) {
      if (e !is IllegalArgumentException && e !is URISyntaxException) throw e
      throw NativeAuthError(NativeAuthError.Code.INVALID_RESPONSE, statusCode = 200, errorDescription = "Metadata document is malformed", cause = e)
    }
  }
}
