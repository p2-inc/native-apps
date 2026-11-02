package io.phasetwo.keycloak.nativeauth.sdk.support

import io.phasetwo.keycloak.nativeauth.sdk.KeycloakNative
import io.phasetwo.keycloak.nativeauth.sdk.challenge.Challenge
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyAssertionParams
import io.phasetwo.keycloak.nativeauth.sdk.challenge.PasskeyRegistrationParams
import io.phasetwo.keycloak.nativeauth.sdk.credentials.InMemorySecureStore
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.stringArray
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import io.phasetwo.keycloak.nativeauth.sdk.json.serialized
import io.phasetwo.keycloak.nativeauth.sdk.logging.LogLevel
import io.phasetwo.keycloak.nativeauth.sdk.logging.NativeAuthLogger
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAssertion
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyAttestation
import io.phasetwo.keycloak.nativeauth.sdk.passkeys.PasskeyPlatform
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowLogEntry
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowObserver
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpRequest
import io.phasetwo.keycloak.nativeauth.sdk.transport.HttpResponse
import io.phasetwo.keycloak.nativeauth.sdk.transport.Transport
import io.phasetwo.keycloak.nativeauth.sdk.web.WebAuthenticationPresenter
import java.net.URI
import kotlinx.serialization.json.JsonElement
import org.junit.jupiter.api.Assertions.fail

/** Builds an SDK instance wired to a transport, an in-memory store and a scripted passkey platform. Twin of `Harness.swift`. */
class Harness(
  issuer: URI,
  clientId: String,
  val transport: Transport,
  dpop: DPoPMode = DPoPMode.SOFTWARE,
  allowRpIdMismatch: Boolean = false,
  webPresenter: WebAuthenticationPresenter? = null,
) {
  val store = InMemorySecureStore()
  val passkeys = MockPasskeyPlatform()
  val observer = CapturingObserver()
  val logger = CapturingLogger()
  val sdk: KeycloakNative = KeycloakNative.configure(
    issuer,
    clientId,
    KeycloakNative.Options(
      dpop = dpop,
      allowRpIdMismatch = allowRpIdMismatch,
      logger = logger,
      transport = transport,
      flowObserver = observer,
      secureStore = store,
      passkeyPlatform = passkeys,
      webPresenter = webPresenter,
    ),
  )

  companion object {
    const val METADATA = "NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath"

    /** Metadata exchange (always the first request of a flow) followed by the scenario's exchanges. */
    fun replay(
      names: List<String>,
      clientId: String,
      metadataFrom: String = METADATA,
      range: IntRange? = null,
      seqs: List<Int>? = null,
      webPresenter: WebAuthenticationPresenter? = null,
    ): Triple<Harness, MockTransport, List<Transcript>> {
      val metadata = Transcript.load(metadataFrom)
      val transcripts = names.map(Transcript::load)
      val exchanges = mutableListOf(metadata.exchange(1))
      exchanges += when {
        seqs != null && transcripts.size == 1 -> seqs.map(transcripts[0]::exchange)
        range != null && transcripts.size == 1 -> transcripts[0].exchanges(range)
        else -> transcripts.flatMap { it.exchanges }
      }
      val transport = MockTransport(exchanges)
      return Triple(Harness(metadata.issuer, clientId, transport, webPresenter = webPresenter), transport, transcripts)
    }
  }
}

fun List<Challenge>.first(type: ChallengeType): Challenge? = firstOrNull { it.type == type }

fun List<Challenge>.require(type: ChallengeType): Challenge = first(type) ?: fail("no $type challenge in ${types()}")

fun List<Challenge>.types(): List<String> = map { it.type.wire }

fun <T> T?.req(message: String = "expected a value"): T = this ?: fail(message)

/** Runs [block] and returns the [NativeAuthError] it throws; fails when it throws nothing or something else. */
suspend fun expectError(block: suspend () -> Unit): NativeAuthError {
  try {
    block()
  } catch (e: NativeAuthError) {
    return e
  }
  fail<Nothing>("expected a NativeAuthError")
}

/** Scripted [PasskeyPlatform]: returns queued assertions/attestations or a queued error, and records the params it was asked for. */
class MockPasskeyPlatform : PasskeyPlatform {
  private val assertions = ArrayDeque<PasskeyAssertion>()
  private val attestations = ArrayDeque<PasskeyAttestation>()
  private var nextError: NativeAuthError? = null
  val assertParams = mutableListOf<PasskeyAssertionParams>()
  val registerParams = mutableListOf<PasskeyRegistrationParams>()
  val preferImmediatelyAvailable = mutableListOf<Boolean>()

  @Synchronized fun enqueue(assertion: PasskeyAssertion) { assertions += assertion }

  @Synchronized fun enqueue(attestation: PasskeyAttestation) { attestations += attestation }

  @Synchronized fun fail(error: NativeAuthError) { nextError = error }

  override suspend fun assert(params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Boolean): PasskeyAssertion = synchronized(this) {
    assertParams += params
    preferImmediatelyAvailable += preferImmediatelyAvailableCredentials
    nextError?.let { nextError = null; throw it }
    assertions.removeFirstOrNull() ?: throw NativeAuthError("mock_empty", errorDescription = "no assertion queued")
  }

  override suspend fun register(params: PasskeyRegistrationParams): PasskeyAttestation = synchronized(this) {
    registerParams += params
    nextError?.let { nextError = null; throw it }
    attestations.removeFirstOrNull() ?: throw NativeAuthError("mock_empty", errorDescription = "no attestation queued")
  }
}

/** Closure-driven transport for hand-written cases: one handler per request, the last one repeats. */
class ScriptedTransport(vararg handlers: (HttpRequest) -> HttpResponse) : Transport {
  private val handlers = ArrayDeque(handlers.toList())
  private val sentRequests = mutableListOf<HttpRequest>()
  val sent: List<HttpRequest> @Synchronized get() = sentRequests.toList()

  override suspend fun send(request: HttpRequest): HttpResponse {
    val handler = synchronized(this) {
      sentRequests += request
      if (handlers.size > 1) handlers.removeFirst() else handlers.firstOrNull()
    } ?: throw MockTransport.Mismatch("no handler for ${request.method} ${request.url}")
    return handler(request)
  }

  companion object {
    fun json(status: Int, json: JsonElement, headers: Map<String, String> = emptyMap()): HttpResponse =
      HttpResponse(status, headers + ("Content-Type" to "application/json"), json.serialized().toByteArray())

    fun json(status: Int, text: String, headers: Map<String, String> = emptyMap()): HttpResponse =
      HttpResponse(status, headers + ("Content-Type" to "application/json"), text.toByteArray())

    /** A minimal metadata document for `https://idp.example.com/realms/demo`. */
    const val METADATA_JSON: String =
      """{"protocol_version":"1","authorization_challenge_endpoint":"https://idp.example.com/realms/demo/native-auth/challenge","token_endpoint":"https://idp.example.com/realms/demo/protocol/openid-connect/token"}"""
  }
}

class CapturingObserver : FlowObserver {
  private val items = mutableListOf<FlowLogEntry>()
  val entries: List<FlowLogEntry> @Synchronized get() = items.toList()

  @Synchronized override fun record(entry: FlowLogEntry) { items += entry }
}

class CapturingLogger : NativeAuthLogger {
  private val items = mutableListOf<Pair<LogLevel, String>>()
  val lines: List<String> @Synchronized get() = items.map { it.second }

  override fun log(level: LogLevel, message: () -> String) {
    val text = message()
    synchronized(this) { items += level to text }
  }
}

/** Plays the browser for `WebFallback`: records the URL it was asked to open and answers with a scripted callback. */
class MockWebPresenter(@Volatile var callback: (URI) -> URI) : WebAuthenticationPresenter {
  private val openedUrls = mutableListOf<Pair<URI, String>>()
  val opened: List<Pair<URI, String>> @Synchronized get() = openedUrls.toList()

  override suspend fun authenticate(url: URI, callbackScheme: String): URI {
    synchronized(this) { openedUrls += url to callbackScheme }
    return callback(url)
  }
}

/** Rebuilds the assertion the integration test sent (so the mock platform can replay it exactly). */
fun assertionFrom(form: Map<String, String>): PasskeyAssertion = PasskeyAssertion(
  form.getValue("credential_id"), form.getValue("client_data_json"), form.getValue("authenticator_data"), form.getValue("signature"), form["user_handle"],
)

fun attestationFrom(form: Map<String, String>): PasskeyAttestation = PasskeyAttestation(
  form.getValue("credential_id"), form.getValue("client_data_json"), form.getValue("attestation_object"),
  form["transports"].orEmpty().split(',').filter { it.isNotEmpty() },
)

fun attestationFrom(json: JsonElement): PasskeyAttestation = PasskeyAttestation(
  json["credential_id"].stringValue!!, json["client_data_json"].stringValue!!, json["attestation_object"].stringValue!!,
  json["transports"].stringValue?.split(',') ?: json["transports"].stringArray.orEmpty(),
)
