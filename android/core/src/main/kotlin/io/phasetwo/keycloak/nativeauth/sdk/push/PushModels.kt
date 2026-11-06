package io.phasetwo.keycloak.nativeauth.sdk.push

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.jose.Jwt
import io.phasetwo.keycloak.nativeauth.sdk.json.arrayValue
import io.phasetwo.keycloak.nativeauth.sdk.json.doubleValue
import io.phasetwo.keycloak.nativeauth.sdk.json.get
import io.phasetwo.keycloak.nativeauth.sdk.json.longValue
import io.phasetwo.keycloak.nativeauth.sdk.json.stringValue
import java.net.URI
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/** What the SDK keeps about this device's push enrollment (the instance's `SecureStore`). */
public data class PushEnrollment(
  /** App-local handle of the credential on the server (`credentialId` of the device JWT). */
  public val credentialId: String,
  /** Stable per-installation id (`deviceId` of the device JWT and of every proof). */
  public val deviceId: String,
  /** Keycloak user id (`sub`); the device API's `userId` query. */
  public val userId: String,
  public val username: String?,
  public val deviceLabel: String,
  /** `fcm` | `apns` | `none` | … (ba-itsys `pushProviderType`). */
  public val pushProviderType: String,
  /** The FCM registration token when [pushProviderType] is `fcm`. */
  public val pushProviderId: String?,
  /** ba-itsys device API root (`…/realms/{realm}/push-mfa`). */
  public val deviceApiBase: URI,
  /** RFC 7638 thumbprint of the key the credential is bound to (the DPoP key, spec/14 D9). */
  public val keyThumbprint: String,
  /** Stored at millisecond precision. */
  public val enrolledAt: Instant = Instant.now().truncatedTo(ChronoUnit.MILLIS),
) {
  override fun toString(): String =
    "PushEnrollment(credentialId=$credentialId, deviceId=$deviceId, userId=$userId, username=$username, deviceLabel=$deviceLabel, " +
      "pushProviderType=$pushProviderType, deviceApiBase=$deviceApiBase)"
}

/**
 * Where push messages reach this device: the server's sender (`fcm`, `apns`, `none`) and the token it
 * addresses (the FCM registration token for `fcm`). The `push` module supplies the FCM one.
 */
public data class PushProviderRegistration(public val type: String, public val id: String?) {
  override fun toString(): String = "PushProviderRegistration(type=$type)"

  public companion object {
    /** No delivery: the app reads its pending approvals itself. */
    public val NONE: PushProviderRegistration = PushProviderRegistration("none", null)
  }
}

/** One entry of `GET /push-mfa/login/pending` (spec/03 §7). */
public class PendingApproval private constructor(public val raw: JsonElement, public val cid: String) {
  public val userId: String? = raw["userId"].stringValue
  public val username: String? = raw["username"].stringValue
  public val clientId: String? = raw["clientId"].stringValue
  public val clientName: String? = raw["clientName"].stringValue
  public val createdAt: Instant? = raw["createdAt"].epochSeconds()
  public val expiresAt: Instant? = raw["expiresAt"].epochSeconds()

  /** Number match: the three numbers to offer; the browser or native client shows one of them. */
  public val numbers: List<String> =
    raw["userVerification"]["numbers"].arrayValue.orEmpty().mapNotNull { n -> (n as? JsonPrimitive)?.let { it.longValue?.toString() ?: it.stringValue } }

  /** `pin` user verification: the user types the PIN the other side shows. */
  public val requiresPin: Boolean = raw["userVerification"]["type"].stringValue == "pin"

  public fun isExpired(now: Instant = Instant.now()): Boolean = expiresAt?.let { !it.isAfter(now) } ?: false

  /** What to show: the client's display name, else its id. */
  public val clientDisplayName: String get() = clientName ?: clientId ?: "?"

  override fun equals(other: Any?): Boolean = other is PendingApproval && other.raw == raw

  override fun hashCode(): Int = raw.hashCode()

  override fun toString(): String = "PendingApproval(cid=$cid, client=$clientDisplayName, numbers=${numbers.size}, requiresPin=$requiresPin)"

  public companion object {
    /** `null` when [json] has no `cid`. */
    public fun parse(json: JsonElement): PendingApproval? = json["cid"].stringValue?.let { PendingApproval(json, it) }
  }
}

/** The device's answer to a pending approval (`POST /push-mfa/login/challenges/{cid}/respond`). */
public sealed class PushApprovalAction(internal val wire: String) {
  /**
   * [userVerification]: the number the user picked (number match) or the PIN typed, `null` when the
   * challenge has no user verification.
   */
  public data class Approve(public val userVerification: String? = null) : PushApprovalAction("approve")

  public data object Deny : PushApprovalAction("deny")
}

/**
 * The push-MFA keys of a notification. FCM (ba-itsys' `fcm` sender) puts the confirm token in
 * `data.token`; APNs in `confirmToken`. The token is realm-signed; its claims (`cid`, `credId`,
 * `exp`) are read unverified: the device API is the authority, the token only routes the message.
 */
public data class PushNotificationPayload(
  public val confirmToken: String,
  public val cid: String,
  public val credentialId: String?,
  public val expiresAt: Instant?,
) {
  override fun toString(): String = "PushNotificationPayload(cid=$cid, credentialId=$credentialId)"

  public companion object {
    /** From the data map of a message (`RemoteMessage.data`); `null` when it is not a push-MFA message. */
    public fun parse(data: Map<String, String>): PushNotificationPayload? {
      val token = data["token"] ?: data["confirmToken"] ?: return null
      val claims = Jwt.decodePayload(token) ?: return null
      val cid = claims["cid"].stringValue ?: data["cid"] ?: return null
      return PushNotificationPayload(token, cid, claims["credId"].stringValue ?: data["credId"], claims["exp"].epochSeconds())
    }
  }
}

/**
 * The in-flow enrollment answer (spec/03 §4.15) together with what to remember once the server
 * accepted it ([Push.commit]).
 */
public class PreparedPushEnrollment internal constructor(
  public val answer: ChallengeAnswer.PushEnrollment,
  public val enrollment: PushEnrollment,
) {
  override fun toString(): String = "PreparedPushEnrollment($enrollment)"
}

private fun JsonElement?.epochSeconds(): Instant? = doubleValue?.let { Instant.ofEpochMilli((it * 1000).toLong()) }
