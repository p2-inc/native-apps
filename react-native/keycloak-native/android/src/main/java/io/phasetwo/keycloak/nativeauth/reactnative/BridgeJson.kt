package io.phasetwo.keycloak.nativeauth.reactnative

import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeAnswer
import io.phasetwo.keycloak.nativeauth.sdk.challenge.ChallengeType
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FlowStep
import io.phasetwo.keycloak.nativeauth.sdk.challenge.FormField
import io.phasetwo.keycloak.nativeauth.sdk.challenge.LoginParameters
import io.phasetwo.keycloak.nativeauth.sdk.dpop.DPoPMode
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.tokens.Credentials
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * The JSON the module exchanges with JavaScript (spec/19 §4), the twin of `BridgeJSON.swift`. Every
 * shape here has a TypeScript reader in `src/model.ts` / `src/KeycloakNative.ts`.
 */
internal object BridgeJson {
  /** `KeycloakNativeConfig` of `src/KeycloakNative.ts`. */
  class Config(
    val issuer: String,
    val clientId: String,
    val dpop: DPoPMode,
    val allowRpIdMismatch: Boolean,
    val ephemeralWebSession: Boolean,
    val metadataCacheTtlSeconds: Long?,
    val storageNamespace: String?,
  )

  fun parseObject(text: String): JsonObject =
    runCatching { Json.parseToJsonElement(text).jsonObject }.getOrElse {
      throw NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = "Expected a JSON object from JavaScript")
    }

  fun config(text: String): Config {
    val o = parseObject(text)
    val issuer = o.string("issuer") ?: throw invalid("issuer is required")
    val clientId = o.string("clientId") ?: throw invalid("clientId is required")
    val dpop = when (val mode = o.string("dpop") ?: "automatic") {
      "automatic" -> DPoPMode.AUTOMATIC
      "hardware" -> DPoPMode.HARDWARE
      "software" -> DPoPMode.SOFTWARE
      "disabled" -> DPoPMode.DISABLED
      else -> throw invalid("Unknown dpop mode '$mode'")
    }
    return Config(
      issuer = issuer,
      clientId = clientId,
      dpop = dpop,
      allowRpIdMismatch = o.bool("allowRpIdMismatch") ?: false,
      ephemeralWebSession = o.bool("ephemeralWebSession") ?: false,
      metadataCacheTtlSeconds = (o["metadataCacheTtl"] as? JsonPrimitive)?.longOrNull,
      storageNamespace = o.string("storageNamespace"),
    )
  }

  /** `LoginParameters` of `src/KeycloakNative.ts`. */
  fun loginParameters(text: String): LoginParameters {
    val o = parseObject(text)
    return LoginParameters(
      // An absent scope is the SDK default; an explicit empty one sends none.
      scope = if (o.containsKey("scope")) o.string("scope") else "openid",
      acrValues = o.string("acrValues"),
      loginHint = o.string("loginHint"),
      prompt = o.string("prompt"),
      maxAge = (o["maxAge"] as? JsonPrimitive)?.intOrNull,
      nonce = o.string("nonce"),
      uiLocales = o.string("uiLocales"),
      deviceName = o.string("deviceName"),
      deviceId = o.string("deviceId"),
      additionalParameters = stringMap(o["additionalParameters"]),
      continuationParameters = stringMap(o["continuationParameters"]),
    )
  }

  fun stringMap(element: JsonElement?): Map<String, String> =
    (element as? JsonObject)?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.contentOrNull?.let { k to it } }?.toMap().orEmpty()

  /**
   * `ChallengeAnswer` of `src/model.ts`. Ceremony answers (passkeys, push enrollment) run natively and
   * are not accepted from JavaScript.
   */
  fun answer(text: String, type: ChallengeType): ChallengeAnswer {
    val o = parseObject(text)
    fun field(name: String) = o.string(name) ?: throw invalid("The ${o.string("kind")} answer needs '$name'")
    return when (val kind = o.string("kind")) {
      "username" -> ChallengeAnswer.Username(field("username"))
      "password" -> ChallengeAnswer.Password(field("password"))
      "totp" -> ChallengeAnswer.Totp(field("code"), o.string("credentialId"))
      "otp" -> ChallengeAnswer.Otp(field("code"))
      "otpResend" -> ChallengeAnswer.OtpResend
      "recoveryCode" -> ChallengeAnswer.RecoveryCode(field("code"))
      "updatePassword" -> ChallengeAnswer.UpdatePassword(field("password"), field("confirm"))
      "verifyEmail" -> ChallengeAnswer.VerifyEmail(field("code"))
      "verifyEmailResend" -> ChallengeAnswer.VerifyEmailResend
      "terms" -> ChallengeAnswer.Terms(o.bool("accepted") ?: throw invalid("The terms answer needs 'accepted'"))
      "pushResend" -> ChallengeAnswer.PushResend
      "pushPoll" -> ChallengeAnswer.PushPoll
      "pushEnrollmentCheck" -> ChallengeAnswer.PushEnrollmentCheck
      "skip" -> ChallengeAnswer.Skip(type)
      "custom" -> ChallengeAnswer.Custom(
        type,
        (o["fields"] as? JsonArray).orEmpty().map { entry ->
          val f = entry as? JsonObject ?: throw invalid("custom fields are {name, value} objects")
          FormField(f.string("name") ?: throw invalid("custom field without a name"), f.string("value") ?: "")
        },
      )
      else -> throw NativeAuthError(NativeAuthError.Code.UNSUPPORTED_CHALLENGE, errorDescription = "Unknown answer kind '$kind'")
    }
  }

  /** `NativeFlowStep`: the descriptors and context as the server sent them. */
  fun step(step: FlowStep, expiresIn: Int?): String = when (step) {
    is FlowStep.Challenges -> buildJsonObject {
      put("kind", "challenges")
      put("challenges", JsonArray(step.challenges.map { it.raw }))
      put("context", step.context.raw)
      expiresIn?.let { put("expiresIn", it) }
    }
    is FlowStep.Authorized -> buildJsonObject {
      put("kind", "authorized")
      put("credentials", credentials(step.credentials))
    }
    is FlowStep.RedirectToWeb -> buildJsonObject {
      put("kind", "redirectToWeb")
      put("request", step.request.raw)
    }
  }.toString()

  /** `NativeCredentials`: everything but the refresh token and the post-login `auth_session`. */
  fun credentials(c: Credentials): JsonObject = buildJsonObject {
    put("accessToken", c.accessToken)
    put("tokenType", c.authorizationScheme)
    put("idToken", c.idToken?.let(::JsonPrimitive) ?: JsonNull)
    put("scope", c.scope?.let(::JsonPrimitive) ?: JsonNull)
    put("expiresAt", millis(c.expiresAt))
    put("refreshExpiresAt", millis(c.refreshExpiresAt))
    put("issuedAt", millis(c.issuedAt))
    put("hasRefreshToken", c.refreshToken != null)
    put("isDPoPBound", c.isDPoPBound)
  }

  /** Epoch milliseconds; `null` for none and for "never" (an offline token's `Instant.MAX`). */
  private fun millis(instant: Instant?): JsonElement =
    if (instant == null || instant.isAfter(FAR_FUTURE)) JsonNull else JsonPrimitive(instant.toEpochMilli())

  private val FAR_FUTURE: Instant = Instant.parse("9999-12-31T23:59:59Z")

  fun headers(headers: Map<String, String>): String = JsonObject(headers.mapValues { JsonPrimitive(it.value) }).toString()

  private fun invalid(message: String) = NativeAuthError(NativeAuthError.Code.INVALID_PARAMETER, errorDescription = message)

  private fun JsonObject.string(name: String): String? = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content

  private fun JsonObject.bool(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull
}
