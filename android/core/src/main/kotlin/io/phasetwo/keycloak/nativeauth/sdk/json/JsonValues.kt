package io.phasetwo.keycloak.nativeauth.sdk.json

import java.nio.charset.StandardCharsets
import kotlin.math.abs
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

// Typed views of a kotlinx JSON tree, used for challenge `params`, error bodies and the flow log.
// The protocol tells clients to ignore unknown fields (spec/03 §10), so every wire object is kept
// raw next to its typed view. Every accessor is strict (a string "true" is not a Boolean) and
// null-safe, so `json["a"]["b"].stringValue` reads like the iOS SDK's `JSONValue` subscripts.

/** The member [key] of an object; `null` for anything else. */
public operator fun JsonElement?.get(key: String): JsonElement? = (this as? JsonObject)?.get(key)

/** The element at [index] of an array; `null` for anything else or out of range. */
public operator fun JsonElement?.get(index: Int): JsonElement? = (this as? JsonArray)?.getOrNull(index)

public val JsonElement?.stringValue: String?
  get() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content

public val JsonElement?.boolValue: Boolean?
  get() = (this as? JsonPrimitive)?.takeIf { !it.isString && it !is JsonNull }?.content?.toBooleanStrictOrNull()

public val JsonElement?.doubleValue: Double?
  get() = (this as? JsonPrimitive)?.takeIf { !it.isString && it !is JsonNull }?.content?.toDoubleOrNull()

/** A whole number below 2^53 in magnitude, as the iOS SDK's `intValue`. */
public val JsonElement?.longValue: Long?
  get() = doubleValue?.takeIf { it == Math.rint(it) && abs(it) < 9.0e15 }?.toLong()

public val JsonElement?.intValue: Int?
  get() = longValue?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()

public val JsonElement?.arrayValue: List<JsonElement>? get() = this as? JsonArray

public val JsonElement?.objectValue: Map<String, JsonElement>? get() = this as? JsonObject

public val JsonElement?.isNull: Boolean get() = this is JsonNull

/** `List<String>` when every element is a string. */
public val JsonElement?.stringArray: List<String>?
  get() = arrayValue?.map { it.stringValue ?: return null }

private val pretty = Json { prettyPrint = true }

/**
 * Compact (or pretty-printed) serialization with keys sorted at every level: deterministic, for the
 * logger, the flow log, JWT parts and the tests.
 */
public fun JsonElement.serialized(prettyPrinted: Boolean = false): String {
  val sorted = sortedKeys(this)
  return if (prettyPrinted) pretty.encodeToString(JsonElement.serializer(), sorted) else sorted.toString()
}

private fun sortedKeys(element: JsonElement): JsonElement = when (element) {
  is JsonObject -> JsonObject(element.entries.sortedBy { it.key }.associateTo(LinkedHashMap()) { it.key to sortedKeys(it.value) })
  is JsonArray -> JsonArray(element.map(::sortedKeys))
  else -> element
}

/** Parses [text] as JSON; `null` when it is not JSON. */
public fun parseJsonOrNull(text: String): JsonElement? = runCatching { Json.parseToJsonElement(text) }.getOrNull()

public fun parseJsonOrNull(bytes: ByteArray): JsonElement? =
  if (bytes.isEmpty()) null else parseJsonOrNull(String(bytes, StandardCharsets.UTF_8))

/** A JSON object from pairs, for building bodies and JWT parts. */
public fun jsonObjectOf(vararg pairs: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*pairs))
