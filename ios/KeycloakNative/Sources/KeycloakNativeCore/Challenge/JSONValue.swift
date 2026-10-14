import Foundation

/// A small, `Sendable` JSON tree used for challenge `params`, error bodies and the flow log. The
/// protocol tells clients to ignore unknown fields (spec/03 §10), so every wire object is kept raw
/// next to its typed view.
public enum JSONValue: Sendable, Equatable, Hashable {
  case null
  case bool(Bool)
  case number(Double)
  case string(String)
  case array([JSONValue])
  case object([String: JSONValue])

  public subscript(key: String) -> JSONValue? {
    if case .object(let o) = self { return o[key] }
    return nil
  }

  public subscript(index: Int) -> JSONValue? {
    if case .array(let a) = self, a.indices.contains(index) { return a[index] }
    return nil
  }

  public var stringValue: String? {
    if case .string(let s) = self { return s }
    return nil
  }

  public var boolValue: Bool? {
    if case .bool(let b) = self { return b }
    return nil
  }

  public var doubleValue: Double? {
    if case .number(let n) = self { return n }
    return nil
  }

  public var intValue: Int? {
    guard case .number(let n) = self, n.rounded() == n, abs(n) < 9.0e15 else { return nil }
    return Int(n)
  }

  public var arrayValue: [JSONValue]? {
    if case .array(let a) = self { return a }
    return nil
  }

  public var objectValue: [String: JSONValue]? {
    if case .object(let o) = self { return o }
    return nil
  }

  public var isNull: Bool {
    if case .null = self { return true }
    return false
  }

  /// `[String]` when every element is a string.
  public var stringArray: [String]? {
    guard let array = arrayValue else { return nil }
    var out: [String] = []
    for element in array {
      guard let s = element.stringValue else { return nil }
      out.append(s)
    }
    return out
  }
}

extension JSONValue: Codable {
  public init(from decoder: any Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let b = try? container.decode(Bool.self) {
      self = .bool(b)
    } else if let n = try? container.decode(Double.self) {
      self = .number(n)
    } else if let s = try? container.decode(String.self) {
      self = .string(s)
    } else if let a = try? container.decode([JSONValue].self) {
      self = .array(a)
    } else if let o = try? container.decode([String: JSONValue].self) {
      self = .object(o)
    } else {
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
    }
  }

  public func encode(to encoder: any Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .null: try container.encodeNil()
    case .bool(let b): try container.encode(b)
    case .number(let n):
      if n.rounded() == n, abs(n) < 9.0e15 { try container.encode(Int(n)) } else { try container.encode(n) }
    case .string(let s): try container.encode(s)
    case .array(let a): try container.encode(a)
    case .object(let o): try container.encode(o)
    }
  }
}

extension JSONValue {
  /// Parses `data` as JSON; `nil` when it is not JSON.
  public init?(jsonData data: Data) {
    guard let value = try? JSONDecoder().decode(JSONValue.self, from: data) else { return nil }
    self = value
  }

  public init?(jsonString: String) {
    self.init(jsonData: Data(jsonString.utf8))
  }

  /// Compact serialisation with sorted keys (deterministic; used by the logger and the tests).
  public func serialized(prettyPrinted: Bool = false) -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = prettyPrinted ? [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
    guard let data = try? encoder.encode(self), let text = String(data: data, encoding: .utf8) else { return "null" }
    return text
  }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
  ExpressibleByFloatLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral, ExpressibleByNilLiteral
{
  public init(stringLiteral value: String) { self = .string(value) }
  public init(booleanLiteral value: Bool) { self = .bool(value) }
  public init(integerLiteral value: Int) { self = .number(Double(value)) }
  public init(floatLiteral value: Double) { self = .number(value) }
  public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
  public init(dictionaryLiteral elements: (String, JSONValue)...) {
    self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
  }
  public init(nilLiteral: ()) { self = .null }
}
