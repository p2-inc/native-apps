import Foundation

/// RFC 4648 §5 base64url without padding — the encoding of every binary value on the wire
/// (spec/03 conventions).
public enum Base64URL {
  public static func encode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  public static func encode(_ string: String) -> String {
    encode(Data(string.utf8))
  }

  /// Accepts unpadded and padded input; `nil` for anything that is not base64url.
  public static func decode(_ string: String) -> Data? {
    var text = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
      .replacingOccurrences(of: "=", with: "")
    let remainder = text.count % 4
    if remainder == 1 { return nil }
    if remainder > 0 { text += String(repeating: "=", count: 4 - remainder) }
    return Data(base64Encoded: text)
  }
}
