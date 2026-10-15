import Foundation
import SwiftUI

/// Localised strings of the default screens (spec/05 §4): the package ships `Localizable.xcstrings`
/// (English source, German); an app overrides any key by supplying its own bundle with
/// `.nativeLoginStrings(bundle:)`. Keys are the English texts; `%@` / `%lld` are the arguments.
public struct NativeLoginStrings: Sendable {
  /// Looked up first; a key it does not define falls back to the package's catalogue.
  public let override: Bundle?

  public init(override: Bundle? = nil) {
    self.override = override
  }

  private static let missing = "\u{0}missing\u{0}"

  /// The localised format for `key`, from the override bundle, else the package, else the key.
  public func format(_ key: String) -> String {
    if let override {
      let value = override.localizedString(forKey: key, value: Self.missing, table: nil)
      if value != Self.missing { return value }
    }
    return Bundle.module.localizedString(forKey: key, value: key, table: nil)
  }

  public func callAsFunction(_ key: String) -> String {
    format(key)
  }

  public func callAsFunction(_ key: String, _ arguments: CVarArg...) -> String {
    String(format: format(key), locale: Locale.current, arguments: arguments)
  }
}

struct NativeLoginStringsKey: EnvironmentKey {
  static let defaultValue = NativeLoginStrings()
}

extension EnvironmentValues {
  /// The strings the default screens use; override with `.nativeLoginStrings(bundle:)`.
  public var nativeLoginStrings: NativeLoginStrings {
    get { self[NativeLoginStringsKey.self] }
    set { self[NativeLoginStringsKey.self] = newValue }
  }
}

extension View {
  /// Overrides the default screens' texts with the `Localizable` table of `bundle` (spec/05 §4);
  /// keys the bundle does not define keep the package's localisation.
  public func nativeLoginStrings(bundle: Bundle) -> some View {
    environment(\.nativeLoginStrings, NativeLoginStrings(override: bundle))
  }
}
