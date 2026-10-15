import Foundation
import SwiftUI

/// Localised strings of the default screens (spec/05 §4): the package ships `Localizable.xcstrings`
/// (English source, German); an app overrides any key by supplying its own bundle with
/// `.nativeLoginStrings(bundle:)`. Keys are the English texts; `%@` / `%lld` are the arguments.
///
/// Lookup order: the override bundle's `Localizable` table, then the package catalogue (the
/// `.lproj` tables Xcode compiles from the catalogue, or — on a Command Line Tools build, which
/// copies `Localizable.xcstrings` verbatim — the catalogue file itself), then the key.
public struct NativeLoginStrings: Sendable {
  /// Looked up first; a key it does not define falls back to the package's catalogue.
  public let override: Bundle?
  /// Languages to resolve the package catalogue in, most preferred first; `nil` = the system's.
  public let preferredLanguages: [String]?

  public init(override: Bundle? = nil, preferredLanguages: [String]? = nil) {
    self.override = override
    self.preferredLanguages = preferredLanguages
  }

  private static let missing = "\u{0}missing\u{0}"

  /// The localised format for `key`, from the override bundle, else the package, else the key.
  public func format(_ key: String) -> String {
    if let override, let value = Self.lookup(key, in: override) {
      return value
    }
    return PackageCatalogue.shared.lookup(key, languages: preferredLanguages) ?? key
  }

  public func callAsFunction(_ key: String) -> String {
    format(key)
  }

  public func callAsFunction(_ key: String, _ arguments: CVarArg...) -> String {
    String(format: format(key), locale: Locale.current, arguments: arguments)
  }

  static func lookup(_ key: String, in bundle: Bundle) -> String? {
    let value = bundle.localizedString(forKey: key, value: missing, table: nil)
    return value == missing ? nil : value
  }
}

/// The package's own catalogue, read once. Compiled `.lproj` tables when the build produced them
/// (Xcode / the default SwiftPM build system), the raw `Localizable.xcstrings` JSON otherwise.
final class PackageCatalogue: Sendable {
  static let shared = PackageCatalogue()

  private let compiled: [String: Bundle]        // language → .lproj bundle
  private let raw: [String: [String: String]]   // language → key → value
  private let sourceLanguage: String
  private let languages: [String]

  private init() {
    let module = Bundle.module
    var compiled: [String: Bundle] = [:]
    for language in module.localizations {
      if let path = module.path(forResource: language, ofType: "lproj"), let bundle = Bundle(path: path),
        bundle.path(forResource: "Localizable", ofType: "strings") != nil || bundle.path(forResource: "Localizable", ofType: "loctable") != nil
      {
        compiled[language] = bundle
      }
    }
    var raw: [String: [String: String]] = [:]
    var source = "en"
    if compiled.isEmpty, let url = module.url(forResource: "Localizable", withExtension: "xcstrings"),
      let data = try? Data(contentsOf: url),
      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    {
      source = json["sourceLanguage"] as? String ?? "en"
      for (key, entry) in json["strings"] as? [String: Any] ?? [:] {
        for (language, localization) in (entry as? [String: Any])?["localizations"] as? [String: Any] ?? [:] {
          if let value = ((localization as? [String: Any])?["stringUnit"] as? [String: Any])?["value"] as? String {
            raw[language, default: [:]][key] = value
          }
        }
      }
    }
    self.compiled = compiled
    self.raw = raw
    self.sourceLanguage = source
    self.languages = Array(Set(compiled.keys).union(raw.keys).union([source]))
  }

  func lookup(_ key: String, languages preferred: [String]?) -> String? {
    let order = preferred ?? Bundle.preferredLocalizations(from: languages)
    for language in order {
      if let bundle = compiled[language], let value = NativeLoginStrings.lookup(key, in: bundle) { return value }
      if let value = raw[language]?[key] { return value }
      if language == sourceLanguage || language.hasPrefix(sourceLanguage + "-") { return key }
    }
    if !compiled.isEmpty, let value = NativeLoginStrings.lookup(key, in: Bundle.module) { return value }
    return nil
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
  /// keys the bundle does not define keep the package's localisation. `preferredLanguages` pins
  /// the package catalogue's language (default: the system's preference).
  public func nativeLoginStrings(bundle: Bundle, preferredLanguages: [String]? = nil) -> some View {
    environment(\.nativeLoginStrings, NativeLoginStrings(override: bundle, preferredLanguages: preferredLanguages))
  }
}
