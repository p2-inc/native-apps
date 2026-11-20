import Foundation

/// `Config.plist` in the app bundle (App/Config.plist), with defaults for the compose stack.
public struct DemoConfig: Sendable, Equatable {
  public var issuer: URL
  public var clientId: String
  public var passkeyClientId: String
  public var stepUpClientId: String
  public var otpClientId: String
  public var pinClientId: String
  /// The demo resource server (S6): `GET /transfer` demands acr 2.
  public var resourceServer: URL
  /// Needed when the Keycloak policy's RP ID (e.g. a tunnel host) is not the issuer host.
  public var allowRpIdMismatch: Bool
  public var deviceName: String

  public static let defaults = DemoConfig(
    issuer: URL(string: "http://localhost:8089/realms/demo")!,
    clientId: "demo-native",
    passkeyClientId: "demo-native-passkey",
    stepUpClientId: "demo-native-stepup",
    otpClientId: "demo-native-otp",
    pinClientId: "demo-native-pin",
    resourceServer: URL(string: "http://localhost:8091")!,
    allowRpIdMismatch: false,
    deviceName: "KeycloakNativeDemo")

  public init(issuer: URL, clientId: String, passkeyClientId: String, stepUpClientId: String = "demo-native-stepup", otpClientId: String = "demo-native-otp", pinClientId: String = "demo-native-pin", resourceServer: URL = URL(string: "http://localhost:8091")!, allowRpIdMismatch: Bool, deviceName: String) {
    self.issuer = issuer
    self.clientId = clientId
    self.passkeyClientId = passkeyClientId
    self.stepUpClientId = stepUpClientId
    self.otpClientId = otpClientId
    self.pinClientId = pinClientId
    self.resourceServer = resourceServer
    self.allowRpIdMismatch = allowRpIdMismatch
    self.deviceName = deviceName
  }

  public static func load(bundle: Bundle = .main) -> DemoConfig {
    guard let url = bundle.url(forResource: "Config", withExtension: "plist"),
      let dict = NSDictionary(contentsOf: url) as? [String: Any]
    else { return defaults }
    var config = defaults
    if let issuer = dict["Issuer"] as? String, let url = URL(string: issuer) { config.issuer = url }
    if let clientId = dict["ClientId"] as? String { config.clientId = clientId }
    if let passkeyClientId = dict["PasskeyClientId"] as? String { config.passkeyClientId = passkeyClientId }
    if let v = dict["StepUpClientId"] as? String { config.stepUpClientId = v }
    if let v = dict["OtpClientId"] as? String { config.otpClientId = v }
    if let v = dict["PinClientId"] as? String { config.pinClientId = v }
    if let v = dict["ResourceServer"] as? String, let url = URL(string: v) { config.resourceServer = url }
    if let allow = dict["AllowRpIdMismatch"] as? Bool { config.allowRpIdMismatch = allow }
    if let deviceName = dict["DeviceName"] as? String { config.deviceName = deviceName }
    return config
  }
}

// MARK: - Server settings (Settings screen, persisted in UserDefaults)

extension DemoConfig {
  /// The Keycloak base URL, the part of the issuer before `/realms/<realm>`.
  public var serverURL: String {
    let issuer = self.issuer.absoluteString
    guard let range = issuer.range(of: "/realms/") else { return issuer }
    return String(issuer[..<range.lowerBound])
  }

  /// The realm name, the issuer's last path segment after `/realms/`.
  public var realm: String {
    let issuer = self.issuer.absoluteString
    guard let range = issuer.range(of: "/realms/") else { return "" }
    return String(issuer[range.upperBound...]).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
  }

  private static let storageKey = "demo.serverSettings"

  /// The bundled `Config.plist` with the values saved on the Settings screen on top.
  public static func current(bundle: Bundle = .main, defaults: UserDefaults = .standard) -> DemoConfig {
    var config = load(bundle: bundle)
    guard let saved = defaults.dictionary(forKey: storageKey) as? [String: String] else { return config }
    if let v = saved["issuer"], let url = URL(string: v) { config.issuer = url }
    if let v = saved["clientId"] { config.clientId = v }
    if let v = saved["passkeyClientId"] { config.passkeyClientId = v }
    if let v = saved["stepUpClientId"] { config.stepUpClientId = v }
    if let v = saved["otpClientId"] { config.otpClientId = v }
    if let v = saved["pinClientId"] { config.pinClientId = v }
    if let v = saved["resourceServer"], let url = URL(string: v) { config.resourceServer = url }
    return config
  }

  /// Saves the server settings; `current()` returns them from now on.
  public func save(defaults: UserDefaults = .standard) {
    defaults.set([
      "issuer": issuer.absoluteString,
      "clientId": clientId,
      "passkeyClientId": passkeyClientId,
      "stepUpClientId": stepUpClientId,
      "otpClientId": otpClientId,
      "pinClientId": pinClientId,
      "resourceServer": resourceServer.absoluteString,
    ], forKey: Self.storageKey)
  }

  /// Forgets the saved settings, so `current()` is `Config.plist` again.
  public static func resetSaved(defaults: UserDefaults = .standard) {
    defaults.removeObject(forKey: storageKey)
  }

  /// Plain HTTP is for a Keycloak on this machine only (the simulator shares the Mac's `localhost`,
  /// and `NSAllowsLocalNetworking` covers it); anything else must be HTTPS.
  public static let localHosts: Set<String> = ["localhost", "127.0.0.1", "::1"]

  /// Checks a base URL from the Settings screen: `nil` when usable, else what is wrong.
  public static func problem(withServerURL text: String) -> String? {
    guard let components = URLComponents(string: text), let scheme = components.scheme?.lowercased(),
      let host = components.host, !host.isEmpty
    else { return "Enter a URL such as https://idp.example.com or http://localhost:8089." }
    if components.query != nil || components.fragment != nil { return "Leave out the query and fragment." }
    if components.path.contains("/realms/") { return "Enter the server URL without /realms/…; the realm has its own field." }
    switch scheme {
    case "https": return nil
    case "http": return localHosts.contains(host.lowercased()) ? nil : "Use https for anything but localhost (App Transport Security allows plain HTTP to local hosts only)."
    default: return "The URL must start with https:// (or http:// for localhost)."
    }
  }

  /// Builds the issuer `<server>/realms/<realm>` from the Settings screen's fields.
  public static func issuer(serverURL: String, realm: String) -> URL? {
    let base = serverURL.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let realm = realm.trimmingCharacters(in: .whitespaces)
    guard !realm.isEmpty, let encoded = realm.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) else { return nil }
    return URL(string: "\(base)/realms/\(encoded)")
  }
}
