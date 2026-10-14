import Foundation

/// `Config.plist` in the app bundle (App/Config.plist), with defaults for the compose stack.
public struct DemoConfig: Sendable, Equatable {
  public var issuer: URL
  public var clientId: String
  public var passkeyClientId: String
  /// Needed when the Keycloak policy's RP ID (e.g. a tunnel host) is not the issuer host.
  public var allowRpIdMismatch: Bool
  public var deviceName: String

  public static let defaults = DemoConfig(
    issuer: URL(string: "http://localhost:8089/realms/demo")!,
    clientId: "demo-ios",
    passkeyClientId: "demo-ios-passkey",
    allowRpIdMismatch: false,
    deviceName: "KeycloakNativeDemo")

  public init(issuer: URL, clientId: String, passkeyClientId: String, allowRpIdMismatch: Bool, deviceName: String) {
    self.issuer = issuer
    self.clientId = clientId
    self.passkeyClientId = passkeyClientId
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
    if let allow = dict["AllowRpIdMismatch"] as? Bool { config.allowRpIdMismatch = allow }
    if let deviceName = dict["DeviceName"] as? String { config.deviceName = deviceName }
    return config
  }
}
