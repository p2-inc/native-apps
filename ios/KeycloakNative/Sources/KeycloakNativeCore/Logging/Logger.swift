import Foundation
import os

public enum LogLevel: Int, Sendable, Comparable {
  case debug, info, warning, error
  public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Logging hook (spec/05 §3.3). Everything the SDK logs has already gone through `Redactor`;
/// implementations must not try to log raw requests themselves.
public protocol NativeAuthLogger: Sendable {
  func log(_ level: LogLevel, _ message: @autoclosure () -> String)
}

/// Default: `os.Logger` under subsystem `io.phasetwo.keycloak.native`.
public struct OSLogLogger: NativeAuthLogger {
  private let logger: Logger
  private let minimumLevel: LogLevel

  public init(subsystem: String = "io.phasetwo.keycloak.native", category: String = "sdk", minimumLevel: LogLevel = .info) {
    self.logger = Logger(subsystem: subsystem, category: category)
    self.minimumLevel = minimumLevel
  }

  public func log(_ level: LogLevel, _ message: @autoclosure () -> String) {
    guard level >= minimumLevel else { return }
    let text = message()
    switch level {
    case .debug: logger.debug("\(text, privacy: .public)")
    case .info: logger.info("\(text, privacy: .public)")
    case .warning: logger.warning("\(text, privacy: .public)")
    case .error: logger.error("\(text, privacy: .public)")
    }
  }
}

public struct NoopLogger: NativeAuthLogger {
  public init() {}
  public func log(_ level: LogLevel, _ message: @autoclosure () -> String) {}
}

/// Masks secrets before anything reaches a log or the app's flow log: `auth_session`, codes, tokens,
/// passwords, OTPs, WebAuthn assertion/attestation material, push enrolment / confirm / device
/// tokens (spec/05 §3.3, task rule "never log").
public enum Redactor {
  public static let mask = "***"

  /// Form fields, JSON keys and header names (case-insensitive) whose values are never shown.
  public static let sensitiveKeys: Set<String> = [
    "auth_session", "password", "password_confirm", "totp", "otp", "recovery_code",
    "authorization_code", "code", "code_verifier",
    "access_token", "refresh_token", "id_token", "token", "client_secret", "registration_id",
    "request_uri",
    "signature", "authenticator_data", "client_data_json", "attestation_object",
    "authorization", "dpop", "dpop-nonce",
    // Push MFA (spec/03 §4.15, §7): the realm-signed enrolment token, the device-signed JWTs
    // (`token`, above), the APNs confirm token and the APNs device token.
    "enrollment_token", "confirmtoken", "confirm_token", "pushproviderid", "push_provider_id", "device_token",
  ]

  public static func isSensitive(_ key: String) -> Bool {
    // Extension parameters (spec/03 §2.3) carry deployment data such as device or risk signals.
    sensitiveKeys.contains(key.lowercased()) || key.lowercased().hasPrefix("x_")
  }

  public static func redact(form fields: [(name: String, value: String)]) -> [(name: String, value: String)] {
    fields.map { (name: $0.name, value: isSensitive($0.name) ? mask : $0.value) }
  }

  public static func redact(headers: [String: String]) -> [String: String] {
    var out: [String: String] = [:]
    for (name, value) in headers {
      if isSensitive(name) {
        // Keep the scheme ("Bearer ***") so the log still shows which kind of credential was sent.
        if let space = value.firstIndex(of: " ") {
          out[name] = String(value[..<space]) + " " + mask
        } else {
          out[name] = mask
        }
      } else {
        out[name] = value
      }
    }
    return out
  }

  public static func redact(json: JSONValue) -> JSONValue {
    switch json {
    case .object(let object):
      var out: [String: JSONValue] = [:]
      for (key, value) in object {
        out[key] = isSensitive(key) ? .string(mask) : redact(json: value)
      }
      return .object(out)
    case .array(let array):
      return .array(array.map(redact(json:)))
    default:
      return json
    }
  }

  /// A one-line, redacted description of a request for debug logs.
  public static func describe(_ request: HTTPRequest) -> String {
    var line = "\(request.method) \(request.url.absoluteString)"
    if let fields = request.formFields {
      line += " form=" + redact(form: fields).map { "\($0.name)=\($0.value)" }.joined(separator: "&")
    } else if let body = request.body, let json = JSONValue(jsonData: body) {
      line += " json=" + redact(json: json).serialized()
    }
    return line
  }

  public static func describe(_ response: HTTPResponse) -> String {
    if let json = response.json {
      return "HTTP \(response.statusCode) " + redact(json: json).serialized()
    }
    return "HTTP \(response.statusCode) (\(response.body.count) bytes)"
  }
}
