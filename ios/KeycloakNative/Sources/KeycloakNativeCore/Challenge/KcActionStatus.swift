import Foundation

/// Outcome of an application-initiated action (spec/21, `kc_action_status` in the success body).
public enum KcActionStatus: Sendable, Equatable {
  /// The action completed.
  case success
  /// The user declined it (`action=skip`).
  case cancelled
  /// The server could not run it: unknown alias, disabled, or not allowed to be started by the app.
  case error
  /// A value this SDK version does not know.
  case other(String)

  public init(wire: String) {
    switch wire {
    case "success": self = .success
    case "cancelled": self = .cancelled
    case "error": self = .error
    default: self = .other(wire)
    }
  }

  public var wire: String {
    switch self {
    case .success: "success"
    case .cancelled: "cancelled"
    case .error: "error"
    case .other(let value): value
    }
  }
}
