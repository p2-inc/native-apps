import AuthenticationServices
import Foundation

/// A username and password the user picked from their password manager. `description` leaves the
/// password out.
public struct SavedPassword: Sendable, Equatable, CustomStringConvertible {
  public let username: String
  public let password: String

  public init(username: String, password: String) {
    self.username = username
    self.password = password
  }

  public var description: String { "SavedPassword(username: \(username), password: ***)" }
}

/// The platform half of the saved-password picker: shows the system sheet listing the passwords
/// saved for the app's associated domains (iCloud Keychain and third-party password managers).
/// Production uses `ASAuthorizationSavedPasswordPlatform`; tests inject a mock.
public protocol SavedPasswordPlatform: Sendable {
  func pick() async throws -> SavedPassword
}

/// `ASAuthorizationPasswordProvider` behind `ASAuthorizationController`. The sheet lists passwords
/// saved for the domains in the app's Associated Domains `webcredentials:` entries. Cancellation
/// becomes `saved_password_cancelled`; no saved password or no sheet, `saved_password_unavailable`.
public final class ASAuthorizationSavedPasswordPlatform: SavedPasswordPlatform {
  private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?

  public init(anchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil) {
    self.anchor = anchor
  }

  public func pick() async throws -> SavedPassword {
    let result: PasskeyPlatformResult
    do {
      result = try await AuthorizationBridge(anchor: anchor).perform(options: []) {
        ASAuthorizationPasswordProvider().createRequest()
      }
    } catch let error as NativeAuthError {
      throw Self.map(error)
    }
    guard case .password(let saved) = result else {
      throw NativeAuthError(code: NativeAuthError.Code.savedPasswordUnavailable, description: "Unexpected credential type for a saved password")
    }
    return saved
  }

  /// `AuthorizationBridge` reports passkey codes; the picker has its own two.
  static func map(_ error: NativeAuthError) -> NativeAuthError {
    switch error.code {
    case NativeAuthError.Code.passkeyCancelled:
      NativeAuthError(code: NativeAuthError.Code.savedPasswordCancelled, description: "The user closed the saved-password sheet", underlying: error.underlying)
    default:
      NativeAuthError(code: NativeAuthError.Code.savedPasswordUnavailable, description: error.errorDescription ?? "No saved password could be picked", underlying: error.underlying)
    }
  }
}
