import Foundation
import KeycloakNativeCore

/// The access token the push device API is called with (spec/03 §7.1).
public struct DeviceToken: Sendable, Equatable {
  public let accessToken: String
  /// `DPoP` or `Bearer`; ba-itsys needs `DPoP` with the enrolled key.
  public let scheme: String

  public init(accessToken: String, scheme: String = "DPoP") {
    self.accessToken = accessToken
    self.scheme = scheme
  }
}

/// How the SDK obtains the device token (spec/05 §5, spec/08 Q6, spec/14 D9). The strategy is
/// abstract so a deployment can swap it without touching callers:
///
/// - `NativeDeviceTokenProvider` (default, metadata `push.device_token = "native"`): the user's own
///   DPoP-bound native access token — the DPoP key is the device key, nothing else is needed.
/// - EXTENSION POINT: a `client_credentials` provider for a stock ba-itsys install (metadata
///   `device_token = "client_credentials"`, `device_client_id`). It needs a confidential client, i.e.
///   a secret the app must get from somewhere (a backend, not the bundle); it is not shipped here.
public protocol DeviceTokenProvider: Sendable {
  func deviceToken() async throws -> DeviceToken
}

/// The stored credentials of the `KeycloakNative` instance, refreshed when needed. Fails with
/// `device_token_unavailable` when nobody is signed in or the tokens are not DPoP-bound.
public struct NativeDeviceTokenProvider: DeviceTokenProvider {
  private let credentials: CredentialsManager
  private let minTTL: TimeInterval

  public init(credentials: CredentialsManager, minTTL: TimeInterval = 30) {
    self.credentials = credentials
    self.minTTL = minTTL
  }

  public func deviceToken() async throws -> DeviceToken {
    let stored: Credentials
    do {
      stored = try await credentials.credentials(minTTL: minTTL)
    } catch let error as NativeAuthError {
      throw NativeAuthError(code: NativeAuthError.Code.deviceTokenUnavailable, description: "No usable native login for the push device API (\(error.code))", underlying: error)
    }
    guard stored.isDPoPBound else {
      throw NativeAuthError(code: NativeAuthError.Code.deviceTokenUnavailable, description: "The native tokens are not DPoP-bound; the push device API needs a DPoP-bound token (spec/03 §7.1)")
    }
    return DeviceToken(accessToken: stored.accessToken, scheme: stored.authorizationScheme)
  }
}

/// A fixed token (tests, or an app that manages the login itself).
public struct StaticDeviceTokenProvider: DeviceTokenProvider {
  private let token: DeviceToken

  public init(_ token: DeviceToken) {
    self.token = token
  }

  public init(credentials: Credentials) {
    self.token = DeviceToken(accessToken: credentials.accessToken, scheme: credentials.authorizationScheme)
  }

  public func deviceToken() async throws -> DeviceToken { token }
}

extension NativeAuthError.Code {
  /// No DPoP-bound native login to call the push device API with.
  public static let deviceTokenUnavailable = "device_token_unavailable"
  /// This device is not enrolled for push MFA (no stored `PushEnrollment`).
  public static let pushNotEnrolled = "push_not_enrolled"
  /// The server has no push-MFA extension (metadata without a `push` block).
  public static let pushUnavailable = "push_unavailable"
  /// `409` from `/respond`: the challenge was resolved concurrently; re-read the pending list.
  public static let pushConflict = "push_conflict"
  /// `403` from `/respond`: the number / PIN did not match.
  public static let userVerificationMismatch = "user_verification_mismatch"
}
