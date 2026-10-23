import Foundation

/// The single error type of the SDK (spec/05 §2.3). Apps switch on `code`, never on messages.
/// Server codes are the `error` values of spec/03 §3.5 / §6; SDK-local codes are listed in
/// `NativeAuthError.Code` as well.
public struct NativeAuthError: Error, CustomStringConvertible {
  /// Stable codes. Server-issued codes are passed through unchanged, so this list is not closed.
  public enum Code {
    // spec/03 §3.5 (challenge endpoint)
    public static let invalidRequest = "invalid_request"
    public static let invalidSession = "invalid_session"
    public static let invalidDPoPProof = "invalid_dpop_proof"
    public static let invalidClient = "invalid_client"
    public static let accessDenied = "access_denied"
    public static let slowDown = "slow_down"
    public static let clientAttestationRequired = "client_attestation_required"
    public static let serverError = "server_error"
    /// spec/03 §3.4: surfaces as `FlowStep.redirectToWeb`; this code only appears when the body
    /// could not be parsed into a `RedirectToWebRequest`.
    public static let redirectToWeb = "redirect_to_web"
    // spec/03 §6 (bearer-authenticated endpoints) and the token endpoint
    public static let invalidToken = "invalid_token"
    public static let insufficientAuthorization = "insufficient_authorization"
    public static let invalidGrant = "invalid_grant"
    // SDK-local
    public static let networkError = "network_error"
    public static let invalidResponse = "invalid_response"
    public static let metadataUnavailable = "metadata_unavailable"
    public static let unsupportedChallenge = "unsupported_challenge"
    public static let flowState = "flow_state"
    public static let passkeyCancelled = "passkey_cancelled"
    public static let passkeyFailed = "passkey_failed"
    public static let passkeyUnavailable = "passkey_unavailable"
    public static let rpIdMismatch = "rp_id_mismatch"
    public static let credentialsNotFound = "credentials_not_found"
    public static let reauthenticationRequired = "reauthentication_required"
    public static let keychainError = "keychain_error"
    /// An access-controlled Keychain item needed user authentication that was cancelled or failed.
    public static let keychainAuthenticationFailed = "keychain_authentication_failed"
    public static let dpopKeyError = "dpop_key_error"
    /// `WebFallback`: the user closed the browser (not a flow failure, the app may retry).
    public static let webFallbackCancelled = "web_fallback_cancelled"
    public static let webFallbackFailed = "web_fallback_failed"
  }

  public let code: String
  public let statusCode: Int?
  public let errorDescription: String?
  /// A still-valid `auth_session` returned with the error (spec/03 §3.5), if any.
  public let authSession: String?
  /// Raw JSON body of the error response, when there was one.
  public let details: JSONValue?
  public let isNetworkError: Bool
  /// `true` for transient conditions (network, `slow_down`, `server_error`).
  public let isRetryable: Bool
  /// `Retry-After` in seconds for `slow_down`.
  public let retryAfter: TimeInterval?
  public let underlying: (any Error)?

  public init(
    code: String,
    statusCode: Int? = nil,
    description: String? = nil,
    authSession: String? = nil,
    details: JSONValue? = nil,
    isNetworkError: Bool = false,
    isRetryable: Bool = false,
    retryAfter: TimeInterval? = nil,
    underlying: (any Error)? = nil
  ) {
    self.code = code
    self.statusCode = statusCode
    self.errorDescription = description
    self.authSession = authSession
    self.details = details
    self.isNetworkError = isNetworkError
    self.isRetryable = isRetryable
    self.retryAfter = retryAfter
    self.underlying = underlying
  }

  public var authSessionStillValid: Bool { authSession != nil }

  /// `max_age` from a §6 `insufficient_authorization` body: the freshness a step-up must satisfy.
  public var maxAge: Int? { details?["max_age"]?.intValue }

  public var description: String {
    var parts = ["NativeAuthError(\(code)"]
    if let statusCode { parts.append("http=\(statusCode)") }
    if let errorDescription { parts.append("\"\(errorDescription)\"") }
    return parts.joined(separator: " ") + ")"
  }

  static func network(_ error: any Error) -> NativeAuthError {
    NativeAuthError(
      code: Code.networkError,
      description: (error as? URLError)?.localizedDescription ?? String(describing: error),
      isNetworkError: true,
      isRetryable: true,
      underlying: error)
  }

  /// Maps a JSON error body from any endpoint to an error, keeping the server's `error` code.
  public static func from(response: HTTPResponse, fallbackCode: String = Code.invalidResponse) -> NativeAuthError {
    let json = response.json
    let code = json?["error"]?.stringValue ?? fallbackCode
    let retryAfter = response.header("Retry-After").flatMap(TimeInterval.init)
    return NativeAuthError(
      code: code,
      statusCode: response.statusCode,
      description: json?["error_description"]?.stringValue
        ?? (json == nil ? "HTTP \(response.statusCode) without a JSON body" : nil),
      authSession: json?["auth_session"]?.stringValue,
      details: json,
      isRetryable: code == Code.slowDown || code == Code.serverError || response.statusCode >= 500,
      retryAfter: retryAfter)
  }
}

// `underlying` holds an arbitrary error; everything else is immutable value data.
extension NativeAuthError: @unchecked Sendable {}
