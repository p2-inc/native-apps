import Foundation

/// Keychain-backed credential storage with serialised refresh (spec/05 §2.2, §6).
public actor CredentialsManager {
  private let store: any SecureStore
  private let key: String
  private let tokens: Tokens
  private let logger: any NativeAuthLogger
  private let leeway: TimeInterval
  private var refreshTask: Task<Credentials, any Error>?

  init(store: any SecureStore, key: String, tokens: Tokens, logger: any NativeAuthLogger, leeway: TimeInterval = 30) {
    self.store = store
    self.key = key
    self.tokens = tokens
    self.logger = logger
    self.leeway = leeway
  }

  public func store(_ credentials: Credentials) throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .secondsSince1970
    try store.set(try encoder.encode(credentials), forKey: key)
  }

  /// The stored credentials as they are, possibly expired; `nil` when none.
  public func stored() throws -> Credentials? {
    guard let data = try store.data(forKey: key) else { return nil }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .secondsSince1970
    do {
      return try decoder.decode(Credentials.self, from: data)
    } catch {
      logger.log(.warning, "Stored credentials are unreadable; clearing them")
      try? store.removeData(forKey: key)
      return nil
    }
  }

  public func hasValid(minTTL: TimeInterval = 0) throws -> Bool {
    guard let credentials = try stored() else { return false }
    return !credentials.isExpired(leeway: leeway + minTTL)
  }

  /// The stored post-login `auth_session`, kept for step-up (Phase 2).
  public func authSession() throws -> String? {
    try stored()?.authSession
  }

  /// Valid credentials, refreshing (once, even under concurrent callers) when the access token is
  /// within `leeway + minTTL` of expiry. Throws `credentials_not_found` when nothing is stored and
  /// `reauthentication_required` (with `authSession` when the server returned one) when the refresh
  /// is refused.
  public func credentials(minTTL: TimeInterval = 0) async throws -> Credentials {
    guard let current = try stored() else {
      throw NativeAuthError(code: NativeAuthError.Code.credentialsNotFound, description: "No stored credentials")
    }
    if !current.isExpired(leeway: leeway + minTTL) {
      return current
    }
    if let refreshTask {
      return try await refreshTask.value
    }
    let task = Task<Credentials, any Error> { [tokens] in
      try await tokens.refresh(current)
    }
    refreshTask = task
    defer { refreshTask = nil }
    do {
      let refreshed = try await task.value
      try store(refreshed)
      return refreshed
    } catch let error as NativeAuthError {
      switch error.code {
      case NativeAuthError.Code.invalidGrant:
        // The session behind the refresh token is gone (logout, expiry, revocation).
        try? clear()
        throw NativeAuthError(code: NativeAuthError.Code.reauthenticationRequired, statusCode: error.statusCode, description: error.errorDescription, details: error.details, underlying: error)
      case NativeAuthError.Code.insufficientAuthorization:
        // spec/03 §5: the returned auth_session feeds Authentication.continueAfterTokenChallenge.
        throw NativeAuthError(code: NativeAuthError.Code.reauthenticationRequired, statusCode: error.statusCode, description: error.errorDescription, authSession: error.authSession, details: error.details, underlying: error)
      default:
        throw error
      }
    }
  }

  public func clear() throws {
    try store.removeData(forKey: key)
  }

  /// Best-effort server-side logout (RP-initiated logout with the refresh token) followed by
  /// `clear()`. Network failures are logged, not thrown: the local state is cleared regardless.
  public func logout() async {
    if let credentials = try? stored(), let refreshToken = credentials.refreshToken {
      do {
        try await tokens.logout(refreshToken: refreshToken)
      } catch {
        logger.log(.warning, "Server logout failed: \(error)")
      }
    }
    try? clear()
  }
}
