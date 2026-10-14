import Foundation
@testable import KeycloakNativeCore

/// Plays the system browser for `WebFallback`: records the URL it was asked to open and answers
/// with a scripted callback URL (or throws).
final class MockWebPresenter: WebAuthenticationPresenter, @unchecked Sendable {
  private let lock = NSLock()
  private var _opened: [(url: URL, scheme: String)] = []
  var callback: @Sendable (URL) throws -> URL

  init(callback: @escaping @Sendable (URL) throws -> URL) {
    self.callback = callback
  }

  var opened: [(url: URL, scheme: String)] { lock.withLock { _opened } }

  func authenticate(url: URL, callbackScheme: String) async throws -> URL {
    lock.withLock { _opened.append((url, callbackScheme)) }
    return try callback(url)
  }
}
