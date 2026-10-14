import AuthenticationServices
import Foundation

/// The platform half of the browser fallback (spec/03 §3.4): open `url` in the system browser and
/// hand back the callback URL. Production: `ASWebAuthenticationSessionPresenter`; tests inject a mock.
public protocol WebAuthenticationPresenter: Sendable {
  func authenticate(url: URL, callbackScheme: String) async throws -> URL
}

/// `ASWebAuthenticationSession` bridged to async/await. Cancellation (`canceledLogin`) becomes
/// `web_fallback_cancelled`; other failures `web_fallback_failed`.
public final class ASWebAuthenticationSessionPresenter: NSObject, WebAuthenticationPresenter, ASWebAuthenticationPresentationContextProviding, @unchecked Sendable {
  private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?
  private let prefersEphemeralSession: Bool
  private let lock = NSLock()
  private var sessions: [ObjectIdentifier: ASWebAuthenticationSession] = [:]

  public init(anchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil, prefersEphemeralSession: Bool = false) {
    self.anchor = anchor
    self.prefersEphemeralSession = prefersEphemeralSession
  }

  public func authenticate(url: URL, callbackScheme: String) async throws -> URL {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, any Error>) in
      Task { @MainActor in
        let box = ContinuationBox(continuation)
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { callback, error in
          if let callback {
            box.resume(.success(callback))
          } else {
            box.resume(.failure(ASWebAuthenticationSessionPresenter.map(error)))
          }
        }
        session.prefersEphemeralWebBrowserSession = self.prefersEphemeralSession
        session.presentationContextProvider = self
        self.lock.withLock { self.sessions[ObjectIdentifier(session)] = session }
        if !session.start() {
          self.lock.withLock { _ = self.sessions.removeValue(forKey: ObjectIdentifier(session)) }
          box.resume(.failure(NativeAuthError(code: NativeAuthError.Code.webFallbackFailed, description: "The browser session could not be started")))
        }
      }
    }
  }

  public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    lock.withLock { _ = sessions.removeValue(forKey: ObjectIdentifier(session)) }
    return MainActor.assumeIsolated {
      if let anchor { return anchor() }
      return AuthorizationBridge.defaultAnchor()
    }
  }

  nonisolated static func map(_ error: (any Error)?) -> NativeAuthError {
    guard let error else {
      return NativeAuthError(code: NativeAuthError.Code.webFallbackFailed, description: "The browser session ended without a callback")
    }
    if let asError = error as? ASWebAuthenticationSessionError, asError.code == .canceledLogin {
      return NativeAuthError(code: NativeAuthError.Code.webFallbackCancelled, description: "The user closed the browser", underlying: error)
    }
    return NativeAuthError(code: NativeAuthError.Code.webFallbackFailed, description: error.localizedDescription, underlying: error)
  }

  /// Resumes a continuation at most once, whichever callback fires.
  private final class ContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<URL, any Error>?
    init(_ continuation: CheckedContinuation<URL, any Error>) { self.continuation = continuation }
    func resume(_ result: Result<URL, any Error>) {
      let c = lock.withLock { () -> CheckedContinuation<URL, any Error>? in
        let c = continuation
        continuation = nil
        return c
      }
      c?.resume(with: result)
    }
  }
}

/// Completes a `redirect_to_web` step (spec/03 §3.4, spec/05 §2.2): opens the realm's authorization
/// endpoint with `client_id` + `request_uri` in the system browser, checks `state` on the callback,
/// and exchanges the code with the native flow's PKCE verifier and the `redirect_uri` of the request.
public struct WebFallback: Sendable {
  private let clientId: String
  private let issuer: URL
  private let metadata: MetadataClient
  private let presenter: any WebAuthenticationPresenter
  private let tokens: Tokens
  private let logger: any NativeAuthLogger

  init(clientId: String, issuer: URL, metadata: MetadataClient, presenter: any WebAuthenticationPresenter, tokens: Tokens, logger: any NativeAuthLogger) {
    self.clientId = clientId
    self.issuer = issuer
    self.metadata = metadata
    self.presenter = presenter
    self.tokens = tokens
    self.logger = logger
  }

  /// The URL the browser is sent to (exposed for apps that want to open it themselves).
  public func authorizationURL(for request: RedirectToWebRequest) async throws -> URL {
    let document = try await metadata.metadata()
    let endpoint = document.authorizationEndpoint ?? issuer.appending(path: "protocol/openid-connect/auth")
    guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Malformed authorization endpoint")
    }
    components.queryItems = [URLQueryItem(name: "client_id", value: clientId), URLQueryItem(name: "request_uri", value: request.requestUri)]
    guard let url = components.url else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Cannot build the authorization URL")
    }
    return url
  }

  /// Runs the browser and exchanges the code. `flow` is the flow that produced the step (its PKCE
  /// verifier signs the exchange). Errors: `web_fallback_cancelled`, `web_fallback_failed`,
  /// `invalid_response` (state mismatch / no code), the server's `error` from the callback, and
  /// token endpoint errors.
  public func complete(_ request: RedirectToWebRequest, flow: NativeLoginFlow) async throws -> Credentials {
    try await complete(request, codeVerifier: flow.pkce.verifier)
  }

  public func complete(_ request: RedirectToWebRequest, codeVerifier: String) async throws -> Credentials {
    guard let scheme = request.callbackScheme else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "redirect_uri '\(request.redirectUri)' has no scheme", details: request.raw)
    }
    let url = try await authorizationURL(for: request)
    logger.log(.info, "Opening the browser for \(request.reason ?? "redirect_to_web")")
    let callback = try await presenter.authenticate(url: url, callbackScheme: scheme)
    let code = try WebFallback.code(from: callback, expectedState: request.state)
    return try await tokens.exchange(code: code, codeVerifier: codeVerifier, redirectUri: request.redirectUri)
  }

  /// Extracts `code` from the callback, enforcing `state` and surfacing an OAuth `error`.
  static func code(from callback: URL, expectedState: String?) throws -> String {
    let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
    func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
    if let error = value("error") {
      throw NativeAuthError(code: error, description: value("error_description") ?? "The browser flow failed")
    }
    if let expectedState, value("state") != expectedState {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "state on the callback does not match the redirect_to_web request")
    }
    guard let code = value("code"), !code.isEmpty else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Callback without a code")
    }
    return code
  }
}
