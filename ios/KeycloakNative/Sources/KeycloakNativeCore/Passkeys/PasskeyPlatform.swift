import AuthenticationServices
import Foundation

/// The platform half of the passkey bridge (spec/05 §3.2): produce an assertion or an attestation
/// from the server's params. Production uses `ASAuthorizationPasskeyPlatform`; tests inject a mock.
public protocol PasskeyPlatform: Sendable {
  func assert(_ params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Bool) async throws -> PasskeyAssertion
  func register(_ params: PasskeyRegistrationParams) async throws -> PasskeyAttestation
}

/// `ASAuthorizationPlatformPublicKeyCredentialProvider` behind `ASAuthorizationController`.
/// Cancellation becomes `passkey_cancelled` (never a flow failure); everything else `passkey_failed`.
public final class ASAuthorizationPasskeyPlatform: PasskeyPlatform {
  private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?

  public init(anchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil) {
    self.anchor = anchor
  }

  public func assert(_ params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Bool) async throws -> PasskeyAssertion {
    guard let challenge = params.challengeData else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "passkey challenge is not base64url")
    }
    let allowed = params.allowCredentials.compactMap(\.idData)
    let userVerification = params.userVerification
    let rpId = params.rpId
    let result = try await AuthorizationBridge(anchor: anchor).perform(
      options: preferImmediatelyAvailableCredentials ? [.preferImmediatelyAvailableCredentials] : []
    ) {
      let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
      let request = provider.createCredentialAssertionRequest(challenge: challenge)
      request.allowedCredentials = allowed.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
      request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: userVerification)
      return request
    }
    guard case .assertion(let assertion) = result else {
      throw NativeAuthError(code: NativeAuthError.Code.passkeyFailed, description: "Unexpected credential type for an assertion")
    }
    return assertion
  }

  public func register(_ params: PasskeyRegistrationParams) async throws -> PasskeyAttestation {
    guard let challenge = params.challengeData, let userId = params.user.idData else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "passkey_registration challenge/user id is not base64url")
    }
    let name = params.user.name
    let userVerification = params.userVerification
    let attestation = params.attestation
    let rpId = params.rp.id
    let excluded = params.excludeCredentials.compactMap(Base64URL.decode)
    let result = try await AuthorizationBridge(anchor: anchor).perform(options: []) {
      let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
      let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: name, userID: userId)
      request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: userVerification)
      request.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKind(rawValue: attestation)
      if #available(iOS 17.4, macOS 14.4, *) {
        request.excludedCredentials = excluded.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
      }
      return request
    }
    guard case .registration(let attestation) = result else {
      throw NativeAuthError(code: NativeAuthError.Code.passkeyFailed, description: "Unexpected credential type for a registration")
    }
    return attestation
  }
}

enum PasskeyPlatformResult: Sendable {
  case assertion(PasskeyAssertion)
  case registration(PasskeyAttestation)
  case password(SavedPassword)
}

/// One `ASAuthorizationController` ceremony bridged to async/await. The delegate converts the
/// credential into a `Sendable` value on whatever thread it is called, so no isolation hop is needed.
final class AuthorizationBridge: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding, @unchecked Sendable {
  private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?
  private let lock = NSLock()
  private var continuation: CheckedContinuation<PasskeyPlatformResult, any Error>?
  private var controller: ASAuthorizationController?

  init(anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?) {
    self.anchor = anchor
  }

  func perform(
    options: ASAuthorizationController.RequestOptions,
    makeRequest: @escaping @MainActor @Sendable () -> ASAuthorizationRequest
  ) async throws -> PasskeyPlatformResult {
    try await withCheckedThrowingContinuation { continuation in
      lock.withLock { self.continuation = continuation }
      Task { @MainActor in
        let controller = ASAuthorizationController(authorizationRequests: [makeRequest()])
        controller.delegate = self
        controller.presentationContextProvider = self
        self.lock.withLock { self.controller = controller }
        controller.performRequests(options: options)
      }
    }
  }

  private func finish(_ result: Result<PasskeyPlatformResult, any Error>) {
    let continuation = lock.withLock { () -> CheckedContinuation<PasskeyPlatformResult, any Error>? in
      let c = self.continuation
      self.continuation = nil
      self.controller = nil
      return c
    }
    continuation?.resume(with: result)
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    switch authorization.credential {
    case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
      finish(.success(.assertion(PasskeyAssertion(
        credentialId: credential.credentialID,
        clientDataJSON: credential.rawClientDataJSON,
        authenticatorData: credential.rawAuthenticatorData,
        signature: credential.signature,
        userHandle: credential.userID.isEmpty ? nil : credential.userID))))
    case let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration:
      guard let attestationObject = credential.rawAttestationObject else {
        finish(.failure(NativeAuthError(code: NativeAuthError.Code.passkeyFailed, description: "Registration returned no attestation object")))
        return
      }
      finish(.success(.registration(PasskeyAttestation(
        credentialId: credential.credentialID,
        clientDataJSON: credential.rawClientDataJSON,
        attestationObject: attestationObject,
        transports: ["internal", "hybrid"]))))
    case let credential as ASPasswordCredential:
      finish(.success(.password(SavedPassword(username: credential.user, password: credential.password))))
    default:
      finish(.failure(NativeAuthError(code: NativeAuthError.Code.passkeyFailed, description: "Unsupported credential \(type(of: authorization.credential))")))
    }
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
    finish(.failure(AuthorizationBridge.map(error)))
  }

  func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
    MainActor.assumeIsolated {
      if let anchor { return anchor() }
      return AuthorizationBridge.defaultAnchor()
    }
  }

  @MainActor
  static func defaultAnchor() -> ASPresentationAnchor {
    #if canImport(UIKit)
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    let windows = scenes.sorted { $0.activationState.rawValue < $1.activationState.rawValue }.flatMap(\.windows)
    return windows.first(where: \.isKeyWindow) ?? windows.first ?? ASPresentationAnchor()
    #elseif canImport(AppKit)
    return NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first ?? ASPresentationAnchor()
    #else
    return ASPresentationAnchor()
    #endif
  }

  nonisolated static func map(_ error: any Error) -> NativeAuthError {
    if let error = error as? NativeAuthError { return error }
    let asError = error as? ASAuthorizationError
    switch asError?.code {
    case .canceled:
      return NativeAuthError(code: NativeAuthError.Code.passkeyCancelled, description: "The user cancelled the passkey prompt", underlying: error)
    case .notInteractive:
      return NativeAuthError(code: NativeAuthError.Code.passkeyUnavailable, description: "Passkey prompt cannot be shown right now", underlying: error)
    default:
      return NativeAuthError(code: NativeAuthError.Code.passkeyFailed, description: error.localizedDescription, underlying: error)
    }
  }
}
