import Foundation
@testable import KeycloakNativeCore

/// Scripted `PasskeyPlatform`: returns queued assertions/attestations (typically the ones a
/// transcript recorded) or a queued error, and records the params it was asked for.
final class MockPasskeyPlatform: PasskeyPlatform, @unchecked Sendable {
  private let lock = NSLock()
  private var assertions: [PasskeyAssertion] = []
  private var attestations: [PasskeyAttestation] = []
  private var nextError: NativeAuthError?
  private(set) var assertParams: [PasskeyAssertionParams] = []
  private(set) var registerParams: [PasskeyRegistrationParams] = []
  private(set) var preferImmediatelyAvailable: [Bool] = []

  init(assertions: [PasskeyAssertion] = [], attestations: [PasskeyAttestation] = []) {
    self.assertions = assertions
    self.attestations = attestations
  }

  func enqueue(_ assertion: PasskeyAssertion) { lock.withLock { assertions.append(assertion) } }
  func enqueue(_ attestation: PasskeyAttestation) { lock.withLock { attestations.append(attestation) } }
  func fail(with error: NativeAuthError) { lock.withLock { nextError = error } }

  func assert(_ params: PasskeyAssertionParams, preferImmediatelyAvailableCredentials: Bool) async throws -> PasskeyAssertion {
    try lock.withLock {
      assertParams.append(params)
      preferImmediatelyAvailable.append(preferImmediatelyAvailableCredentials)
      if let error = nextError { nextError = nil; throw error }
      guard !assertions.isEmpty else { throw NativeAuthError(code: "mock_empty", description: "no assertion queued") }
      return assertions.removeFirst()
    }
  }

  func register(_ params: PasskeyRegistrationParams) async throws -> PasskeyAttestation {
    try lock.withLock {
      registerParams.append(params)
      if let error = nextError { nextError = nil; throw error }
      guard !attestations.isEmpty else { throw NativeAuthError(code: "mock_empty", description: "no attestation queued") }
      return attestations.removeFirst()
    }
  }
}
