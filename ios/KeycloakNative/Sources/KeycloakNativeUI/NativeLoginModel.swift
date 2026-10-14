import KeycloakNativeCore
import Observation
import SwiftUI

/// State behind `NativeLoginView`: drives the flow, picks the screen, runs platform ceremonies.
@MainActor
@Observable
final class NativeLoginModel {
  enum Phase {
    case starting
    case challenge([Challenge], FlowContext, selected: Challenge)
    case redirectToWeb(RedirectToWebRequest)
    case finished
  }

  private(set) var phase: Phase = .starting
  private(set) var isSubmitting = false
  /// A user-facing error that is not attached to a challenge (network, passkey failure…).
  private(set) var message: String?

  private let kc: KeycloakNative
  private let flow: NativeLoginFlow
  private let autoSelectPasskey: Bool
  private let onResult: @MainActor (NativeLoginResult) -> Void
  private var started = false
  private var done = false

  init(kc: KeycloakNative, flow: NativeLoginFlow, autoSelectPasskey: Bool, onResult: @escaping @MainActor (NativeLoginResult) -> Void) {
    self.kc = kc
    self.flow = flow
    self.autoSelectPasskey = autoSelectPasskey
    self.onResult = onResult
  }

  func startIfNeeded() async {
    guard !started else { return }
    started = true
    await perform { try await self.flow.start() }
  }

  func submit(_ answer: ChallengeAnswer, to challenge: Challenge) {
    Task { await perform { try await self.flow.respond(answer, to: challenge) } }
  }

  func usePasskey(_ challenge: Challenge, preferImmediatelyAvailable: Bool) {
    guard let params = challenge.passkeyParams else { return }
    Task {
      await perform {
        let assertion = try await self.kc.passkeys().assert(params, preferImmediatelyAvailableCredentials: preferImmediatelyAvailable)
        return try await self.flow.respond(.passkey(assertion), to: challenge)
      }
    }
  }

  func registerPasskey(_ challenge: Challenge, label: String?) {
    guard let params = challenge.passkeyRegistrationParams else { return }
    Task {
      await perform {
        let attestation = try await self.kc.passkeys().register(params)
        return try await self.flow.respond(.passkeyRegistration(attestation, label: label), to: challenge)
      }
    }
  }

  func openBrowser() {
    guard case .redirectToWeb(let request) = phase else { return }
    Task {
      await perform {
        let credentials = try await self.kc.webFallback().complete(request, flow: self.flow)
        return .authorized(credentials)
      }
    }
  }

  func select(_ challenge: Challenge) {
    guard case .challenge(let challenges, let context, _) = phase, challenges.contains(where: { $0.id == challenge.id }) else { return }
    message = nil
    phase = .challenge(challenges, context, selected: challenge)
  }

  func cancel() {
    guard !done else { return }
    done = true
    Task {
      await flow.cancel()
      phase = .finished
      onResult(.cancelled)
    }
  }

  // MARK: -

  private func perform(_ body: @escaping () async throws -> FlowStep) async {
    guard !done else { return }
    isSubmitting = true
    message = nil
    defer { isSubmitting = false }
    do {
      apply(try await body())
    } catch let error as NativeAuthError {
      switch error.code {
      case NativeAuthError.Code.passkeyCancelled, NativeAuthError.Code.webFallbackCancelled:
        // Not a flow failure: the set stays, the user may pick another way (spec/12 D4).
        message = nil
      case NativeAuthError.Code.passkeyFailed, NativeAuthError.Code.passkeyUnavailable, NativeAuthError.Code.rpIdMismatch,
        NativeAuthError.Code.networkError, NativeAuthError.Code.webFallbackFailed:
        message = error.errorDescription ?? error.code
      default:
        // Terminal (invalid_session, access_denied, …): the flow is over.
        done = true
        phase = .finished
        onResult(.failed(error))
      }
    } catch {
      message = String(describing: error)
    }
  }

  private func apply(_ step: FlowStep) {
    switch step {
    case .challenges(let challenges, let context):
      let selected = pick(from: challenges, previous: currentSelection)
      phase = .challenge(challenges, context, selected: selected)
      if autoSelectPasskey, selected.type == .passkey, selected.error == nil, !isStepUpAfterPasskeyFailure(selected) {
        usePasskey(selected, preferImmediatelyAvailable: false)
      }
    case .authorized(let credentials):
      done = true
      phase = .finished
      onResult(.authorized(credentials))
    case .redirectToWeb(let request):
      phase = .redirectToWeb(request)
    }
  }

  private var currentSelection: Challenge? {
    if case .challenge(_, _, let selected) = phase { return selected }
    return nil
  }

  /// The entry to show: the one that just failed (it carries `error`), else the previously shown
  /// type when it is still offered, else the first supported entry (server order = flow order).
  private func pick(from challenges: [Challenge], previous: Challenge?) -> Challenge {
    if let failed = challenges.first(where: { $0.error != nil && $0.type.isSupported }) { return failed }
    if let previous, let same = challenges.first(where: { $0.type == previous.type && $0.type.isSupported }) { return same }
    return challenges.first(where: { $0.type.isSupported }) ?? challenges[0]
  }

  private func isStepUpAfterPasskeyFailure(_ challenge: Challenge) -> Bool { false }
}
