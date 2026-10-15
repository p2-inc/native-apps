import KeycloakNativeCore
import SwiftUI

/// Outcome of a `NativeLoginView` (spec/05 §4).
public enum NativeLoginResult: Sendable {
  case authorized(Credentials)
  case cancelled
  case failed(NativeAuthError)
}

/// What a challenge screen gets (spec/05 §4): the challenge, the set it belongs to, the flow context
/// and the actions it may trigger. Presenters are plain SwiftUI views built from this.
@MainActor
public struct ChallengePresentationContext {
  public let challenge: Challenge
  public let challenges: [Challenge]
  public let flowContext: FlowContext
  public let isSubmitting: Bool
  /// The step is a step-up / re-authentication (`context.step_up`).
  public var isStepUp: Bool { flowContext.stepUp }
  let model: NativeLoginModel

  public func submit(_ answer: ChallengeAnswer) {
    model.submit(answer, to: challenge)
  }

  /// Runs the platform passkey ceremony for a `passkey` challenge and submits the assertion.
  public func usePasskey(preferImmediatelyAvailableCredentials: Bool = false) {
    model.usePasskey(challenge, preferImmediatelyAvailable: preferImmediatelyAvailableCredentials)
  }

  /// Runs the platform registration for a `passkey_registration` challenge and submits it.
  public func registerPasskey(label: String?) {
    model.registerPasskey(challenge, label: label)
  }

  /// Show another entry of the current set instead.
  public func switchTo(_ other: Challenge) {
    model.select(other)
  }

  public func cancel() {
    model.cancel()
  }

  /// Entries of the set other than this one, in server order.
  public var alternatives: [Challenge] { challenges.filter { $0.id != challenge.id } }
}

/// A replaceable screen for one challenge type (spec/05 §4 `challengePresenter(for:)`).
public typealias ChallengePresenter = @MainActor (ChallengePresentationContext) -> AnyView

/// Theme for the default screens.
public struct NativeLoginTheme: Sendable {
  public var accent: Color
  public var logo: Image?
  public var title: String

  public init(accent: Color = .accentColor, logo: Image? = nil, title: String = "Sign in") {
    self.accent = accent
    self.logo = logo
    self.title = title
  }
}

/// Drives a `NativeLoginFlow` with the default screens: `start()`, one screen per challenge (the
/// first supported entry of each set, with "Try another way" for the rest), passkey ceremonies,
/// the browser fallback, and `onResult` at the end (spec/05 §4 option 1). Any screen can be replaced
/// with `.challengePresenter(for:_:)`, the chooser with `.challengeChooser(_:)`.
public struct NativeLoginView: View {
  @State private var model: NativeLoginModel
  private let theme: NativeLoginTheme
  @Environment(\.challengePresenters) private var presenters
  @Environment(\.challengeChooser) private var chooser
  @Environment(\.nativeLoginStrings) private var strings

  /// - Parameters:
  ///   - kc: the configured SDK (for passkeys and the browser fallback).
  ///   - flow: a flow from `authentication().startLogin(...)` or `stepUp(...)`, not yet started.
  ///   - autoSelectPasskey: when a set contains `passkey`, run the ceremony right away.
  public init(kc: KeycloakNative, flow: NativeLoginFlow, theme: NativeLoginTheme = NativeLoginTheme(), autoSelectPasskey: Bool = false, onResult: @escaping @MainActor (NativeLoginResult) -> Void) {
    _model = State(initialValue: NativeLoginModel(kc: kc, flow: flow, autoSelectPasskey: autoSelectPasskey, onResult: onResult))
    self.theme = theme
  }

  public var body: some View {
    content
      .tint(theme.accent)
      .task { await model.startIfNeeded() }
  }

  @ViewBuilder
  private var content: some View {
    switch model.phase {
    case .starting:
      VStack(spacing: 16) {
        if let logo = theme.logo { logo }
        ProgressView(strings("Contacting the server…"))
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
    case .challenge(let challenges, let context, let selected):
      let presentation = ChallengePresentationContext(challenge: selected, challenges: challenges, flowContext: context, isSubmitting: model.isSubmitting, model: model)
      VStack(spacing: 0) {
        if let logo = theme.logo { logo.padding(.top) }
        screen(for: presentation)
        if let message = model.message {
          Text(message).font(.footnote).foregroundStyle(.red).padding()
        }
        if presentation.alternatives.contains(where: { $0.type.isSupported }) {
          chooser(ChallengeChooserContext(current: selected, alternatives: presentation.alternatives, model: model))
        }
      }
    case .redirectToWeb(let request):
      RedirectToWebScreen(request: request, isSubmitting: model.isSubmitting, message: model.message, open: { model.openBrowser() }, cancel: { model.cancel() })
    case .finished:
      ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
    }
  }

  @ViewBuilder
  private func screen(for presentation: ChallengePresentationContext) -> some View {
    if let custom = presenters[presentation.challenge.type] {
      custom(presentation)
    } else {
      DefaultChallengeScreen(presentation: presentation)
    }
  }
}

/// Input of a chooser (the "Try another way" list).
@MainActor
public struct ChallengeChooserContext {
  public let current: Challenge
  public let alternatives: [Challenge]
  let model: NativeLoginModel

  public func select(_ challenge: Challenge) { model.select(challenge) }
}

public typealias ChallengeChooser = @MainActor (ChallengeChooserContext) -> AnyView

// MARK: - Environment: presenter overrides

struct ChallengePresentersKey: EnvironmentKey {
  static let defaultValue: [ChallengeType: ChallengePresenter] = [:]
}

struct ChallengeChooserKey: EnvironmentKey {
  static let defaultValue: ChallengeChooser = { context in AnyView(DefaultChallengeChooser(context: context)) }
}

extension EnvironmentValues {
  var challengePresenters: [ChallengeType: ChallengePresenter] {
    get { self[ChallengePresentersKey.self] }
    set { self[ChallengePresentersKey.self] = newValue }
  }

  var challengeChooser: ChallengeChooser {
    get { self[ChallengeChooserKey.self] }
    set { self[ChallengeChooserKey.self] = newValue }
  }
}

extension View {
  /// Replaces the default screen for `type` (spec/05 §4 option 2).
  public func challengePresenter<Content: View>(for type: ChallengeType, @ViewBuilder _ content: @escaping @MainActor (ChallengePresentationContext) -> Content) -> some View {
    transformEnvironment(\.challengePresenters) { presenters in
      presenters[type] = { context in AnyView(content(context)) }
    }
  }

  /// Replaces the "Try another way" chooser.
  public func challengeChooser<Content: View>(@ViewBuilder _ content: @escaping @MainActor (ChallengeChooserContext) -> Content) -> some View {
    environment(\.challengeChooser, { context in AnyView(content(context)) })
  }
}
