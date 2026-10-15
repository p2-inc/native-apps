import KeycloakNativeCore
import SwiftUI

public struct RootView: View {
  // A plain reference: DemoModel is @Observable, so views observe it through the environment.
  // (@State is a macro in recent SDKs and needs Xcode's plugin; a stored reference works everywhere.)
  private let model: DemoModel

  /// - Parameter enableNotifications: asks for notification permission and registers for APNs
  ///   (the iOS app target's `AppDelegate`); `nil` on platforms without it.
  public init(model: DemoModel, enableNotifications: (@MainActor () async -> Void)? = nil) {
    self.model = model
    model.enableNotifications = enableNotifications
  }

  public var body: some View {
    TabView {
      NavigationStack { ScenariosView() }.tabItem { Label("Scenarios", systemImage: "list.bullet") }
      NavigationStack { LoginView() }.tabItem { Label("Login", systemImage: "person.badge.key") }
      NavigationStack { HomeView() }.tabItem { Label("Home", systemImage: "house") }
      NavigationStack { DiagnosticsView() }.tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
    }
    .environment(model)
    .task { await model.restoreSession() }
  }
}

struct StatusBar: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(model.status).font(.footnote).foregroundStyle(model.lastError == nil ? Color.secondary : Color.red)
        .accessibilityIdentifier("status")
      if model.isBusy { ProgressView().controlSize(.small) }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
