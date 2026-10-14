import KeycloakNativeCore
import SwiftUI

public struct RootView: View {
  // A plain reference: DemoModel is @Observable, so views observe it through the environment.
  // (@State is a macro in recent SDKs and needs Xcode's plugin; a stored reference works everywhere.)
  private let model: DemoModel

  public init(model: DemoModel) {
    self.model = model
  }

  public var body: some View {
    TabView {
      NavigationStack { ScenariosView() }.tabItem { Label("Scenarios", systemImage: "list.bullet") }
      NavigationStack { LoginView() }.tabItem { Label("Login", systemImage: "person.badge.key") }
      NavigationStack { HomeView() }.tabItem { Label("Home", systemImage: "house") }
      NavigationStack { DiagnosticsView() }.tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
    }
    .environment(model)
  }
}

struct StatusBar: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(model.status).font(.footnote).foregroundStyle(model.lastError == nil ? Color.secondary : Color.red)
      if model.isBusy { ProgressView().controlSize(.small) }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
