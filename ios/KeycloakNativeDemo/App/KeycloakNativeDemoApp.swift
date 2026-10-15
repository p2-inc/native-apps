import KeycloakNativeDemoApp
import SwiftUI

@main
struct KeycloakNativeDemoApp: App {
  @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  private let model = DemoModel(config: DemoConfig.load())

  var body: some Scene {
    WindowGroup {
      RootView(model: model, enableNotifications: { await AppDelegate.enableNotifications() })
        .onAppear { delegate.model = model }
    }
  }
}
