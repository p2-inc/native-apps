import KeycloakNativeDemoApp
import SwiftUI

@main
struct KeycloakNativeDemoApp: App {
  var body: some Scene {
    WindowGroup {
      RootView(model: DemoModel(config: DemoConfig.load()))
    }
  }
}
