import SwiftUI

/// The Keycloak server the demo talks to: base URL, realm and the demo realm's client IDs. Saved in
/// UserDefaults; saving signs out and rebuilds the SDK instances (`DemoModel.apply`).
struct SettingsView: View {
  @Environment(DemoModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  @State private var serverURL = ""
  @State private var realm = ""
  @State private var clientId = ""
  @State private var passkeyClientId = ""
  @State private var stepUpClientId = ""
  @State private var otpClientId = ""
  @State private var pinClientId = ""
  @State private var resourceServer = ""
  @State private var loaded = false
  @State private var confirmSave = false

  var body: some View {
    Form {
      Section {
        field("Server URL", $serverURL, prompt: "https://idp.example.com", id: "settingsServerURL")
        field("Realm", $realm, prompt: "demo", id: "settingsRealm")
        field("Client ID", $clientId, prompt: "demo-native", id: "settingsClientId")
      } header: {
        Text("Keycloak")
      } footer: {
        if let problem = serverProblem {
          Text(problem).foregroundStyle(.red).accessibilityIdentifier("settingsProblem")
        } else if let issuer = newConfig?.issuer {
          Text("Issuer: \(issuer.absoluteString)")
        }
      }
      Section {
        field("Passkey first", $passkeyClientId, prompt: "demo-native-passkey", id: "settingsPasskeyClientId")
        field("Step-up", $stepUpClientId, prompt: "demo-native-stepup", id: "settingsStepUpClientId")
        field("Email code", $otpClientId, prompt: "demo-native-otp", id: "settingsOtpClientId")
        field("PIN", $pinClientId, prompt: "demo-native-pin", id: "settingsPinClientId")
        field("Step-up API", $resourceServer, prompt: "http://localhost:8091", id: "settingsResourceServer")
      } header: {
        Text("Other demo clients")
      } footer: {
        Text("The scenarios use these clients of the demo realm. Browser fallbacks return to demoapp://auth/callback, which each client must list as a redirect URI.")
      }
      Section {
        Button("Save and sign out") { confirmSave = true }
          .disabled(newConfig == nil || newConfig == model.config || model.isBusy)
          .accessibilityIdentifier("settingsSave")
        Button("Reset to defaults") { fill(from: model.bundledConfig) }
          .disabled(newConfig == model.bundledConfig)
          .accessibilityIdentifier("settingsReset")
      } footer: {
        Text("Defaults come from Config.plist: \(model.bundledConfig.issuer.absoluteString). Plain HTTP works for localhost only; use https for any other host.")
      }
      Section("About") {
        Link(destination: URL(string: "https://phasetwo.io")!) {
          LabeledContent("Made by Phase Two", value: "phasetwo.io")
        }
        Link(destination: URL(string: "https://github.com/p2-inc/native-apps")!) {
          LabeledContent("Source", value: "p2-inc/native-apps")
        }
      }
    }
    .autocorrectionDisabled()
    .plainTextInput()
    .navigationTitle("Server")
    .onAppear {
      if !loaded { fill(from: model.config); loaded = true }
    }
    .confirmationDialog("Switch servers?", isPresented: $confirmSave, titleVisibility: .visible) {
      Button("Save and sign out", role: .destructive) {
        guard let config = newConfig else { return }
        Task {
          await model.apply(config)
          if config == model.bundledConfig { DemoConfig.resetSaved() } else { config.save() }
          dismiss()
        }
      }
    } message: {
      Text("The stored logins and this device's local push enrollment are removed.")
    }
  }

  private var serverProblem: String? {
    if let problem = DemoConfig.problem(withServerURL: serverURL.trimmingCharacters(in: .whitespaces)) { return problem }
    if realm.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter the realm." }
    if [clientId, passkeyClientId, stepUpClientId, otpClientId, pinClientId].contains(where: { $0.trimmingCharacters(in: .whitespaces).isEmpty }) {
      return "Every client ID needs a value."
    }
    if let problem = DemoConfig.problem(withServerURL: resourceServer.trimmingCharacters(in: .whitespaces)) { return "Step-up demo API: \(problem)" }
    return nil
  }

  /// The configuration the fields describe, or `nil` while they are not valid.
  private var newConfig: DemoConfig? {
    guard serverProblem == nil, let issuer = DemoConfig.issuer(serverURL: serverURL, realm: realm),
      let resource = URL(string: resourceServer.trimmingCharacters(in: .whitespaces))
    else { return nil }
    var config = model.config
    config.issuer = issuer
    config.clientId = clientId.trimmingCharacters(in: .whitespaces)
    config.passkeyClientId = passkeyClientId.trimmingCharacters(in: .whitespaces)
    config.stepUpClientId = stepUpClientId.trimmingCharacters(in: .whitespaces)
    config.otpClientId = otpClientId.trimmingCharacters(in: .whitespaces)
    config.pinClientId = pinClientId.trimmingCharacters(in: .whitespaces)
    config.resourceServer = resource
    return config
  }

  private func field(_ label: String, _ text: Binding<String>, prompt: String, id: String) -> some View {
    LabeledContent(label) {
      TextField(label, text: text, prompt: Text(prompt))
        .multilineTextAlignment(.trailing)
        .accessibilityIdentifier(id)
    }
  }

  private func fill(from config: DemoConfig) {
    serverURL = config.serverURL
    realm = config.realm
    clientId = config.clientId
    passkeyClientId = config.passkeyClientId
    stepUpClientId = config.stepUpClientId
    otpClientId = config.otpClientId
    pinClientId = config.pinClientId
    resourceServer = config.resourceServer.absoluteString
  }
}

/// The Phase Two mark and the app's name, at the top of the Scenarios list.
struct BrandHeader: View {
  var body: some View {
    HStack(spacing: 12) {
      // Assets.xcassets/BrandMark of the app target (design/brand/mark.svg).
      Image("BrandMark", bundle: .main)
        .resizable()
        .scaledToFit()
        .frame(height: 22)
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 2) {
        Text("Phase Two").font(.headline)
        Text("Keycloak native login demo").font(.subheadline).foregroundStyle(.secondary)
      }
    }
    .padding(.vertical, 4)
    .accessibilityElement(children: .combine)
  }
}

/// A toolbar button that opens the Settings screen.
struct ServerSettingsButton: View {
  var body: some View {
    NavigationLink {
      SettingsView()
    } label: {
      Label("Server settings", systemImage: "server.rack")
    }
    .accessibilityIdentifier("serverSettings")
  }
}

extension View {
  /// URLs and identifiers: no automatic capitalization (iOS; the package also builds for macOS).
  fileprivate func plainTextInput() -> some View {
    #if os(iOS)
      textInputAutocapitalization(.never).keyboardType(.asciiCapable)
    #else
      self
    #endif
  }
}
