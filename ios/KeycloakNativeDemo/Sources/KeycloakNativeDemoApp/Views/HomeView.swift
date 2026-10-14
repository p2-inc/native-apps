import KeycloakNativeCore
import SwiftUI

struct HomeView: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    @Bindable var model = model
    Form {
      if let credentials = model.credentials {
        Section("Access token claims (unverified, display only)") {
          claim("preferred_username", credentials.accessTokenClaims)
          claim("acr", credentials.accessTokenClaims)
          claim("azp", credentials.accessTokenClaims)
          claim("sid", credentials.accessTokenClaims)
          LabeledContent("Expires", value: credentials.expiresAt.formatted(date: .omitted, time: .standard))
          LabeledContent("Token type", value: credentials.tokenType + (credentials.isDPoPBound ? " (bound to this device's DPoP key)" : ""))
          LabeledContent("auth_session", value: credentials.authSession == nil ? "absent" : "stored (post-login, for step-up in Phase 2)")
        }
        Section("S11 · Register a passkey after login") {
          TextField("Label", text: $model.passkeyLabel)
          Button("Register passkey") { Task { await model.registerPasskey() } }.disabled(model.isBusy)
          ForEach(model.registeredPasskeys, id: \.credentialId) { passkey in
            LabeledContent(passkey.label ?? "passkey", value: String(passkey.credentialId.prefix(12)) + "…").font(.footnote)
          }
          Text("Within 300 s of authenticating; later the server answers 403 insufficient_authorization and a new login is needed (step-up is Phase 2).")
            .font(.footnote).foregroundStyle(.secondary)
        }
        Section("Tokens") {
          Button("Refresh tokens") { Task { await model.refreshTokens() } }.disabled(model.isBusy)
          Button("Log out", role: .destructive) { Task { await model.logout() } }.disabled(model.isBusy)
        }
      } else {
        Section { Text("Not signed in. Use the Login tab.") }
      }
      Section { StatusBar() }
    }
    .navigationTitle("Home")
  }

  private func claim(_ name: String, _ claims: JSONValue?) -> some View {
    LabeledContent(name, value: claims?[name]?.stringValue ?? claims?[name].map { $0.serialized() } ?? "—")
  }
}
