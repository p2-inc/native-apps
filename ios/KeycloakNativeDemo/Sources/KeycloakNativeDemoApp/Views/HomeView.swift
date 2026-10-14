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
            .accessibilityIdentifier("homeTokenType")
          LabeledContent("auth_session", value: credentials.authSession == nil ? "absent" : "stored (post-login; used by step-up)")
        }
        Section("S11 · Register a passkey after login") {
          TextField("Label", text: $model.passkeyLabel)
          Button("Register passkey") { Task { await model.registerPasskey() } }.disabled(model.isBusy)
          ForEach(model.registeredPasskeys, id: \.credentialId) { passkey in
            LabeledContent(passkey.label ?? "passkey", value: String(passkey.credentialId.prefix(12)) + "…").font(.footnote)
          }
          Text("Within 300 s of authenticating; later the server answers 403 insufficient_authorization with an auth_session and max_age, and the app steps up on the Login tab before retrying.")
            .font(.footnote).foregroundStyle(.secondary)
        }
        Section("S6 · Step-up: protected action") {
          Button("Transfer (GET /transfer, needs acr 2)") { Task { await model.transfer() } }.disabled(model.isBusy)
            .accessibilityIdentifier("transfer")
          if let result = model.resourceResult { Text(result).font(.caption.monospaced()).accessibilityIdentifier("resourceResult") }
          Text("The demo API at \(model.config.resourceServer.absoluteString) validates the token (JWKS, DPoP) and answers 401 insufficient_user_authentication below acr 2; the app then steps up with the stored auth_session and the Login tab shows the remaining factor.")
            .font(.footnote).foregroundStyle(.secondary)
        }
        Section("Tokens") {
          Button("Refresh tokens") { Task { await model.refreshTokens() } }.disabled(model.isBusy)
          Button("End session on the server (S8)") { Task { await model.endSessionOnServer() } }.disabled(model.isBusy)
            .accessibilityIdentifier("endSession")
          Button("Log out", role: .destructive) { Task { await model.logout() } }.disabled(model.isBusy)
        }
      } else {
        Section { Text("Not signed in. Use the Login tab.").accessibilityIdentifier("notSignedIn") }
      }
      Section { StatusBar() }
    }
    .navigationTitle("Home")
  }

  private func claim(_ name: String, _ claims: JSONValue?) -> some View {
    LabeledContent(name, value: claims?[name]?.stringValue ?? claims?[name].map { $0.serialized() } ?? "—")
  }
}
