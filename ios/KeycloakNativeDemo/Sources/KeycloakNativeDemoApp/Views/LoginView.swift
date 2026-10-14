import KeycloakNativeCore
import SwiftUI

/// Hand-rolled rendering of `FlowStep` from Core (spec/05 §4 option 3): one section per offered
/// challenge, in the server's order. `KeycloakNativeUI` default screens arrive in Phase 2.
struct LoginView: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    @Bindable var model = model
    Form {
      Section {
        Text(model.scenario?.title ?? "No scenario selected (defaults to client \(model.config.clientId))").font(.headline)
        HStack {
          Button(model.flow == nil ? "Start login" : "Restart") { Task { await model.startLogin() } }
            .disabled(model.isBusy)
          if model.flow != nil {
            Button("Cancel", role: .destructive) { Task { await model.cancel() } }
          }
        }
        StatusBar()
      }

      if case .challenges(let challenges, let context) = model.step {
        if let username = context.username {
          Section("Context") {
            LabeledContent("User", value: context.displayName.map { "\($0) (\(username))" } ?? username)
            if let client = context.clientName { LabeledContent("Client", value: client) }
          }
        }
        ForEach(challenges) { challenge in
          Section {
            challengeView(challenge)
          } header: {
            Text("\(challenge.type.wire)\(challenge.required ? "" : " · alternative")")
          } footer: {
            if let error = challenge.error {
              Text("\(error.code): \(error.message ?? "")").foregroundStyle(.red)
            } else if let label = challenge.label {
              Text(label)
            }
          }
        }
      } else if case .authorized(let credentials) = model.step {
        Section("Signed in") {
          LabeledContent("User", value: credentials.accessTokenClaims?["preferred_username"]?.stringValue ?? "?")
          LabeledContent("Token type", value: credentials.tokenType)
          Text("See Home for claims, passkey registration and logout.").font(.footnote)
        }
      }
    }
    .navigationTitle("Login")
  }

  @ViewBuilder
  private func challengeView(_ challenge: Challenge) -> some View {
    @Bindable var model = model
    switch challenge.type {
    case .username:
      TextField("Username or email", text: $model.username)
        .textContentType(.username)
        .disableAutocorrection(true)
      Button("Continue") { Task { await model.answer(.username(model.username), to: challenge) } }
        .disabled(model.isBusy || model.username.isEmpty)
    case .password:
      SecureField("Password", text: $model.password).textContentType(.password)
      Button("Sign in with password") { Task { await model.answer(.password(model.password), to: challenge) } }
        .disabled(model.isBusy)
    case .totp:
      let params = challenge.totpParams
      TextField("\(params?.digits ?? 6)-digit code", text: $model.totp).textContentType(.oneTimeCode)
      if let credentials = params?.credentials, credentials.count > 1 {
        Picker("Authenticator", selection: $model.totpCredentialId) {
          Text("Default").tag(String?.none)
          ForEach(credentials, id: \.id) { Text($0.label).tag(String?.some($0.id)) }
        }
      }
      Button("Verify code") { Task { await model.answer(.totp(model.totp, credentialId: model.totpCredentialId), to: challenge) } }
        .disabled(model.isBusy || model.totp.isEmpty)
    case .passkey:
      let params = challenge.passkeyParams
      Text(params?.discoverable == true ? "Discoverable: no username needed (rp_id \(params?.rpId ?? "?"))" : "\(params?.allowCredentials.count ?? 0) registered passkey(s), rp_id \(params?.rpId ?? "?")")
        .font(.footnote).foregroundStyle(.secondary)
      Button("Sign in with a passkey") { Task { await model.usePasskey(challenge) } }
        .disabled(model.isBusy)
    case .passkeyRegistration:
      let params = challenge.passkeyRegistrationParams
      Text("The server requires a passkey for \(params?.user.name ?? "?") before finishing (required action \(challenge.id)).")
        .font(.footnote).foregroundStyle(.secondary)
      TextField("Passkey label", text: $model.passkeyLabel)
      Button("Create passkey") { Task { await model.registerPasskeyInFlow(challenge) } }
        .disabled(model.isBusy)
    case .otp, .push, .recoveryCode, .select, .unknown:
      Text("Unsupported challenge type '\(challenge.type.wire)' in this app version: update the app or use the web.")
        .foregroundStyle(.orange)
    }
  }
}
