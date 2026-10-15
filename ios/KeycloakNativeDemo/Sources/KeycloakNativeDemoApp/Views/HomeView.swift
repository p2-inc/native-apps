import KeycloakNativeCore
import KeycloakNativePush
import KeycloakNativeUI
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
      // Last on purpose: Form rows are lazy and the older XCUITests read the status right after the
      // token actions; the push tests scroll for what they need.
      Section("S9 · S10 · S12 · Push MFA (this device)") {
        if let enrollment = model.pushEnrollment {
          LabeledContent("Device", value: enrollment.deviceLabel).accessibilityIdentifier("pushEnrolledDevice")
          LabeledContent("User", value: enrollment.username ?? enrollment.userId)
          LabeledContent("Provider", value: enrollment.pushProviderType + (enrollment.pushProviderId.map { " (\($0.prefix(8))…)" } ?? ""))
            .accessibilityIdentifier("pushProvider")
          LabeledContent("Key (jkt)", value: String(enrollment.keyThumbprint.prefix(12)) + "…").font(.footnote.monospaced())
          NavigationLink("Sign-in requests") {
            PushApprovalsView(push: model.push) { approval, status in
              model.noteApproval(approval, status: status)
            }
          }
          .accessibilityIdentifier("pushApprovals")
          if let enable = model.enableNotifications {
            Button("Enable notifications (device: real APNs token)") { Task { await enable() } }.disabled(model.isBusy)
              .accessibilityIdentifier("pushEnableNotifications")
          }
          Button("Simulate APNs token (S12)") { Task { await model.simulateApnsToken() } }.disabled(model.isBusy)
            .accessibilityIdentifier("pushSimulateToken")
          Button("Rotate device key (S12)") { Task { await model.rotatePushKey() } }.disabled(model.isBusy)
            .accessibilityIdentifier("pushRotate")
          Button("Lock out account (S12 panic button)", role: .destructive) { Task { await model.lockoutPush() } }.disabled(model.isBusy)
            .accessibilityIdentifier("pushLockout")
          Button("Forget local enrolment") { model.forgetPush() }.disabled(model.isBusy)
            .accessibilityIdentifier("pushForget")
          Text("The device key is this app's DPoP key and the device token is the stored native login (spec/03 §7.1). The simulator receives no APNs: open “Sign-in requests” and pull to refresh.")
            .font(.footnote).foregroundStyle(.secondary)
        } else {
          TextField("Device name", text: $model.pushDeviceLabel).accessibilityIdentifier("pushDeviceLabel")
          Button("Enrol this device for push") { Task { await model.enrolPush() } }
            .disabled(model.isBusy || model.credentials == nil)
            .accessibilityIdentifier("pushEnrol")
          Text(model.credentials == nil ? "Sign in first (S3); the enrolment uses the DPoP-bound tokens." : "POST /native-auth/push/enroll/start, then /push-mfa/enroll/complete with a device JWT signed by the DPoP key (spec/14 D9).")
            .font(.footnote).foregroundStyle(.secondary)
        }
      }
    }
    .navigationTitle("Home")
  }

  private func claim(_ name: String, _ claims: JSONValue?) -> some View {
    LabeledContent(name, value: claims?[name]?.stringValue ?? claims?[name].map { $0.serialized() } ?? "—")
  }
}
