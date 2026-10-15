import KeycloakNativeCore
import KeycloakNativeUI
import SwiftUI

/// Hand-rolled rendering of `FlowStep` from Core (spec/05 §4 option 3): one section per offered
/// challenge, in the server's order. `KeycloakNativeUI` default screens arrive in Phase 2.
struct LoginView: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    if model.scenario?.usesDefaultUI == true {
      DefaultUILoginView()
    } else {
      handRolled
    }
  }

  private var handRolled: some View {
    @Bindable var model = model
    return Form {
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
          Section(context.stepUp ? "Step-up" : "Context") {
            LabeledContent("User", value: context.displayName.map { "\($0) (\(username))" } ?? username)
            if let client = context.clientName { LabeledContent("Client", value: client) }
            if context.stepUp { LabeledContent("acr requested", value: context.acrRequested ?? "— (max_age)") }
          }
        }
        ForEach(challenges) { challenge in
          Section {
            challengeView(challenge)
          } header: {
            Text("\(challenge.type.wire)\(challenge.required ? "" : " · alternative")")
          } footer: {
            if let error = challenge.error {
              Text("\(error.code): \(error.message ?? "")" + (challenge.retry?.remaining.map { " (\($0) attempt\($0 == 1 ? "" : "s") left)" } ?? "")).foregroundStyle(.red)
            } else if let label = challenge.label {
              Text(label)
            }
          }
        }
      } else if case .redirectToWeb(let request) = model.step {
        Section("Continue in the browser (S7)") {
          Text("The server cannot finish this login natively (\(request.reason ?? "redirect_to_web")). Safari opens the realm's login page with a pushed authorization request; the code it returns is exchanged with this flow's PKCE verifier.")
            .font(.footnote).foregroundStyle(.secondary)
          Button("Open browser") { Task { await model.continueInBrowser() } }.disabled(model.isBusy)
            .accessibilityIdentifier("openBrowser")
        }
      } else if case .authorized(let credentials) = model.step {
        Section("Signed in") {
          LabeledContent("User", value: credentials.accessTokenClaims?["preferred_username"]?.stringValue ?? "?")
          LabeledContent("Token type", value: credentials.tokenType).accessibilityIdentifier("signedInTokenType")
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
        .accessibilityIdentifier("username")
      Button("Continue") { Task { await model.answer(.username(model.username), to: challenge) } }
        .disabled(model.isBusy || model.username.isEmpty)
    case .password:
      SecureField("Password", text: $model.password).textContentType(.password)
        .accessibilityIdentifier("password")
      Button("Sign in with password") { Task { await model.answer(.password(model.password), to: challenge) } }
        .disabled(model.isBusy)
    case .totp:
      let params = challenge.totpParams
      TextField("\(params?.digits ?? 6)-digit code", text: $model.totp).textContentType(.oneTimeCode)
        .accessibilityIdentifier("totp")
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
    case .otp:
      OTPChallengeSection(challenge: challenge, params: challenge.otpParams)
    case .updatePassword:
      let params = challenge.updatePasswordParams
      Text("Keycloak's UPDATE_PASSWORD served in-band by \(challenge.id) (spec/03 §4.12).").font(.footnote).foregroundStyle(.secondary)
      if let hints = params?.hints, !hints.isEmpty {
        Text(hints.joined(separator: " · ")).font(.footnote).foregroundStyle(.secondary)
      }
      SecureField("New password", text: $model.newPassword).textContentType(.newPassword).accessibilityIdentifier("newPassword")
      SecureField("Confirm new password", text: $model.newPasswordConfirm).textContentType(.newPassword).accessibilityIdentifier("newPasswordConfirm")
      Button("Update password") { Task { await model.answer(.updatePassword(model.newPassword, confirm: model.newPasswordConfirm), to: challenge) } }
        .disabled(model.isBusy || model.newPassword.isEmpty)
        .accessibilityIdentifier("updatePassword")
    case .verifyEmail:
      VerifyEmailChallengeSection(challenge: challenge, params: challenge.verifyEmailParams)
    case .terms:
      let params = challenge.termsParams
      if let text = params?.text { Text(text).font(.footnote).accessibilityIdentifier("termsText") }
      if let url = params?.url { Link("Read the full terms (\(params?.version ?? "no version"))", destination: url).font(.footnote) }
      Button("Accept") { Task { await model.answer(.terms(accepted: true), to: challenge) } }.disabled(model.isBusy).accessibilityIdentifier("acceptTerms")
      Button("Decline", role: .destructive) { Task { await model.answer(.terms(accepted: false), to: challenge) } }.disabled(model.isBusy).accessibilityIdentifier("declineTerms")
    case .recoveryCode:
      let params = challenge.recoveryCodeParams
      Text("\(params?.remaining.map(String.init) ?? "?") unused code(s) left" + (params?.shouldWarn == true ? " — generate new ones soon" : "")).font(.footnote).foregroundStyle(.secondary)
      TextField("XXXX-XXXX-XXXX", text: $model.recoveryCode).autocorrectionDisabled().accessibilityIdentifier("recoveryCode")
      Button("Sign in with a recovery code") { Task { await model.answer(.recoveryCode(model.recoveryCode), to: challenge) } }
        .disabled(model.isBusy || model.recoveryCode.isEmpty)
    case .push, .select, .unknown:
      Text("Unsupported challenge type '\(challenge.type.wire)' in this app version: update the app or use the web.")
        .foregroundStyle(.orange)
    }
  }
}


/// S4: the hand-rolled `otp` screen (send / verify / resend with the server's cooldown).
struct OTPChallengeSection: View {
  @Environment(DemoModel.self) private var model
  let challenge: Challenge
  let params: OTPParams?
  @State private var now = Date()
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    @Bindable var model = model
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    Text(sent ? "Code sent to \(params?.destinationMasked ?? "?") via \(params?.channel ?? "?"), valid \(params?.ttl ?? 0) s" : "No code sent yet (\(params?.channel ?? "?") to \(params?.destinationMasked ?? "?")): ask for one")
      .font(.footnote).foregroundStyle(.secondary)
    if sent {
      TextField("\(params?.digits ?? 6)-digit code", text: $model.otp).textContentType(.oneTimeCode).accessibilityIdentifier("otp")
      Button("Verify code") { Task { await model.answer(.otp(model.otp), to: challenge) } }
        .disabled(model.isBusy || model.otp.isEmpty)
    }
    Button(sent ? (wait > 0 ? "Resend in \(wait) s" : "Resend code") : "Send me a code") { Task { await model.resendOtp(challenge) } }
      .disabled(model.isBusy || wait > 0)
      .accessibilityIdentifier("otpResend")
      .onReceive(ticker) { now = $0 }
  }
}

/// grace: the hand-rolled `verify_email` screen (spec/03 §4.13), same shape as the `otp` one.
struct VerifyEmailChallengeSection: View {
  @Environment(DemoModel.self) private var model
  let challenge: Challenge
  let params: VerifyEmailParams?
  @State private var now = Date()
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    @Bindable var model = model
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    Text(sent ? "Code sent to \(params?.emailMasked ?? "?"), valid \(params?.ttl ?? 0) s (VERIFY_EMAIL served by \(challenge.id))" : "No code outstanding: ask for one")
      .font(.footnote).foregroundStyle(.secondary)
    if sent {
      TextField("\(params?.digits ?? 6)-digit code", text: $model.verifyEmailCode).textContentType(.oneTimeCode).accessibilityIdentifier("verifyEmailCode")
      Button("Verify email") { Task { await model.answer(.verifyEmail(code: model.verifyEmailCode), to: challenge) } }
        .disabled(model.isBusy || model.verifyEmailCode.isEmpty)
        .accessibilityIdentifier("verifyEmail")
    }
    Button(sent ? (wait > 0 ? "Resend in \(wait) s" : "Resend code") : "Send me a code") { Task { await model.answer(.verifyEmailResend, to: challenge) } }
      .disabled(model.isBusy || wait > 0)
      .accessibilityIdentifier("verifyEmailResend")
      .onReceive(ticker) { now = $0 }
  }
}

/// S5 / S13: the KeycloakNativeUI product driving the flow with the default screens; S13 swaps the
/// TOTP screen through `challengePresenter(for:)`.
struct DefaultUILoginView: View {
  @Environment(DemoModel.self) private var model
  @State private var flow: NativeLoginFlow?

  var body: some View {
    VStack {
      Text(model.scenario?.title ?? "").font(.headline).padding(.top)
      if let flow {
        let view = NativeLoginView(kc: model.sdk, flow: flow, theme: NativeLoginTheme(title: "Demo")) { result in
          model.finish(result)
          self.flow = nil
        }
        if model.scenario == .s13CustomPresenter {
          view.challengePresenter(for: .totp) { context in CustomTOTPScreen(context: context) }
        } else {
          view
        }
      } else {
        Button("Start login (\(model.activeClientId))") {
          flow = model.sdk.authentication().startLogin(LoginParameters(scope: "openid profile", deviceName: model.config.deviceName))
        }
        .buttonStyle(.borderedProminent)
        .accessibilityIdentifier("startDefaultUI")
        StatusBar().padding()
      }
      Spacer()
    }
    .navigationTitle("Login")
  }
}

/// S13: a deliberately different TOTP screen built from the presentation context only.
struct CustomTOTPScreen: View {
  let context: ChallengePresentationContext
  @State private var digits = ""

  var body: some View {
    VStack(spacing: 12) {
      Text("CUSTOM TOTP SCREEN").font(.caption.bold()).foregroundStyle(.orange).accessibilityIdentifier("customTotpTitle")
      Text("Type the code from your authenticator for \(context.flowContext.username ?? "?")")
      if let error = context.challenge.error { Text(error.message ?? error.code).foregroundStyle(.red) }
      TextField("000000", text: $digits).textFieldStyle(.roundedBorder).textContentType(.oneTimeCode).accessibilityIdentifier("customTotp")
      Button("Go") { context.submit(.totp(digits)) }.buttonStyle(.bordered).disabled(digits.count < 6 || context.isSubmitting)
      Button("Cancel", role: .cancel) { context.cancel() }.font(.footnote)
    }
    .padding()
    .background(Color.orange.opacity(0.1))
  }
}
