import KeycloakNativeCore
import SwiftUI

/// Routes a challenge to its default screen (spec/05 §4 "Provided default screens").
struct DefaultChallengeScreen: View {
  let presentation: ChallengePresentationContext

  var body: some View {
    switch presentation.challenge.type {
    case .username: UsernameScreen(presentation: presentation)
    case .password: PasswordScreen(presentation: presentation)
    case .totp: TOTPScreen(presentation: presentation)
    case .otp: OTPScreen(presentation: presentation)
    case .passkey: PasskeyScreen(presentation: presentation)
    case .passkeyRegistration: PasskeyRegistrationScreen(presentation: presentation)
    case .updatePassword: UpdatePasswordScreen(presentation: presentation)
    case .verifyEmail: VerifyEmailScreen(presentation: presentation)
    case .terms: TermsScreen(presentation: presentation)
    case .push, .recoveryCode, .select, .unknown: UnsupportedScreen(presentation: presentation)
    }
  }
}

/// Shared frame: title, context line, the descriptor's error, the content, a cancel button.
struct ChallengeFrame<Content: View>: View {
  let presentation: ChallengePresentationContext
  let title: String
  let subtitle: String?
  @ViewBuilder let content: () -> Content

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(title).font(.title2.bold())
      if let user = presentation.flowContext.username {
        Text(presentation.isStepUp ? "Confirm it's you, \(presentation.flowContext.displayName ?? user)" : "Signing in as \(presentation.flowContext.displayName ?? user)")
          .font(.subheadline).foregroundStyle(.secondary)
      }
      if let subtitle { Text(subtitle).font(.footnote).foregroundStyle(.secondary) }
      if let error = presentation.challenge.error {
        Label(error.message ?? error.code, systemImage: "exclamationmark.triangle")
          .font(.footnote).foregroundStyle(.red)
          .accessibilityIdentifier("challengeError")
      }
      content()
      Button("Cancel", role: .cancel) { presentation.cancel() }
        .font(.footnote)
        .disabled(presentation.isSubmitting)
    }
    .padding()
    .frame(maxWidth: 480)
  }
}

struct UsernameScreen: View {
  let presentation: ChallengePresentationContext
  @State private var username = ""

  var body: some View {
    ChallengeFrame(presentation: presentation, title: "Sign in", subtitle: presentation.challenge.usernameParams?.allowEmail == true ? "Username or email" : "Username") {
      TextField("Username", text: $username)
        .textContentType(.username)
        .autocorrectionDisabled()
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("username")
        .onSubmit(submit)
      Button("Continue", action: submit)
        .buttonStyle(.borderedProminent)
        .disabled(username.isEmpty || presentation.isSubmitting)
    }
    .onAppear { if username.isEmpty, let hint = presentation.challenge.usernameParams?.hint { username = hint } }
  }

  private func submit() { presentation.submit(.username(username)) }
}

struct PasswordScreen: View {
  let presentation: ChallengePresentationContext
  @State private var password = ""

  var body: some View {
    ChallengeFrame(presentation: presentation, title: "Enter your password", subtitle: nil) {
      SecureField("Password", text: $password)
        .textContentType(.password)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("password")
        .onSubmit(submit)
      Button("Sign in", action: submit)
        .buttonStyle(.borderedProminent)
        .disabled(password.isEmpty || presentation.isSubmitting)
    }
  }

  private func submit() { presentation.submit(.password(password)) }
}

struct TOTPScreen: View {
  let presentation: ChallengePresentationContext
  @State private var code = ""
  @State private var credentialId: String?

  var body: some View {
    let params = presentation.challenge.totpParams
    ChallengeFrame(presentation: presentation, title: "Authenticator code", subtitle: "Enter the \(params?.digits ?? 6)-digit code from your authenticator app.") {
      if let credentials = params?.credentials, credentials.count > 1 {
        Picker("Authenticator", selection: $credentialId) {
          Text("Default").tag(String?.none)
          ForEach(credentials, id: \.id) { Text($0.label).tag(String?.some($0.id)) }
        }
      }
      TextField("Code", text: $code)
        .textContentType(.oneTimeCode)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("totp")
        .onSubmit(submit)
      Button("Verify", action: submit)
        .buttonStyle(.borderedProminent)
        .disabled(code.isEmpty || presentation.isSubmitting)
    }
  }

  private func submit() { presentation.submit(.totp(code, credentialId: credentialId)) }
}

/// `otp` (spec/03 §4.6): shows the masked destination, a resend button with the server's cooldown,
/// and a "Send me a code" button first when the server has not sent one yet (`sent: false`).
struct OTPScreen: View {
  let presentation: ChallengePresentationContext
  @State private var code = ""
  @State private var now = Date()
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    let params = presentation.challenge.otpParams
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    let destination = params?.destinationMasked ?? (params?.channel == "sms" ? "your phone" : "your email address")
    ChallengeFrame(
      presentation: presentation,
      title: params?.channel == "sms" ? "Text message code" : "Email code",
      subtitle: sent ? "We sent a \(params?.digits ?? 6)-digit code to \(destination)." : "We can send a \(params?.digits ?? 6)-digit code to \(destination)."
    ) {
      if sent {
        TextField("Code", text: $code)
          .textContentType(.oneTimeCode)
          .textFieldStyle(.roundedBorder)
          .accessibilityIdentifier("otp")
          .onSubmit(submit)
        Button("Verify", action: submit)
          .buttonStyle(.borderedProminent)
          .disabled(code.isEmpty || presentation.isSubmitting)
        Button(wait > 0 ? "Resend code in \(wait) s" : "Resend code") { presentation.submit(.otpResend) }
          .disabled(wait > 0 || presentation.isSubmitting)
          .accessibilityIdentifier("otpResend")
      } else {
        Button(wait > 0 ? "Send me a code (\(wait) s)" : "Send me a code") { presentation.submit(.otpResend) }
          .buttonStyle(.borderedProminent)
          .disabled(wait > 0 || presentation.isSubmitting)
          .accessibilityIdentifier("otpSend")
      }
    }
    .onReceive(ticker) { now = $0 }
  }

  private func submit() { presentation.submit(.otp(code)) }
}

struct PasskeyScreen: View {
  let presentation: ChallengePresentationContext

  var body: some View {
    let params = presentation.challenge.passkeyParams
    ChallengeFrame(presentation: presentation, title: "Sign in with a passkey", subtitle: params?.discoverable == true ? "Use a passkey saved on this device." : "Use the passkey registered for this account.") {
      Button {
        presentation.usePasskey()
      } label: {
        Label("Continue with passkey", systemImage: "person.badge.key")
      }
      .buttonStyle(.borderedProminent)
      .disabled(presentation.isSubmitting)
      .accessibilityIdentifier("usePasskey")
    }
  }
}

struct PasskeyRegistrationScreen: View {
  let presentation: ChallengePresentationContext
  @State private var label = ""

  var body: some View {
    let params = presentation.challenge.passkeyRegistrationParams
    ChallengeFrame(presentation: presentation, title: "Create a passkey", subtitle: "\(params?.rp.name ?? "This service") requires a passkey for \(params?.user.name ?? "your account") before you can continue.") {
      TextField("Passkey name (optional)", text: $label).textFieldStyle(.roundedBorder)
      Button {
        presentation.registerPasskey(label: label.isEmpty ? nil : label)
      } label: {
        Label("Create passkey", systemImage: "person.badge.key.fill")
      }
      .buttonStyle(.borderedProminent)
      .disabled(presentation.isSubmitting)
      .accessibilityIdentifier("createPasskey")
    }
  }
}

/// `update_password` (spec/03 §4.12): the new password twice, with the realm's policy as hints.
struct UpdatePasswordScreen: View {
  let presentation: ChallengePresentationContext
  @State private var password = ""
  @State private var confirm = ""

  var body: some View {
    let params = presentation.challenge.updatePasswordParams
    ChallengeFrame(presentation: presentation, title: "Choose a new password", subtitle: "Your password must be updated before you can continue.") {
      SecureField("New password", text: $password)
        .textContentType(.newPassword)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("newPassword")
      SecureField("Confirm new password", text: $confirm)
        .textContentType(.newPassword)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("newPasswordConfirm")
        .onSubmit(submit)
      if let hints = params?.hints, !hints.isEmpty {
        VStack(alignment: .leading, spacing: 2) {
          ForEach(hints, id: \.self) { Text("• \($0)").font(.footnote).foregroundStyle(.secondary) }
        }
      }
      if !confirm.isEmpty, confirm != password {
        Text("Passwords do not match").font(.footnote).foregroundStyle(.red)
      }
      Button("Update password", action: submit)
        .buttonStyle(.borderedProminent)
        .disabled(password.isEmpty || confirm != password || presentation.isSubmitting)
        .accessibilityIdentifier("updatePassword")
    }
  }

  private func submit() { presentation.submit(.updatePassword(password, confirm: confirm)) }
}

/// `verify_email` (spec/03 §4.13): the code sent to the masked address, with resend and cooldown.
struct VerifyEmailScreen: View {
  let presentation: ChallengePresentationContext
  @State private var code = ""
  @State private var now = Date()
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    let params = presentation.challenge.verifyEmailParams
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    let destination = params?.emailMasked ?? "your email address"
    ChallengeFrame(
      presentation: presentation,
      title: "Verify your email",
      subtitle: sent ? "We sent a \(params?.digits ?? 6)-digit code to \(destination)." : "We need to send a \(params?.digits ?? 6)-digit code to \(destination)."
    ) {
      if sent {
        TextField("Code", text: $code)
          .textContentType(.oneTimeCode)
          .textFieldStyle(.roundedBorder)
          .accessibilityIdentifier("verifyEmailCode")
          .onSubmit(submit)
        Button("Verify", action: submit)
          .buttonStyle(.borderedProminent)
          .disabled(code.isEmpty || presentation.isSubmitting)
      }
      Button(sent ? (wait > 0 ? "Resend code in \(wait) s" : "Resend code") : (wait > 0 ? "Send a code (\(wait) s)" : "Send a code")) { presentation.submit(.verifyEmailResend) }
        .disabled(wait > 0 || presentation.isSubmitting)
        .accessibilityIdentifier("verifyEmailResend")
    }
    .onReceive(ticker) { now = $0 }
  }

  private func submit() { presentation.submit(.verifyEmail(code: code)) }
}

/// `terms` (spec/03 §4.14): the text and/or a link, then accept or decline (decline ends the login).
struct TermsScreen: View {
  let presentation: ChallengePresentationContext
  @Environment(\.openURL) private var openURL

  var body: some View {
    let params = presentation.challenge.termsParams
    ChallengeFrame(presentation: presentation, title: "Terms and conditions", subtitle: params?.version.map { "Version \($0)" }) {
      if let text = params?.text {
        ScrollView { Text(text).font(.footnote).frame(maxWidth: .infinity, alignment: .leading) }
          .frame(maxHeight: 220)
          .accessibilityIdentifier("termsText")
      }
      if let url = params?.url {
        Button("Read the full terms") { openURL(url) }.font(.footnote)
      }
      Button("Accept") { presentation.submit(.terms(accepted: true)) }
        .buttonStyle(.borderedProminent)
        .disabled(presentation.isSubmitting)
        .accessibilityIdentifier("acceptTerms")
      Button("Decline", role: .destructive) { presentation.submit(.terms(accepted: false)) }
        .disabled(presentation.isSubmitting)
        .accessibilityIdentifier("declineTerms")
    }
  }
}

struct UnsupportedScreen: View {
  let presentation: ChallengePresentationContext

  var body: some View {
    ChallengeFrame(presentation: presentation, title: "Update required", subtitle: "This version of the app cannot handle the '\(presentation.challenge.type.wire)' sign-in method. Update the app or sign in on the web.") {
      EmptyView()
    }
  }
}

/// The default "Try another way" list under a screen.
struct DefaultChallengeChooser: View {
  let context: ChallengeChooserContext

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("Try another way").font(.footnote).foregroundStyle(.secondary)
      ForEach(context.alternatives.filter { $0.type.isSupported }) { challenge in
        Button(title(for: challenge)) { context.select(challenge) }
          .font(.footnote)
          .accessibilityIdentifier("switchTo-\(challenge.type.wire)")
      }
    }
    .padding(.horizontal)
    .padding(.bottom)
    .frame(maxWidth: 480, alignment: .leading)
  }

  private func title(for challenge: Challenge) -> String {
    switch challenge.type {
    case .passkey: "Use a passkey"
    case .password: "Use your password"
    case .totp: "Use an authenticator app"
    case .otp: challenge.otpParams?.channel == "sms" ? "Text me a code" : "Email me a code"
    default: challenge.label ?? challenge.type.wire
    }
  }
}

/// `redirect_to_web` (spec/03 §3.4): explains and opens the system browser.
struct RedirectToWebScreen: View {
  let request: RedirectToWebRequest
  let isSubmitting: Bool
  let message: String?
  let open: () -> Void
  let cancel: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Continue in your browser").font(.title2.bold())
      Text(explanation).font(.footnote).foregroundStyle(.secondary)
      if let message { Text(message).font(.footnote).foregroundStyle(.red) }
      Button("Open browser", action: open)
        .buttonStyle(.borderedProminent)
        .disabled(isSubmitting)
        .accessibilityIdentifier("openBrowser")
      Button("Cancel", role: .cancel, action: cancel).font(.footnote)
    }
    .padding()
    .frame(maxWidth: 480)
  }

  private var explanation: String {
    if let reason = request.reason, reason.hasPrefix("required_action:") {
      let action = reason.dropFirst("required_action:".count).replacingOccurrences(of: "_", with: " ").lowercased()
      return "Your account needs attention (\(action)). Finish it on the web, then you will be returned here."
    }
    return request.errorDescription ?? "This sign-in has to be completed on the web."
  }
}
