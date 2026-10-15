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
    case .recoveryCode: RecoveryCodeScreen(presentation: presentation)
    case .push: PushScreen(presentation: presentation)
    case .pushEnrollment: PushEnrollmentScreen(presentation: presentation)
    case .select, .unknown: UnsupportedScreen(presentation: presentation)
    }
  }
}

/// Shared frame: title, context line, the descriptor's error, the content, a cancel button.
struct ChallengeFrame<Content: View>: View {
  let presentation: ChallengePresentationContext
  let title: String
  let subtitle: String?
  @ViewBuilder let content: () -> Content
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(title).font(.title2.bold())
      if let user = presentation.flowContext.username {
        let name = presentation.flowContext.displayName ?? user
        Text(presentation.isStepUp ? l("Confirm it's you, %@", name) : l("Signing in as %@", name))
          .font(.subheadline).foregroundStyle(.secondary)
      }
      if let subtitle { Text(subtitle).font(.footnote).foregroundStyle(.secondary) }
      if let error = presentation.challenge.error {
        Label(error.message ?? error.code, systemImage: "exclamationmark.triangle")
          .font(.footnote).foregroundStyle(.red)
          .accessibilityIdentifier("challengeError")
        if let remaining = presentation.challenge.retry?.remaining {
          // spec/03 §3.3: attempts left before the realm's brute-force protection locks the account.
          Text(remaining == 1 ? l("1 attempt left") : l("%lld attempts left", remaining)).font(.footnote).foregroundStyle(.secondary)
            .accessibilityIdentifier("retryRemaining")
        }
      }
      content()
      Button(l("Cancel"), role: .cancel) { presentation.cancel() }
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    ChallengeFrame(presentation: presentation, title: l("Sign in"), subtitle: presentation.challenge.usernameParams?.allowEmail == true ? l("Username or email") : l("Username")) {
      TextField(l("Username"), text: $username)
        .textContentType(.username)
        .autocorrectionDisabled()
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("username")
        .onSubmit(submit)
      Button(l("Continue"), action: submit)
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    ChallengeFrame(presentation: presentation, title: l("Enter your password"), subtitle: nil) {
      SecureField(l("Password"), text: $password)
        .textContentType(.password)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("password")
        .onSubmit(submit)
      Button(l("Sign in"), action: submit)
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.totpParams
    ChallengeFrame(presentation: presentation, title: l("Authenticator code"), subtitle: l("Enter the %lld-digit code from your authenticator app.", params?.digits ?? 6)) {
      if let credentials = params?.credentials, credentials.count > 1 {
        Picker(l("Authenticator"), selection: $credentialId) {
          Text(l("Default")).tag(String?.none)
          ForEach(credentials, id: \.id) { Text($0.label).tag(String?.some($0.id)) }
        }
      }
      TextField(l("Code"), text: $code)
        .textContentType(.oneTimeCode)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("totp")
        .onSubmit(submit)
      Button(l("Verify"), action: submit)
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
  @Environment(\.nativeLoginStrings) private var l
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    let params = presentation.challenge.otpParams
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    let digits = params?.digits ?? 6
    let destination = params?.destinationMasked ?? (params?.channel == "sms" ? l("your phone") : l("your email address"))
    ChallengeFrame(
      presentation: presentation,
      title: params?.channel == "sms" ? l("Text message code") : l("Email code"),
      subtitle: sent ? l("We sent a %lld-digit code to %@.", digits, destination) : l("We can send a %lld-digit code to %@.", digits, destination)
    ) {
      if sent {
        TextField(l("Code"), text: $code)
          .textContentType(.oneTimeCode)
          .textFieldStyle(.roundedBorder)
          .accessibilityIdentifier("otp")
          .onSubmit(submit)
        Button(l("Verify"), action: submit)
          .buttonStyle(.borderedProminent)
          .disabled(code.isEmpty || presentation.isSubmitting)
        Button(wait > 0 ? l("Resend code in %lld s", wait) : l("Resend code")) { presentation.submit(.otpResend) }
          .disabled(wait > 0 || presentation.isSubmitting)
          .accessibilityIdentifier("otpResend")
      } else {
        Button(wait > 0 ? l("Send me a code (%lld s)", wait) : l("Send me a code")) { presentation.submit(.otpResend) }
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.passkeyParams
    ChallengeFrame(presentation: presentation, title: l("Sign in with a passkey"), subtitle: params?.discoverable == true ? l("Use a passkey saved on this device.") : l("Use the passkey registered for this account.")) {
      Button {
        presentation.usePasskey()
      } label: {
        Label(l("Continue with passkey"), systemImage: "person.badge.key")
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.passkeyRegistrationParams
    ChallengeFrame(presentation: presentation, title: l("Create a passkey"), subtitle: l("%@ requires a passkey for %@ before you can continue.", params?.rp.name ?? l("This service"), params?.user.name ?? l("your account"))) {
      TextField(l("Passkey name (optional)"), text: $label).textFieldStyle(.roundedBorder)
      Button {
        presentation.registerPasskey(label: label.isEmpty ? nil : label)
      } label: {
        Label(l("Create passkey"), systemImage: "person.badge.key.fill")
      }
      .buttonStyle(.borderedProminent)
      .disabled(presentation.isSubmitting)
      .accessibilityIdentifier("createPasskey")
    }
  }
}

/// `recovery_code` (spec/03 §4.8): one single-use code, with the remaining count and a warning.
struct RecoveryCodeScreen: View {
  let presentation: ChallengePresentationContext
  @State private var code = ""
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.recoveryCodeParams
    ChallengeFrame(presentation: presentation, title: l("Recovery code"), subtitle: params?.remaining.map { l("Enter one of your unused recovery codes (%lld left).", $0) } ?? l("Enter one of your unused recovery codes.")) {
      if params?.shouldWarn == true {
        Label(l("You are running low on recovery codes; generate new ones after signing in."), systemImage: "exclamationmark.circle")
          .font(.footnote).foregroundStyle(.orange)
      }
      TextField("XXXX-XXXX-XXXX", text: $code)
        #if os(iOS)
        .textInputAutocapitalization(.characters)
        #endif
        .autocorrectionDisabled()
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("recoveryCode")
        .onSubmit(submit)
      Button(l("Sign in"), action: submit)
        .buttonStyle(.borderedProminent)
        .disabled(code.isEmpty || presentation.isSubmitting)
    }
  }

  private func submit() { presentation.submit(.recoveryCode(code)) }
}

/// `update_password` (spec/03 §4.12): the new password twice, with the realm's policy as hints.
struct UpdatePasswordScreen: View {
  let presentation: ChallengePresentationContext
  @State private var password = ""
  @State private var confirm = ""
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.updatePasswordParams
    ChallengeFrame(presentation: presentation, title: l("Choose a new password"), subtitle: l("Your password must be updated before you can continue.")) {
      SecureField(l("New password"), text: $password)
        .textContentType(.newPassword)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("newPassword")
      SecureField(l("Confirm new password"), text: $confirm)
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
        Text(l("Passwords do not match")).font(.footnote).foregroundStyle(.red)
      }
      Button(l("Update password"), action: submit)
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
  @Environment(\.nativeLoginStrings) private var l
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    let params = presentation.challenge.verifyEmailParams
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    let digits = params?.digits ?? 6
    let destination = params?.emailMasked ?? l("your email address")
    ChallengeFrame(
      presentation: presentation,
      title: l("Verify your email"),
      subtitle: sent ? l("We sent a %lld-digit code to %@.", digits, destination) : l("We need to send a %lld-digit code to %@.", digits, destination)
    ) {
      if sent {
        TextField(l("Code"), text: $code)
          .textContentType(.oneTimeCode)
          .textFieldStyle(.roundedBorder)
          .accessibilityIdentifier("verifyEmailCode")
          .onSubmit(submit)
        Button(l("Verify"), action: submit)
          .buttonStyle(.borderedProminent)
          .disabled(code.isEmpty || presentation.isSubmitting)
      }
      Button(sent ? (wait > 0 ? l("Resend code in %lld s", wait) : l("Resend code")) : (wait > 0 ? l("Send a code (%lld s)", wait) : l("Send a code"))) { presentation.submit(.verifyEmailResend) }
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let params = presentation.challenge.termsParams
    ChallengeFrame(presentation: presentation, title: l("Terms and conditions"), subtitle: params?.version.map { l("Version %@", $0) }) {
      if let text = params?.text {
        ScrollView { Text(text).font(.footnote).frame(maxWidth: .infinity, alignment: .leading) }
          .frame(maxHeight: 220)
          .accessibilityIdentifier("termsText")
      }
      if let url = params?.url {
        Button(l("Read the full terms")) { openURL(url) }.font(.footnote)
      }
      Button(l("Accept")) { presentation.submit(.terms(accepted: true)) }
        .buttonStyle(.borderedProminent)
        .disabled(presentation.isSubmitting)
        .accessibilityIdentifier("acceptTerms")
      Button(l("Decline"), role: .destructive) { presentation.submit(.terms(accepted: false)) }
        .disabled(presentation.isSubmitting)
        .accessibilityIdentifier("declineTerms")
    }
  }
}

struct UnsupportedScreen: View {
  let presentation: ChallengePresentationContext
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    ChallengeFrame(presentation: presentation, title: l("Update required"), subtitle: l("This version of the app cannot handle the '%@' sign-in method. Update the app or sign in on the web.", presentation.challenge.type.wire)) {
      EmptyView()
    }
  }
}

/// The default "Try another way" list under a screen.
struct DefaultChallengeChooser: View {
  let context: ChallengeChooserContext
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(l("Try another way")).font(.footnote).foregroundStyle(.secondary)
      ForEach(context.alternatives.filter { $0.type.isSupported }) { challenge in
        Button(DefaultChallengeChooser.title(for: challenge, strings: l)) { context.select(challenge) }
          .font(.footnote)
          .accessibilityIdentifier("switchTo-\(challenge.type.wire)")
      }
    }
    .padding(.horizontal)
    .padding(.bottom)
    .frame(maxWidth: 480, alignment: .leading)
  }

  static func title(for challenge: Challenge, strings l: NativeLoginStrings) -> String {
    switch challenge.type {
    case .passkey: l("Use a passkey")
    case .password: l("Use your password")
    case .totp: l("Use an authenticator app")
    case .otp: challenge.otpParams?.channel == "sms" ? l("Text me a code") : l("Email me a code")
    case .recoveryCode: l("Use a recovery code")
    case .push: l("Approve on your phone")
    default: challenge.label ?? challenge.type.wire
    }
  }
}

/// `push` (spec/03 §4.7): sends the push when the user asks (or shows the one already sent), shows
/// the number for number match, and polls every `poll_interval` seconds until the device answers.
struct PushScreen: View {
  let presentation: ChallengePresentationContext
  @State private var now = Date()
  @Environment(\.nativeLoginStrings) private var l
  private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

  var body: some View {
    let params = presentation.challenge.pushParams
    let sent = params?.sent ?? false
    let wait = Int(params?.resendWait(at: now).rounded(.up) ?? 0)
    let device = params?.devices.first ?? l("your phone")
    ChallengeFrame(
      presentation: presentation,
      title: l("Approve on your phone"),
      subtitle: sent ? l("We sent a sign-in request to %@. Approve it there to continue.", device) : l("We can send a sign-in request to %@.", device)
    ) {
      if sent {
        if let number = params?.userVerificationNumber {
          VStack(spacing: 4) {
            Text(l("Choose this number on your phone")).font(.footnote).foregroundStyle(.secondary)
            Text(number).font(.system(size: 44, weight: .bold, design: .rounded)).accessibilityIdentifier("pushNumber")
          }
          .frame(maxWidth: .infinity)
        }
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text(l("Waiting for your approval…")).font(.footnote).foregroundStyle(.secondary).accessibilityIdentifier("pushWaiting")
        }
        Button(l("Check now")) { presentation.submit(.pushPoll) }
          .disabled(presentation.isSubmitting)
          .accessibilityIdentifier("pushPoll")
      } else {
        Button(wait > 0 ? l("Send request (%lld s)", wait) : l("Send request")) { presentation.submit(.pushResend) }
          .buttonStyle(.borderedProminent)
          .disabled(wait > 0 || presentation.isSubmitting)
          .accessibilityIdentifier("pushSend")
      }
    }
    .onReceive(ticker) { now = $0 }
    .task(id: params?.cid) {
      // Poll while the challenge is pending; the server advances on `approved` (spec/03 §4.7).
      guard let params, params.isPending else { return }
      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(params.pollInterval))
        guard !Task.isCancelled, !presentation.isSubmitting else { continue }
        presentation.submit(.pushPoll)
      }
    }
  }
}

/// `push_enrollment` (spec/03 §4.15): enrols this device with the SDK's DPoP key. The default
/// screen enrols without a push provider (`none`: the app pulls its approvals); an app that has
/// an APNs token replaces the screen or calls `enrolPush(deviceLabel:pushProviderType:pushProviderId:)`.
struct PushEnrollmentScreen: View {
  let presentation: ChallengePresentationContext
  @State private var label = ""
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    let client = presentation.flowContext.clientName ?? l("This service")
    ChallengeFrame(presentation: presentation, title: l("Set up sign-in approvals"), subtitle: l("%@ asks you to enrol this device so you can approve sign-ins from here.", client)) {
      TextField(l("Device name (optional)"), text: $label)
        .textFieldStyle(.roundedBorder)
        .accessibilityIdentifier("pushDeviceLabel")
      Button(l("Enrol this device")) {
        presentation.enrolPush(deviceLabel: label.isEmpty ? l("This device") : label)
      }
      .buttonStyle(.borderedProminent)
      .disabled(presentation.isSubmitting)
      .accessibilityIdentifier("pushEnrol")
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
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(l("Continue in your browser")).font(.title2.bold())
      Text(explanation).font(.footnote).foregroundStyle(.secondary)
      if let message { Text(message).font(.footnote).foregroundStyle(.red) }
      Button(l("Open browser"), action: open)
        .buttonStyle(.borderedProminent)
        .disabled(isSubmitting)
        .accessibilityIdentifier("openBrowser")
      Button(l("Cancel"), role: .cancel, action: cancel).font(.footnote)
    }
    .padding()
    .frame(maxWidth: 480)
  }

  private var explanation: String {
    if let reason = request.reason, reason.hasPrefix("required_action:") {
      let action = reason.dropFirst("required_action:".count).replacingOccurrences(of: "_", with: " ").lowercased()
      return l("Your account needs attention (%@). Finish it on the web, then you will be returned here.", action)
    }
    return request.errorDescription ?? l("This sign-in has to be completed on the web.")
  }
}
