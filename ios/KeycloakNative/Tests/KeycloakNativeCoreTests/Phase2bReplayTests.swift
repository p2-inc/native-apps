import Foundation
import Testing
@testable import KeycloakNativeCore

/// Phase 2b contract tests (spec/14): the native required actions `update_password`, `verify_email`
/// and `terms` (spec/03 §4.11–§4.14), replayed from the transcripts of RequiredActionsIT.
@Suite(.serialized) struct Phase2bReplayTests {
  static let client = TranscriptReplayTests.demoIOS
  static let itParameters = TranscriptReplayTests.itParameters

  private func loginToRequiredAction(_ h: Harness, username: String, password: String) async throws -> (NativeLoginFlow, Challenge) {
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username(username), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password(password), to: try #require(step.challenges?.first(.password)))
    let challenges = try #require(step.challenges)
    #expect(challenges.count == 1 && challenges[0].required && challenges[0].type.isRequiredAction, "a required action is the single entry")
    return (flow, challenges[0])
  }

  @Test func metadataAdvertisesTheNativeRequiredActions() async throws {
    let (h, _, _) = try Harness.replay([], clientId: Self.client, metadataFrom: "RequiredActionsIT.metadataAdvertisesTheNativeRequiredActions")
    let metadata = try await h.sdk.metadata()
    for type in ["update_password", "verify_email", "terms", "passkey_registration"] {
      #expect(metadata.challengeTypesSupported.contains(type), "\(type) advertised")
    }
    #expect(ChallengeType(wire: "update_password") == .updatePassword && ChallengeType.terms.isSupported && ChallengeType.verifyEmail.isSupported)
  }

  @Test func carolUpdatesHerPasswordInBand() async throws {
    let (h, transport, _) = try Harness.replay(["RequiredActionsIT.carolUpdatesHerPasswordInBand"], clientId: Self.client, range: 1...8)
    let (flow, challenge) = try await loginToRequiredAction(h, username: "carol", password: "carol-password")
    #expect(challenge.type == .updatePassword && challenge.id == "native-update-password")
    let params = try #require(challenge.updatePasswordParams)
    #expect(params.username == "carol" && params.minimumLength == 8)
    #expect(params.hints == ["At least 8 characters"])

    var step = try await flow.respond(.updatePassword("", confirm: ""), to: challenge)
    let missing = try #require(step.challenges?.first(.updatePassword))
    #expect(missing.error?.code == ChallengeError.Code.missingCredential)

    step = try await flow.respond(.updatePassword("carol-password", confirm: "other"), to: missing)
    let mismatch = try #require(step.challenges?.first(.updatePassword))
    #expect(mismatch.error?.code == ChallengeError.Code.passwordMismatch)

    step = try await flow.respond(.updatePassword("short", confirm: "short"), to: mismatch)
    let rejected = try #require(step.challenges?.first(.updatePassword))
    #expect(rejected.error?.code == ChallengeError.Code.invalidPassword)
    #expect(rejected.error?.message?.contains("8") == true, "the policy message is rendered: \(rejected.error?.message ?? "")")

    step = try await flow.respond(.updatePassword("carol-password", confirm: "carol-password"), to: rejected)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "carol")
    #expect(transport.remaining == 0)
    // The new password never reaches the flow log.
    let everything = h.observer.entries.compactMap(\.requestBody).joined()
    #expect(!everything.contains("carol-password") && !everything.contains("short"))
  }

  @Test func disablingTheNativeVariantFallsBackToRedirectToWeb() async throws {
    let (h, transport, _) = try Harness.replay(["RequiredActionsIT.disablingTheNativeVariantFallsBackToRedirectToWeb"], clientId: Self.client)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("carol"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("carol-password"), to: try #require(step.challenges?.first(.password)))
    guard case .redirectToWeb(let request) = step else { Issue.record("expected redirect_to_web, got \(step)"); return }
    #expect(request.reason == "required_action:UPDATE_PASSWORD")
    #expect(transport.remaining == 0)
  }

  @Test func graceVerifiesHerEmailWithACode() async throws {
    let (h, transport, _) = try Harness.replay(["RequiredActionsIT.graceVerifiesHerEmailWithACode"], clientId: Self.client)
    let (flow, challenge) = try await loginToRequiredAction(h, username: "grace", password: "grace-password")
    #expect(challenge.type == .verifyEmail && challenge.id == "native-verify-email")
    let params = try #require(challenge.verifyEmailParams)
    #expect(params.sent && params.emailMasked == "g***@example.com" && params.digits == 6 && params.ttl == 300 && params.resendAllowedAt != nil)

    var step = try await flow.respond(.verifyEmailResend, to: challenge)
    let tooSoon = try #require(step.challenges?.first(.verifyEmail))
    #expect(tooSoon.error?.code == ChallengeError.Code.resendTooSoon && tooSoon.verifyEmailParams?.sent == true)

    step = try await flow.respond(.verifyEmail(code: "000000"), to: tooSoon)
    let wrong = try #require(step.challenges?.first(.verifyEmail))
    #expect(wrong.error?.code == ChallengeError.Code.invalidCredential)

    step = try await flow.respond(.verifyEmail(code: "000000"), to: wrong)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["email_verified"]?.boolValue == true)
    #expect(transport.remaining == 0)
    let everything = h.observer.entries.compactMap(\.requestBody).joined()
    #expect(!everything.contains("code=0"), "the verification code is masked in the flow log")
  }

  @Test func hankDeclinesThenAcceptsTheTerms() async throws {
    // Exchanges 1-4: decline → access_denied; 5-9: accept → code → tokens (the IT's `accepted=maybe`
    // probe comes after that and is not replayed: a Bool answer cannot reproduce it).
    let (h, transport, _) = try Harness.replay(["RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin"], clientId: Self.client, range: 1...9)
    let (declining, challenge) = try await loginToRequiredAction(h, username: "hank", password: "hank-password")
    #expect(challenge.type == .terms && challenge.id == "native-terms")
    let params = try #require(challenge.termsParams)
    #expect(params.text?.hasPrefix("Demo terms") == true && params.url?.absoluteString == "https://example.com/terms" && params.version == "2026-10")

    let error = await #expect(throws: NativeAuthError.self) { try await declining.respond(.terms(accepted: false), to: challenge) }
    #expect(error?.code == NativeAuthError.Code.accessDenied)
    #expect(error?.errorDescription?.contains("required_action:TERMS_AND_CONDITIONS") == true && error?.errorDescription?.contains("declined") == true)
    let state = await declining.currentState
    #expect(state == .finished)

    let (accepting, again) = try await loginToRequiredAction(h, username: "hank", password: "hank-password")
    let step = try await accepting.respond(.terms(accepted: true), to: again)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "hank")
    #expect(transport.remaining == 0)
  }

  // MARK: - Recovery codes (spec/03 §4.8, spec/14 D2)

  private func ivySecondFactor(_ h: Harness) async throws -> (NativeLoginFlow, [Challenge]) {
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("ivy"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("ivy-password"), to: try #require(step.challenges?.first(.password)))
    return (flow, try #require(step.challenges))
  }

  @Test func ivyUsesARecoveryCodeInsteadOfTheTotp() async throws {
    // Exchanges 1-6: [totp, recovery_code], a wrong code, then a code in display format → tokens.
    let (h, transport, _) = try Harness.replay(["RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"], clientId: Self.client, range: 1...6)
    let (flow, set) = try await ivySecondFactor(h)
    #expect(set.types == ["totp", "recovery_code"] && set[1].required == false)
    let recovery = try #require(set.first(.recoveryCode))
    #expect(recovery.recoveryCodeParams?.remaining == 3 && recovery.recoveryCodeParams?.warningThreshold == 4 && recovery.recoveryCodeParams?.shouldWarn == true)
    var step = try await flow.respond(.recoveryCode("IVY9-IVY9-IVY9"), to: recovery)
    let wrong = try #require(step.challenges?.first(.recoveryCode))
    #expect(wrong.error?.code == ChallengeError.Code.invalidCredential && wrong.recoveryCodeParams?.remaining == 3)
    step = try await flow.respond(.recoveryCode("ivy1-ivy1-ivy1"), to: wrong)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "ivy")
    let logged = h.observer.entries.compactMap(\.requestBody).joined()
    #expect(!logged.contains("IVY9") && !logged.contains("ivy1"), "recovery codes are masked in the flow log")
    #expect(transport.remaining == 0)
  }

  @Test func ivyUsedCodeIsRefusedAndTheCountGoesDown() async throws {
    // Exchanges 7-10: the second login shows remaining 2 and refuses the code used before (the IT's
    // second successful code was not exchanged, so the replay stops there).
    let (h, transport, _) = try Harness.replay(["RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"], clientId: Self.client, range: 7...10)
    let (flow, set) = try await ivySecondFactor(h)
    let recovery = try #require(set.first(.recoveryCode))
    #expect(recovery.recoveryCodeParams?.remaining == 2)
    let step = try await flow.respond(.recoveryCode("IVY1IVY1IVY1"), to: recovery)
    #expect(step.challenges?.first(.recoveryCode)?.error?.code == ChallengeError.Code.invalidCredential)
    #expect(transport.remaining == 0)
  }

  @Test func ivyLastRecoveryCodeHandsTheLoginToTheBrowser() async throws {
    let (h, transport, _) = try Harness.replay(["RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut"], clientId: Self.client, range: 12...18)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("ivy"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("ivy-password"), to: try #require(step.challenges?.first(.password)))
    let recovery = try #require(step.challenges?.first(.recoveryCode))
    #expect(recovery.recoveryCodeParams?.remaining == 1)
    step = try await flow.respond(.recoveryCode("IVY3IVY3IVY3"), to: recovery)
    guard case .redirectToWeb(let request) = step else { Issue.record("expected redirect_to_web, got \(step)"); return }
    #expect(request.reason == "required_action:CONFIGURE_RECOVERY_AUTHN_CODES")

    let again = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await again.start()
    step = try await again.respond(.username("ivy"), to: try #require(step.challenges?.first(.username)))
    step = try await again.respond(.password("ivy-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.challenges?.types == ["totp"], "no code left: the alternative is gone")
    #expect(transport.remaining == 0)
  }

  // MARK: - Enrol on first login (spec/14 D4), SMS webhook (spec/14 D5), idle-timeout auth_session (spec/14 D6)

  @Test func bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin() async throws {
    let (h, transport, t) = try Harness.replay(["EnrolOnFirstLoginIT.bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin"], clientId: Self.client)
    h.passkeys.enqueue(PasskeyAttestation(form: t[0].form(4)))
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    #expect(step.challenges?.types == ["password"], "no passkey yet: the password is the only primary factor")
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let registration = try #require(step.challenges?.first(.passkeyRegistration))
    #expect(registration.id == "native-passkey-register" && registration.required && registration.type.isRequiredAction)
    let params = try #require(registration.passkeyRegistrationParams)
    #expect(params.user.name == "bob")
    step = try await flow.respond(.passkeyRegistration(try await h.sdk.passkeys().register(params), label: "Bob's phone"), to: registration)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "bob")

    // The next login offers the new passkey beside the password.
    let again = h.sdk.authentication().startLogin(Self.itParameters)
    step = try await again.start()
    step = try await again.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    #expect(step.challenges?.types == ["passkey", "password"] && step.challenges?.first(.passkey)?.passkeyParams?.discoverable == false)
    #expect(transport.remaining == 0)
  }

  @Test func bobGetsAnSmsCodeThroughTheWebhook() async throws {
    let (h, transport, _) = try Harness.replay(["SmsOtpIT.bobGetsAnSmsCodeThroughTheWebhook"], clientId: "demo-native-sms")
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let otp = try #require(step.challenges?.first(.otp))
    let params = try #require(otp.otpParams)
    #expect(otp.required && params.channel == "sms" && params.destinationMasked == "***23" && params.sent)
    step = try await flow.respond(.otp("000000"), to: otp)
    let wrong = try #require(step.challenges?.first(.otp))
    #expect(wrong.error?.code == ChallengeError.Code.invalidCredential && wrong.otpParams?.sent == true)
    step = try await flow.respond(.otp("000000"), to: wrong)
    #expect(step.credentials?.accessTokenClaims?["preferred_username"]?.stringValue == "bob")
    #expect(transport.remaining == 0)
  }

  @Test func postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive() async throws {
    // 1-4: login + exchange; 5: a refresh keeps the session alive; 6: the step-up with the expired
    // post-login auth_session is invalid_session (the IT's final refresh, 7, is not replayed).
    let (h, transport, _) = try Harness.replay(["StepUpIT.postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive"], clientId: Phase2ReplayTests.stepUpClient, range: 1...6)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    let credentials = try #require(step.credentials)
    let refreshed = try await h.sdk.tokens().refresh(credentials)
    #expect(refreshed.authSession == credentials.authSession, "a refresh does not renew the post-login auth_session")
    let stepUp = try await h.sdk.authentication().stepUp(LoginParameters(scope: "openid profile", acrValues: "2", deviceName: "NativeAuthIT"), authSession: refreshed.authSession)
    let error = await #expect(throws: NativeAuthError.self) { try await stepUp.start() }
    #expect(error?.code == NativeAuthError.Code.invalidSession, "the idle timeout passed: log in again (spec/14 D6)")
    #expect(transport.remaining == 0)
  }

  @Test func answersCarryTheRightFields() {
    #expect(ChallengeAnswer.updatePassword("a", confirm: "b").formFields.map(\.name) == ["password", "password_confirm"])
    #expect(ChallengeAnswer.verifyEmail(code: "1").formFields.map { "\($0.name)=\($0.value)" } == ["code=1"])
    #expect(ChallengeAnswer.verifyEmailResend.formFields.map { "\($0.name)=\($0.value)" } == ["action=resend"])
    #expect(ChallengeAnswer.terms(accepted: true).formFields.map { "\($0.name)=\($0.value)" } == ["accepted=true"])
    #expect(ChallengeAnswer.terms(accepted: false).challengeType == .terms && ChallengeAnswer.verifyEmailResend.challengeType == .verifyEmail)
  }
}
