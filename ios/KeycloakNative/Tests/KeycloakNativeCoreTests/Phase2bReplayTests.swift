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

  @Test func answersCarryTheRightFields() {
    #expect(ChallengeAnswer.updatePassword("a", confirm: "b").formFields.map(\.name) == ["password", "password_confirm"])
    #expect(ChallengeAnswer.verifyEmail(code: "1").formFields.map { "\($0.name)=\($0.value)" } == ["code=1"])
    #expect(ChallengeAnswer.verifyEmailResend.formFields.map { "\($0.name)=\($0.value)" } == ["action=resend"])
    #expect(ChallengeAnswer.terms(accepted: true).formFields.map { "\($0.name)=\($0.value)" } == ["accepted=true"])
    #expect(ChallengeAnswer.terms(accepted: false).challengeType == .terms && ChallengeAnswer.verifyEmailResend.challengeType == .verifyEmail)
  }
}
