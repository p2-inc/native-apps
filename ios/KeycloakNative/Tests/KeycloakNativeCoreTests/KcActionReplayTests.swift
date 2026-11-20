import Foundation
import Testing
@testable import KeycloakNativeCore

/// Application-initiated actions (spec/21): `Authentication.requiredAction(_:maxAge:)` sends
/// `kc_action` with the stored post-login `auth_session`; the flow reports `kcActionStatus` after
/// `.authorized`. Replayed from the transcripts of KcActionIT (alice on the plain `native` flow).
@Suite(.serialized) struct KcActionReplayTests {
  static let client = TranscriptReplayTests.demoIOS
  static let itParameters = TranscriptReplayTests.itParameters

  /// username → password → TOTP; the code is exchanged and the credentials stored.
  private func signIn(_ h: Harness) async throws -> Credentials {
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("alice"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    let credentials = try #require(step.credentials)
    #expect(await flow.kcActionStatus == nil, "a login without kc_action has no status")
    try await h.sdk.credentialsManager().store(credentials)
    return credentials
  }

  @Test func changingThePasswordRightAfterSigningInSignsOutOtherDevices() async throws {
    // Exchanges 1–5 are the other device's login; 6–13 are this app.
    let (h, transport, _) = try Harness.replay(["KcActionIT.aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd"], clientId: Self.client, range: 6...13)
    _ = try await signIn(h)

    let flow = try await h.sdk.authentication().requiredAction("UPDATE_PASSWORD", scope: "openid profile", deviceName: "NativeAuthIT")
    #expect(flow.isStepUp && flow.parameters.kcAction == "UPDATE_PASSWORD")
    var step = try await flow.start()
    // Within the realm's maximum authentication age: no factor, straight to the action.
    let challenge = try #require(step.challenges?.first(.updatePassword))
    #expect(step.challenges?.count == 1)
    #expect(challenge.isSkippable, "the user may cancel an action the app asked for")
    #expect(challenge.updatePasswordParams?.logoutOtherSessions == true, "offered, suggested on")

    step = try await flow.respond(.updatePassword("alice-new-password", confirm: "alice-new-password", logoutOtherSessions: true), to: challenge)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "alice")
    #expect(await flow.kcActionStatus == .success)
    #expect(transport.remaining == 0)
  }

  @Test func theRealmsMaxAuthAgeAsksForTheFactorsFirst() async throws {
    let (h, transport, _) = try Harness.replay(["KcActionIT.theRealmsMaxAuthAgeForcesReauthenticationFirst"], clientId: Self.client, range: 1...8)
    _ = try await signIn(h)
    let flow = try await h.sdk.authentication().requiredAction("UPDATE_PASSWORD", scope: "openid profile", deviceName: "NativeAuthIT")
    var step = try await flow.start()
    guard case .challenges(let set, let context) = step else { Issue.record("expected the password factor"); return }
    #expect(set.first(.password) != nil && set.first(.username) == nil, "the user is known; the factor is asked again")
    #expect(context.stepUp && context.username == "alice")
    step = try await flow.respond(.password("alice-password"), to: try #require(set.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    #expect(step.challenges?.first(.updatePassword) != nil, "then the action")
    #expect(transport.remaining == 0)
  }

  @Test func maxAgeZeroReauthenticatesAndCancellingReportsCancelled() async throws {
    let (h, transport, _) = try Harness.replay(["KcActionIT.maxAgeZeroReauthenticatesAndCancellingKeepsThePassword"], clientId: Self.client, range: 1...10)
    _ = try await signIn(h)
    let flow = try await h.sdk.authentication().requiredAction("UPDATE_PASSWORD", maxAge: 0, scope: "openid profile", deviceName: "NativeAuthIT")
    var step = try await flow.start()
    step = try await flow.respond(.password("alice-password"), to: try #require(step.challenges?.first(.password)))
    step = try await flow.respond(.totp("000000"), to: try #require(step.challenges?.first(.totp)))
    let challenge = try #require(step.challenges?.first(.updatePassword))
    step = try await flow.respond(.skip(.updatePassword), to: challenge)
    #expect(step.credentials != nil, "cancelling still signs the user in again")
    #expect(await flow.kcActionStatus == .cancelled)
    #expect(transport.remaining == 0)
  }

  @Test func anActionThatCannotBeInitiatedReportsError() async throws {
    let (h, transport, _) = try Harness.replay(["KcActionIT.anActionThatCannotBeInitiatedReportsError"], clientId: Self.client)
    _ = try await signIn(h)
    for action in ["TERMS_AND_CONDITIONS", "no-such-action"] {
      let flow = try await h.sdk.authentication().requiredAction(action, scope: "openid profile", deviceName: "NativeAuthIT")
      let step = try await flow.start()
      let credentials = try #require(step.credentials, "\(action): the code is issued anyway")
      try await h.sdk.credentialsManager().store(credentials)
      #expect(await flow.kcActionStatus == .error, "\(action)")
    }
    #expect(transport.remaining == 0)
  }

  @Test func kcActionIsReservedAndStatusParsing() throws {
    #expect(throws: NativeAuthError.self) { try NativeLoginFlow.extraFields(["kc_action": "UPDATE_PASSWORD"], after: []) }
    #expect(KcActionStatus(wire: "success") == .success && KcActionStatus(wire: "later") == .other("later"))
    #expect(ChallengeAnswer.updatePassword("a", confirm: "a", logoutOtherSessions: false).formFields.map(\.name) == ["password", "password_confirm", "logout_other_sessions"])
    #expect(ChallengeAnswer.updatePassword("a", confirm: "a").formFields.map(\.name) == ["password", "password_confirm"])
  }
}
