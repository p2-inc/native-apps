import Foundation
import Testing
@testable import KeycloakNativeCore

/// Additions to v1.0-rc (spec/03 §2.3, §3.3, §4.11): `skip` for optional required actions, `custom`
/// answers, and extra request fields, replayed from EnrolOnFirstLoginIT and ExtensionParametersIT.
@Suite(.serialized) struct ProtocolAdditionsReplayTests {
  static let client = TranscriptReplayTests.demoIOS
  static let itParameters = TranscriptReplayTests.itParameters

  private func bobUpToRegistration(_ flow: NativeLoginFlow) async throws -> Challenge {
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    let challenges = try #require(step.challenges)
    #expect(challenges.count == 1 && challenges[0].type == .passkeyRegistration)
    return challenges[0]
  }

  // MARK: - skip (spec/03 §4.11)

  @Test func anOptionalEnrolmentIsSkippedAndOfferedAgain() async throws {
    let (h, transport, _) = try Harness.replay(["EnrolOnFirstLoginIT.bobMayDeclineAnOptionalEnrolmentAndIsOfferedItAgainAtTheNextLogin"], clientId: Self.client)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    let offer = try await bobUpToRegistration(flow)
    #expect(offer.isSkippable)

    let step = try await flow.respond(.skip(offer.type), to: offer)
    let credentials = try #require(step.credentials, "a skip completes the login like any other answer")
    #expect(credentials.accessTokenClaims?["preferred_username"]?.stringValue == "bob")

    let again = try await bobUpToRegistration(h.sdk.authentication().startLogin(Self.itParameters))
    #expect(again.isSkippable, "the next login offers it again")
    #expect(transport.remaining == 0)
  }

  @Test func aMandatoryEnrolmentIsNotSkippableAndTheSDKRefusesLocally() async throws {
    let (h, transport, _) = try Harness.replay(["EnrolOnFirstLoginIT.aMandatoryEnrolmentIsNotSkippableAndRefusesSkip"], clientId: Self.client, range: 1...4)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    let registration = try await bobUpToRegistration(flow)
    #expect(!registration.isSkippable)
    let local = await #expect(throws: NativeAuthError.self) { try await flow.respond(.skip(.passkeyRegistration), to: registration) }
    #expect(local?.code == NativeAuthError.Code.flowState)
    #expect(transport.remaining == 1, "nothing was sent")

    // A custom answer goes out as-is; the server refuses the skip and the session survives.
    let sent = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.custom(type: .passkeyRegistration, fields: [FormField("action", "skip")]), to: registration)
    }
    #expect(sent?.code == NativeAuthError.Code.invalidRequest)
    #expect(await flow.currentState == .awaitingAnswer)
    #expect(transport.remaining == 0)
  }

  // MARK: - extra fields (spec/03 §2.3)

  @Test func extraFieldsGoOutOnTheInitialAndContinuationRequestsAndAreMasked() async throws {
    let (h, transport, _) = try Harness.replay(["ExtensionParametersIT.extensionParametersAreAcceptedOnEveryRequest"], clientId: Self.client)
    let parameters = LoginParameters(
      scope: "openid profile", additionalParameters: ["x_device_signal": "a1b2c3d4"], continuationParameters: ["x_risk_score": "12"])
    let flow = h.sdk.authentication().startLogin(parameters)
    var step = try await flow.start()
    step = try await flow.respond(.username("bob"), to: try #require(step.challenges?.first(.username)), additionalFields: ["x_device_signal": "a1b2c3d4"])
    step = try await flow.respond(.password("bob-password"), to: try #require(step.challenges?.first(.password)))
    #expect(step.credentials != nil)
    #expect(transport.remaining == 0)
    let log = h.observer.entries.compactMap(\.requestBody).joined(separator: "\n")
    #expect(log.contains("x_device_signal=***") && !log.contains("a1b2c3d4"), "x_ values never reach the flow log")
  }

  @Test func extraFieldsMayNotOverrideProtocolOrAnswerFields() throws {
    let existing: [(name: String, value: String)] = [("auth_session", "s"), ("challenge_type", "username"), ("challenge_id", "e"), ("username", "bob")]
    for name in ["auth_session", "client_id", "action", "username", ""] {
      #expect(throws: NativeAuthError.self, "\(name) is refused") { try NativeLoginFlow.extraFields([name: "x"], after: existing) }
    }
    let ok = try NativeLoginFlow.extraFields(["x_b": "2", "x_a": "1"], after: existing)
    #expect(ok.map(\.name) == ["x_a", "x_b"], "sent in key order")
  }

  @Test func aCustomAnswerMayNotSetTheContinuationFields() async throws {
    let (h, _, _) = try Harness.replay(["EnrolOnFirstLoginIT.aMandatoryEnrolmentIsNotSkippableAndRefusesSkip"], clientId: Self.client, range: 1...3)
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    let registration = try await bobUpToRegistration(flow)
    let error = await #expect(throws: NativeAuthError.self) {
      try await flow.respond(.custom(type: .passkeyRegistration, fields: [FormField("challenge_id", "other")]), to: registration)
    }
    #expect(error?.code == NativeAuthError.Code.invalidParameter)
  }
}
