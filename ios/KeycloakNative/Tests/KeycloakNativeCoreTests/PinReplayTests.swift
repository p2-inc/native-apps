import Foundation
import Testing
@testable import KeycloakNativeCore

/// PIN extension contract tests (spec/03 §4.17, §4.18, spec/20 D7), replaying `PinIT`'s recorded
/// transcripts (client `demo-native-pin`: username, password, then the PIN; pia has the PIN 2580,
/// pete sets one, rita's PIN locks after 3 attempts).
@Suite(.serialized) struct PinReplayTests {
  static let client = "demo-native-pin"
  static let itParameters = TranscriptReplayTests.itParameters

  private func loginToPinStep(_ h: Harness, user: String, expecting type: ChallengeType) async throws -> (NativeLoginFlow, Challenge) {
    let flow = h.sdk.authentication().startLogin(Self.itParameters)
    var step = try await flow.start()
    step = try await flow.respond(.username(user), to: try #require(step.challenges?.first(.username)))
    step = try await flow.respond(.password(user == "rita" ? "pia-password" : "\(user)-password"), to: try #require(step.challenges?.first(.password)))
    let challenge = try #require(step.challenges?.first(type))
    #expect(step.challenges?.count == 1)
    return (flow, challenge)
  }

  @Test func metadataAdvertisesPinWhenTheExtensionIsInstalled() async throws {
    let (h, _, _) = try Harness.replay([], clientId: Self.client, metadataFrom: "PinIT.metadataAdvertisesPinWhenTheExtensionIsInstalled")
    let metadata = try await h.sdk.metadata()
    #expect(metadata.challengeTypesSupported.contains("pin") && metadata.challengeTypesSupported.contains("pin_setup"))
  }

  @Test func wireValuesAndClassification() {
    #expect(ChallengeType(wire: "pin") == .pin && ChallengeType.pin.wire == "pin")
    #expect(ChallengeType(wire: "pin_setup") == .pinSetup && ChallengeType.pinSetup.wire == "pin_setup")
    #expect(ChallengeType.pin.isSupported && ChallengeType.pinSetup.isSupported)
    #expect(!ChallengeType.pin.isRequiredAction && ChallengeType.pinSetup.isRequiredAction)
  }

  @Test func paramsDecodeWithDefaults() {
    let pin = Challenge(json: ["type": "pin", "id": "p", "params": ["length": 6]])
    #expect(pin?.pinParams?.length == 6 && pin?.pinSetupParams == nil)
    let bare = Challenge(json: ["type": "pin", "id": "p"])
    #expect(bare?.pinParams?.length == 4, "length defaults to 4")
    let setup = Challenge(json: ["type": "pin_setup", "id": "native-configure-pin", "params": ["length": 5]])
    let params = try? #require(setup?.pinSetupParams)
    #expect(params?.length == 5 && setup?.pinParams == nil)
    #expect(params?.isWellFormed("24680") == true)
    #expect(params?.isWellFormed("2468") == false && params?.isWellFormed("2468a") == false && params?.isWellFormed("２４６８０") == false)
  }

  @Test func answersCarryTheRightFields() {
    #expect(ChallengeAnswer.pin("1234").formFields.map { "\($0.name)=\($0.value)" } == ["pin=1234"])
    #expect(ChallengeAnswer.pinSetup(pin: "1357", confirm: "1358").formFields.map { "\($0.name)=\($0.value)" } == ["pin=1357", "pin_confirm=1358"])
    #expect(ChallengeAnswer.pin("1").challengeType == .pin && ChallengeAnswer.pinSetup(pin: "1", confirm: "1").challengeType == .pinSetup)
  }

  @Test func pinsAreRedacted() {
    #expect(Redactor.sensitiveKeys.isSuperset(of: ["pin", "pin_confirm"]))
    for answer: ChallengeAnswer in [.pin("1234"), .pinSetup(pin: "1357", confirm: "1357")] {
      #expect(Redactor.redact(form: answer.formFields).allSatisfy { $0.value == "***" })
    }
    #expect(Redactor.redact(json: ["params": ["length": 4]])["params"]?["length"]?.intValue == 4, "the length is not a secret")
  }

  @Test func piaSignsInWithHerPinAfterAWrongOne() async throws {
    let (h, transport, t) = try Harness.replay(["PinIT.piaSignsInWithHerPinAfterAWrongOne"], clientId: Self.client)
    let (flow, challenge) = try await loginToPinStep(h, user: "pia", expecting: .pin)
    #expect(challenge.required && challenge.pinParams?.length == 4 && challenge.error == nil && !challenge.isLocked)

    var step = try await flow.respond(.pin("0000"), to: challenge)
    let wrong = try #require(step.challenges?.first(.pin))
    #expect(wrong.error?.code == ChallengeError.Code.invalidCredential && wrong.retry?.remaining == 2 && !wrong.isLocked)

    step = try await flow.respond(.pin("2580"), to: wrong)
    let credentials = try #require(step.credentials)
    #expect(credentials.accessToken == t[0].exchange(6).response.json?["access_token"]?.stringValue)
    #expect(transport.remaining == 0)
    let everything = h.observer.entries.compactMap(\.requestBody).joined() + h.logger.lines.joined()
    #expect(!everything.contains("2580") && !everything.contains("0000"), "PINs never reach the flow log or the logger")
  }

  @Test func aLockedPinCanOnlyBeCancelled() async throws {
    let (h, transport, _) = try Harness.replay(["PinIT.aLockedPinCanOnlyBeCancelled"], clientId: Self.client)
    let (flow, challenge) = try await loginToPinStep(h, user: "rita", expecting: .pin)
    #expect(challenge.error == nil && !challenge.isLocked)

    var step = try await flow.respond(.pin("0001"), to: challenge)
    var pin = try #require(step.challenges?.first(.pin))
    #expect(pin.error?.code == ChallengeError.Code.invalidCredential && pin.retry?.remaining == 2)
    step = try await flow.respond(.pin("0002"), to: pin)
    pin = try #require(step.challenges?.first(.pin))
    #expect(pin.retry?.remaining == 1, "the last attempt")

    step = try await flow.respond(.pin("0009"), to: pin)
    let locked = try #require(step.challenges?.first(.pin))
    #expect(locked.error?.code == ChallengeError.Code.credentialLocked && locked.isLocked && locked.retry?.remaining == 0)

    await flow.cancel()
    #expect(transport.remaining == 0, "action=cancel was sent")
  }

  @Test func peteSetsAPinInBand() async throws {
    let (h, transport, _) = try Harness.replay(["PinIT.peteSetsAPinInBand"], clientId: Self.client)
    let (flow, challenge) = try await loginToPinStep(h, user: "pete", expecting: .pinSetup)
    #expect(challenge.id == "native-configure-pin" && challenge.required && challenge.type.isRequiredAction)
    #expect(challenge.pinSetupParams?.length == 4)

    var step = try await flow.respond(.pinSetup(pin: "", confirm: ""), to: challenge)
    let missing = try #require(step.challenges?.first(.pinSetup))
    #expect(missing.error?.code == ChallengeError.Code.missingCredential)

    step = try await flow.respond(.pinSetup(pin: "1357", confirm: "1358"), to: missing)
    let mismatch = try #require(step.challenges?.first(.pinSetup))
    #expect(mismatch.error?.code == ChallengeError.Code.pinMismatch)

    step = try await flow.respond(.pinSetup(pin: "1111", confirm: "1111"), to: mismatch)
    let weak = try #require(step.challenges?.first(.pinSetup))
    #expect(weak.error?.code == ChallengeError.Code.weakPin)

    step = try await flow.respond(.pinSetup(pin: "12", confirm: "12"), to: weak)
    let format = try #require(step.challenges?.first(.pinSetup))
    #expect(format.error?.code == ChallengeError.Code.invalidFormat)

    step = try await flow.respond(.pinSetup(pin: "2580", confirm: "2580"), to: format)
    #expect(step.credentials != nil)
    #expect(transport.remaining == 0)
    let everything = h.observer.entries.compactMap(\.requestBody).joined()
    #expect(!everything.contains("2580") && !everything.contains("1357"))
  }

  @Test func aPinAnswerIsRefusedForAnotherType() async throws {
    let (h, _, _) = try Harness.replay(["PinIT.peteSetsAPinInBand"], clientId: Self.client)
    let (flow, challenge) = try await loginToPinStep(h, user: "pete", expecting: .pinSetup)
    let error = await #expect(throws: NativeAuthError.self) { try await flow.respond(.pin("2580"), to: challenge) }
    #expect(error?.code == NativeAuthError.Code.unsupportedChallenge)
  }
}
