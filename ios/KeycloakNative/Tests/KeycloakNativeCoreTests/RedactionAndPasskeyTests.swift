import AuthenticationServices
import Foundation
import Testing
@testable import KeycloakNativeCore

@Suite struct RedactionTests {
  @Test func formJsonAndHeaderRedaction() {
    let form = Redactor.redact(form: [("username", "alice"), ("password", "secret"), ("totp", "123456"), ("auth_session", "eyJ")])
    #expect(form.map(\.value) == ["alice", "***", "***", "***"])
    // Phase 2b fields: the new password pair, the e-mail verification code, recovery codes.
    let phase2b = Redactor.redact(form: [("password_confirm", "secret"), ("code", "123456"), ("recovery_code", "ABCD-EFGH"), ("accepted", "true")])
    #expect(phase2b.map(\.value) == ["***", "***", "***", "true"])
    for answer: ChallengeAnswer in [.updatePassword("s3cret", confirm: "s3cret"), .verifyEmail(code: "123456"), .terms(accepted: true)] {
      for field in Redactor.redact(form: answer.formFields) where field.name != "accepted" {
        #expect(field.value == "***", "\(field.name) must be masked")
      }
    }
    let json = Redactor.redact(json: ["authorization_code": "c", "auth_session": "s", "challenges": [["params": ["signature": "x", "rp_id": "localhost"]]], "access_token": "t"])
    #expect(json["authorization_code"]?.stringValue == "***")
    #expect(json["auth_session"]?.stringValue == "***")
    #expect(json["access_token"]?.stringValue == "***")
    #expect(json["challenges"]?[0]?["params"]?["signature"]?.stringValue == "***")
    #expect(json["challenges"]?[0]?["params"]?["rp_id"]?.stringValue == "localhost")
    #expect(Redactor.redact(headers: ["Authorization": "Bearer abc", "DPoP": "eyJ", "Accept": "application/json"]) == ["Authorization": "Bearer ***", "DPoP": "***", "Accept": "application/json"])
  }

  @Test func flowLogNeverContainsSecrets() async throws {
    let transport = ScriptedTransport { _ in
      ScriptedTransport.json(200, ["authorization_code": "CODE-SECRET", "auth_session": "SESSION-SECRET"])
    }
    let h = Harness(issuer: URL(string: "https://idp.example.com/realms/demo")!, clientId: "c", transport: transport)
    let client = ChallengeEndpointClient(endpoint: URL(string: "https://idp.example.com/realms/demo/native-auth/challenge")!, transport: h.sdk.transport, dpop: nil, logger: h.logger)
    _ = try await client.post([("auth_session", "SESSION-SECRET"), ("challenge_type", "password"), ("challenge_id", "e"), ("password", "PASSWORD-SECRET")])
    let entry = try #require(h.observer.entries.first)
    let everything = (entry.requestBody ?? "") + (entry.responseBody ?? "") + h.logger.lines.joined()
    for secret in ["PASSWORD-SECRET", "SESSION-SECRET", "CODE-SECRET"] {
      #expect(!everything.contains(secret), "\(secret) leaked")
    }
    #expect(entry.requestBody?.contains("challenge_type=password") == true)
    #expect(entry.statusCode == 200)
  }
}

@Suite struct PasskeyBridgeTests {
  @Test func cancellationIsPasskeyCancelledAndLeavesTheFlowPending() async throws {
    let transport = ScriptedTransport([
      { _ in ScriptedTransport.json(200, ["protocol_version": "1", "authorization_challenge_endpoint": "https://idp.example.com/realms/demo/native-auth/challenge", "token_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/token", "passkey": ["rp_id": "idp.example.com"]]) },
      { _ in ScriptedTransport.json(403, ["error": "insufficient_authorization", "auth_session": "s", "challenges": [["type": "passkey", "id": "p", "required": false, "params": ["challenge": "AQID", "rp_id": "idp.example.com", "allow_credentials": [], "discoverable": true]], ["type": "username", "id": "u", "required": false]]]) },
    ])
    let h = Harness(issuer: URL(string: "https://idp.example.com/realms/demo")!, clientId: "c", transport: transport)
    let flow = h.sdk.authentication().startLogin()
    let step = try await flow.start()
    let passkey = try #require(step.challenges?.first(.passkey))

    h.passkeys.fail(with: AuthorizationBridge.map(ASAuthorizationError(.canceled)))
    let error = await #expect(throws: NativeAuthError.self) {
      try await h.sdk.passkeys().assert(try #require(passkey.passkeyParams))
    }
    #expect(error?.code == NativeAuthError.Code.passkeyCancelled)
    let state = await flow.currentState
    #expect(state == .awaitingAnswer, "the user can still pick another challenge")
    let pending = await flow.pendingChallenges.types
    #expect(pending == ["passkey", "username"])
    #expect(transport.sent.count == 2, "no request was made for the cancelled ceremony")
    #expect(h.passkeys.assertParams.first?.discoverable == true)
  }

  @Test func asAuthorizationErrorMapping() {
    #expect(AuthorizationBridge.map(ASAuthorizationError(.canceled)).code == "passkey_cancelled")
    #expect(AuthorizationBridge.map(ASAuthorizationError(.failed)).code == "passkey_failed")
    #expect(AuthorizationBridge.map(ASAuthorizationError(.notInteractive)).code == "passkey_unavailable")
    #expect(AuthorizationBridge.map(NativeAuthError(code: "x")).code == "x")
  }

  @Test func rpIdMustBeIssuerHostOrParentDomain() async throws {
    func passkeys(issuer: String, allow: Bool = false) -> Passkeys {
      Harness(issuer: URL(string: issuer)!, clientId: "c", transport: ScriptedTransport { _ in HTTPResponse(statusCode: 500) }, allowRpIdMismatch: allow).sdk.passkeys()
    }
    #expect(throws: Never.self) { try passkeys(issuer: "https://idp.example.com/realms/demo").checkRpId("idp.example.com") }
    #expect(throws: Never.self) { try passkeys(issuer: "https://idp.example.com/realms/demo").checkRpId("example.com") }
    #expect(throws: Never.self) { try passkeys(issuer: "http://localhost:8089/realms/demo").checkRpId("localhost") }
    let mismatch = #expect(throws: NativeAuthError.self) { try passkeys(issuer: "https://idp.example.com/realms/demo").checkRpId("other.example") }
    #expect(mismatch?.code == NativeAuthError.Code.rpIdMismatch)
    #expect(throws: NativeAuthError.self) { try passkeys(issuer: "https://idp.example.com/realms/demo").checkRpId("ple.com") }
    #expect(throws: Never.self) { try passkeys(issuer: "http://localhost:8089/realms/demo", allow: true).checkRpId("demo.ngrok.app") }
  }

  @Test func registrationParamsReachThePlatformAndTransportsAreSent() async throws {
    let h = Harness(issuer: URL(string: "https://idp.example.com/realms/demo")!, clientId: "c", transport: ScriptedTransport { _ in HTTPResponse(statusCode: 500) })
    let attestation = PasskeyAttestation(credentialId: "id", clientDataJSON: "cd", attestationObject: "ao", transports: ["internal", "hybrid"])
    h.passkeys.enqueue(attestation)
    let params = try #require(PasskeyRegistrationParams(json: ["challenge": "AQID", "rp": ["id": "idp.example.com"], "user": ["id": "dXNlcg", "name": "alice"]]))
    let result = try await h.sdk.passkeys().register(params)
    #expect(result == attestation)
    #expect(h.passkeys.registerParams.first?.user.name == "alice")
    #expect(attestation.jsonFields["transports"]?.stringArray == ["internal", "hybrid"])
  }
}
