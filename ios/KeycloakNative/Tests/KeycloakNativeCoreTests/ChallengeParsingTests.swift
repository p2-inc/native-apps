import Foundation
import Testing
@testable import KeycloakNativeCore

@Suite struct ChallengeParsingTests {
  private func response(_ status: Int, _ json: JSONValue) -> HTTPResponse {
    ScriptedTransport.json(status, json)
  }

  @Test func unknownChallengeTypesAreKeptAsUnknown() throws {
    let outcome = try ChallengeEndpointClient.parse(response(403, [
      "error": "insufficient_authorization", "auth_session": "s",
      "challenges": [
        ["type": "x-vendor-foo", "id": "1", "required": true, "params": ["k": "v"]],
        ["type": "password", "id": "2", "required": false],
        ["id": "no-type"],
      ],
    ]))
    guard case .challenges(let set) = outcome else { Issue.record("expected challenges"); return }
    #expect(set.challenges.count == 2, "descriptors without type/id are dropped")
    #expect(set.challenges[0].type == .unknown("x-vendor-foo"))
    #expect(set.challenges[0].type.isSupported == false)
    #expect(set.challenges[0].params["k"]?.stringValue == "v")
    #expect(set.challenges[1].type == .password && set.challenges[1].required == false)
    #expect(FlowStep.challenges(set.challenges, .empty).supportedChallenges.types == ["password"])
  }

  @Test func http400IsToleratedForInsufficientAuthorization() throws {
    let outcome = try ChallengeEndpointClient.parse(response(400, [
      "error": "insufficient_authorization", "auth_session": "s", "expires_in": 12,
      "challenges": [["type": "username", "id": "e1"]], "context": ["client_name": "Demo"],
    ]))
    guard case .challenges(let set) = outcome else { Issue.record("expected challenges"); return }
    #expect(set.authSession == "s" && set.expiresIn == 12 && set.context.clientName == "Demo")
  }

  @Test func successBodyYieldsCodeAndPostLoginSession() throws {
    let outcome = try ChallengeEndpointClient.parse(response(200, ["authorization_code": "c", "auth_session": "post"]))
    guard case .authorizationCode(let code, let session) = outcome else { Issue.record("expected code"); return }
    #expect(code == "c" && session == "post")
  }

  @Test func errorsKeepServerCodeAndOptionalAuthSession() {
    #expect(throws: NativeAuthError.self) { try ChallengeEndpointClient.parse(response(200, ["foo": "bar"])) }

    let invalidRequest = #expect(throws: NativeAuthError.self) {
      try ChallengeEndpointClient.parse(response(400, ["error": "invalid_request", "error_description": "bad", "auth_session": "still"]))
    }
    #expect(invalidRequest?.code == "invalid_request")
    #expect(invalidRequest?.authSession == "still" && invalidRequest?.authSessionStillValid == true)
    #expect(invalidRequest?.statusCode == 400)

    let redirect = #expect(throws: NativeAuthError.self) {
      try ChallengeEndpointClient.parse(response(403, ["error": "redirect_to_web", "request_uri": "urn:x", "expires_in": 90]))
    }
    #expect(redirect?.code == NativeAuthError.Code.redirectToWeb)
    #expect(redirect?.details?["request_uri"]?.stringValue == "urn:x")

    let slowDown = #expect(throws: NativeAuthError.self) {
      try ChallengeEndpointClient.parse(HTTPResponse(statusCode: 429, headers: ["Content-Type": "application/json", "Retry-After": "7"], body: Data(#"{"error":"slow_down"}"#.utf8)))
    }
    #expect(slowDown?.isRetryable == true && slowDown?.retryAfter == 7)

    let notJSON = #expect(throws: NativeAuthError.self) {
      try ChallengeEndpointClient.parse(HTTPResponse(statusCode: 502, headers: [:], body: Data("<html>".utf8)))
    }
    #expect(notJSON?.code == NativeAuthError.Code.invalidResponse && notJSON?.statusCode == 502)
  }

  @Test func typedParamsDecodeSnakeCase() throws {
    let passkey = try #require(Challenge(json: [
      "type": "passkey", "id": "e", "label": "Sign in", "required": false,
      "error": ["code": "invalid_credential", "message": "nope"], "retry": ["remaining": 2],
      "params": [
        "challenge": "AQID", "rp_id": "localhost", "timeout": 60000, "user_verification": "required",
        "allow_credentials": [["type": "public-key", "id": "BAUG", "transports": ["internal", "hybrid"]]], "discoverable": false,
      ],
    ]))
    let p = try #require(passkey.passkeyParams)
    #expect(p.rpId == "localhost" && p.timeoutMilliseconds == 60000 && p.userVerification == "required")
    #expect(p.challengeData == Data([1, 2, 3]))
    #expect(p.allowCredentials.first?.idData == Data([4, 5, 6]))
    #expect(p.allowCredentials.first?.transports == ["internal", "hybrid"])
    #expect(p.discoverable == false)
    #expect(passkey.error?.code == "invalid_credential" && passkey.retry?.remaining == 2 && passkey.label == "Sign in")

    let registration = try #require(Challenge(json: [
      "type": "passkey_registration", "id": "native-passkey-register",
      "params": [
        "challenge": "AQID", "rp": ["id": "localhost", "name": "Demo"], "user": ["id": "dXNlcg", "name": "dave", "display_name": "Dave E"],
        "pub_key_cred_params": [["type": "public-key", "alg": -7], ["type": "public-key", "alg": -257]],
        "authenticator_selection": ["resident_key": "required", "require_resident_key": true, "user_verification": "required"],
        "attestation": "none", "exclude_credentials": [["type": "public-key", "id": "BAUG"]], "timeout": 60000,
      ],
    ]))
    let r = try #require(registration.passkeyRegistrationParams)
    #expect(r.rp.id == "localhost" && r.rp.name == "Demo")
    #expect(r.user.name == "dave" && r.user.displayName == "Dave E" && r.user.idData == Data("user".utf8))
    #expect(r.pubKeyCredParams == [-7, -257])
    #expect(r.residentKey == "required" && r.requireResidentKey && r.userVerification == "required")
    #expect(r.excludeCredentials == ["BAUG"] && r.attestation == "none")

    let totp = try #require(Challenge(json: ["type": "totp", "id": "t", "params": ["digits": 6, "period": 30, "algorithm": "HmacSHA1", "credential_labels": ["Phone"], "credentials": [["id": "c1", "label": "Phone"]]]]))
    #expect(totp.totpParams?.credentials.first?.id == "c1" && totp.totpParams?.digits == 6)
    #expect(totp.passkeyParams == nil)
  }

  @Test func answersProduceWireFields() {
    #expect(ChallengeAnswer.totp("123456", credentialId: "c1").formFields.map(\.name) == ["totp", "credential_id"])
    #expect(ChallengeAnswer.totp("123456").formFields.map(\.name) == ["totp"])
    let assertion = PasskeyAssertion(credentialId: "a", clientDataJSON: "b", authenticatorData: "c", signature: "d", userHandle: nil)
    #expect(ChallengeAnswer.passkey(assertion).formFields.map(\.name) == ["credential_id", "client_data_json", "authenticator_data", "signature"])
    let attestation = PasskeyAttestation(credentialId: "a", clientDataJSON: "b", attestationObject: "c", transports: ["internal", "hybrid"])
    let fields = ChallengeAnswer.passkeyRegistration(attestation, label: "My phone").formFields
    #expect(fields.map(\.name) == ["credential_id", "client_data_json", "attestation_object", "transports", "label"])
    #expect(fields.first { $0.name == "transports" }?.value == "internal,hybrid")
  }
}

@Suite struct MetadataTests {
  @Test func decodesRecordedMetadataAndIgnoresUnknownFields() throws {
    let transcript = try Transcript.load("NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath")
    let response = transcript.exchange(1).response
    let metadata = try NativeAuthMetadata.decode(response.httpResponse.body)
    #expect(metadata.protocolVersion == "1" && metadata.protocolMajorVersion == 1)
    #expect(metadata.fipaDraft == "draft-ietf-oauth-first-party-apps-04")
    #expect(metadata.authorizationChallengeEndpoint.path == "/realms/demo/native-auth/challenge")
    #expect(metadata.tokenEndpoint.path == "/realms/demo/protocol/openid-connect/token")
    #expect(metadata.codeExchange.redirectUriRequired == false)
    #expect(metadata.passkey?.rpId == "localhost")
    #expect(metadata.passkey?.registerFinishEndpoint?.path == "/realms/demo/native-auth/passkey/register/finish")
    #expect(Set(metadata.challengeTypesSupported) == ["otp", "passkey", "passkey_registration", "password", "totp", "username", "update_password", "verify_email", "terms", "recovery_code", "push", "push_enrollment"])
    #expect(metadata.supports(.passkey) && metadata.supports(.otp) && metadata.supports(.push))
    #expect(metadata.dpopSigningAlgValuesSupported.contains("ES256"), "the challenge endpoint verifies and binds proofs (spec/13 D3)")
    #expect(metadata.authorizationEndpoint?.path == "/realms/demo/protocol/openid-connect/auth")
    #expect(metadata.clientAttestation?.required == false)
    #expect(metadata.raw?["push"] != nil && metadata.push?.deviceToken == "native" && metadata.push?.enabled == true)
  }

  @Test func minimalDocumentAndExtraFields() throws {
    let metadata = try NativeAuthMetadata.decode(Data(#"{"protocol_version":"1.2","authorization_challenge_endpoint":"https://a/c","token_endpoint":"https://a/t","push":{"enabled":true},"new_field":1}"#.utf8))
    #expect(metadata.protocolMajorVersion == 1)
    #expect(metadata.codeExchange.redirectUriRequired == false)
    #expect(metadata.passkey == nil)
    #expect(metadata.raw?["push"]?["enabled"]?.boolValue == true)
  }
}
