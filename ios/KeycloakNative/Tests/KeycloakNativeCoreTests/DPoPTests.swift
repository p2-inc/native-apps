import CryptoKit
import Foundation
import Testing
@testable import KeycloakNativeCore

@Suite struct DPoPTests {
  @Test func proofHasRfc9449ShapeAndVerifiableSignature() throws {
    let key = SoftwareDPoPKey()
    let builder = DPoPProofBuilder(key: key)
    let issuedAt = Date(timeIntervalSince1970: 1_760_000_000)
    let proof = try builder.proof(method: "post", url: URL(string: "https://idp.example.com:8443/realms/demo/protocol/openid-connect/token?x=1#frag")!, issuedAt: issuedAt, jti: "abc")

    let parts = proof.split(separator: ".").map(String.init)
    #expect(parts.count == 3)
    let headerData = try #require(Base64URL.decode(parts[0]))
    let header = try #require(JSONValue(jsonData: headerData))
    #expect(header["typ"]?.stringValue == "dpop+jwt")
    #expect(header["alg"]?.stringValue == "ES256")
    #expect(header["jwk"]?["kty"]?.stringValue == "EC")
    #expect(header["jwk"]?["x"]?.stringValue == key.publicJWK.x)
    #expect(header["jwk"]?["d"] == nil, "private material never leaves the key")

    let payloadData = try #require(Base64URL.decode(parts[1]))
    let payload = try #require(JSONValue(jsonData: payloadData))
    #expect(payload["htm"]?.stringValue == "POST")
    #expect(payload["htu"]?.stringValue == "https://idp.example.com:8443/realms/demo/protocol/openid-connect/token")
    #expect(payload["iat"]?.intValue == 1_760_000_000)
    #expect(payload["jti"]?.stringValue == "abc")
    #expect(payload["ath"] == nil)
    #expect(payload["nonce"] == nil)

    // Verify with CryptoKit from the JWK alone.
    let x = try #require(Base64URL.decode(header["jwk"]!["x"]!.stringValue!))
    let y = try #require(Base64URL.decode(header["jwk"]!["y"]!.stringValue!))
    let publicKey = try P256.Signing.PublicKey(rawRepresentation: x + y)
    let signature = try P256.Signing.ECDSASignature(rawRepresentation: try #require(Base64URL.decode(parts[2])))
    #expect(publicKey.isValidSignature(signature, for: Data((parts[0] + "." + parts[1]).utf8)))
  }

  /// RFC 9449 §7.1: `ath` for the example access token.
  @Test func accessTokenHashAndNonce() throws {
    let builder = DPoPProofBuilder(key: SoftwareDPoPKey())
    let proof = try builder.proof(method: "GET", url: URL(string: "https://resource.example.org/protectedresource")!, accessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", nonce: "eyJ7S_zG.eyJH0-Z.HX4w-7v")
    let payloadData = try #require(Base64URL.decode(String(proof.split(separator: ".")[1])))
    let payload = try #require(JSONValue(jsonData: payloadData))
    #expect(payload["ath"]?.stringValue == "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo")
    #expect(payload["nonce"]?.stringValue == "eyJ7S_zG.eyJH0-Z.HX4w-7v")
    #expect(payload["htu"]?.stringValue == "https://resource.example.org/protectedresource")
  }

  @Test func softwareKeyPersistsAndRestores() throws {
    let key = SoftwareDPoPKey()
    let restored = try SoftwareDPoPKey(rawRepresentation: key.rawRepresentation)
    #expect(restored.publicJWK == key.publicJWK)
  }

  @Test func signerCreatesOnceAndReloadsFromStore() async throws {
    let store = InMemorySecureStore()
    let signer = DPoPSigner(mode: .software, store: store, storeKey: "k", logger: NoopLogger())
    let jwk1 = try await signer.publicJWK()
    let again = DPoPSigner(mode: .software, store: store, storeKey: "k", logger: NoopLogger())
    let jwk2 = try await again.publicJWK()
    #expect(jwk1 == jwk2)
    #expect(store.keys == ["k"])
    let disabled = DPoPSigner(mode: .disabled, store: store, storeKey: "d", logger: NoopLogger())
    let none = try await disabled.proof(method: "POST", url: URL(string: "https://x/y")!, accessToken: nil)
    #expect(none == nil)
  }

  @Test func automaticModeFallsBackToSoftwareWithoutSecureEnclave() async throws {
    let store = InMemorySecureStore()
    let signer = DPoPSigner(mode: .automatic, store: store, storeKey: "k", logger: NoopLogger())
    let proof = try #require(try await signer.proof(method: "POST", url: URL(string: "https://x/y")!, accessToken: nil))
    #expect(proof.split(separator: ".").count == 3)
    let stored = try #require(try store.data(forKey: "k"))
    let persisted = try #require(JSONValue(jsonData: stored))
    #expect(persisted["kind"]?.stringValue == (SecureEnclaveDPoPKey.isAvailable ? "secure_enclave" : "software"))
  }

  @Test func nonceChallengeDetection() {
    let response = ScriptedTransport.json(400, ["error": "use_dpop_nonce"], headers: ["DPoP-Nonce": "n1"])
    #expect(DPoPSigner.nonceChallenge(in: response) == "n1")
    #expect(DPoPSigner.nonceChallenge(in: ScriptedTransport.json(400, ["error": "invalid_request"])) == nil)
  }

  @Test func tokenRequestRetriesOnceWithServerNonce() async throws {
    let transport = ScriptedTransport([
      { _ in ScriptedTransport.json(400, ["error": "use_dpop_nonce"], headers: ["DPoP-Nonce": "server-nonce"]) },
      { request in
        let proof = request.header("DPoP")!
        let payload = JSONValue(jsonData: Base64URL.decode(String(proof.split(separator: ".")[1]))!)!
        #expect(payload["nonce"]?.stringValue == "server-nonce")
        return ScriptedTransport.json(200, ["access_token": "t", "token_type": "DPoP", "expires_in": 60])
      },
    ])
    let issuer = URL(string: "https://idp.example.com/realms/demo")!
    let metadataTransport = ScriptedTransport { _ in
      ScriptedTransport.json(200, [
        "protocol_version": "1",
        "authorization_challenge_endpoint": "https://idp.example.com/realms/demo/native-auth/challenge",
        "token_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/token",
      ])
    }
    let metadata = MetadataClient(issuer: issuer, transport: metadataTransport, ttl: 60)
    let signer = DPoPSigner(mode: .software, store: InMemorySecureStore(), storeKey: "k", logger: NoopLogger())
    let tokens = Tokens(clientId: "c", issuer: issuer, metadata: metadata, transport: transport, dpop: signer, logger: NoopLogger())
    let credentials = try await tokens.exchange(code: "code", codeVerifier: "v")
    #expect(credentials.isDPoPBound)
    #expect(credentials.authorizationScheme == "DPoP")
    #expect(transport.sent.count == 2)
  }
}
