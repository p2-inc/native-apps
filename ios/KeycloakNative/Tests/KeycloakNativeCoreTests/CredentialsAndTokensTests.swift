import Foundation
import Testing
@testable import KeycloakNativeCore

@Suite struct TokensParsingTests {
  @Test func tokenResponseBecomesCredentials() throws {
    let now = Date(timeIntervalSince1970: 1_000)
    let response = ScriptedTransport.json(200, ["access_token": "a", "refresh_token": "r", "id_token": "i", "token_type": "Bearer", "expires_in": 300, "refresh_expires_in": 1800, "scope": "openid"])
    let credentials = try Tokens.parseTokenResponse(response, authSession: "s", now: now)
    #expect(credentials.accessToken == "a" && credentials.refreshToken == "r" && credentials.idToken == "i")
    #expect(credentials.expiresAt == now.addingTimeInterval(300))
    #expect(credentials.refreshExpiresAt == now.addingTimeInterval(1800))
    #expect(credentials.authSession == "s" && credentials.authorizationScheme == "Bearer")
    #expect(credentials.isExpired(at: now.addingTimeInterval(299)) == false)
    #expect(credentials.isExpired(at: now.addingTimeInterval(299), leeway: 5))
  }

  @Test func offlineRefreshTokensNeverExpire() throws {
    let response = ScriptedTransport.json(200, ["access_token": "a", "expires_in": 60, "refresh_expires_in": 0])
    #expect(try Tokens.parseTokenResponse(response, authSession: nil).refreshExpiresAt == .distantFuture)
  }

  @Test func errorsPropagateServerCodes() {
    let error = #expect(throws: NativeAuthError.self) {
      try Tokens.parseTokenResponse(ScriptedTransport.json(400, ["error": "invalid_grant", "error_description": "Code not valid"]), authSession: nil)
    }
    #expect(error?.code == "invalid_grant" && error?.errorDescription == "Code not valid")
    let stepUp = #expect(throws: NativeAuthError.self) {
      try Tokens.parseTokenResponse(ScriptedTransport.json(400, ["error": "insufficient_authorization", "auth_session": "s2"]), authSession: nil)
    }
    #expect(stepUp?.code == "insufficient_authorization" && stepUp?.authSession == "s2")
  }
}

@Suite struct CredentialsManagerTests {
  private func makeManager(store: InMemorySecureStore, transport: any Transport) -> CredentialsManager {
    let issuer = URL(string: "https://idp.example.com/realms/demo")!
    let metadata = MetadataClient(issuer: issuer, transport: ScriptedTransport { _ in
      ScriptedTransport.json(200, ["protocol_version": "1", "authorization_challenge_endpoint": "https://idp.example.com/realms/demo/native-auth/challenge", "token_endpoint": "https://idp.example.com/realms/demo/protocol/openid-connect/token"])
    }, ttl: 60)
    let tokens = Tokens(clientId: "c", issuer: issuer, metadata: metadata, transport: transport, dpop: nil, logger: NoopLogger())
    return CredentialsManager(store: store, key: "k", tokens: tokens, logger: NoopLogger())
  }

  private func credentials(expiresIn: TimeInterval) -> Credentials {
    Credentials(accessToken: "a", refreshToken: "r", idToken: nil, scope: nil, expiresAt: Date().addingTimeInterval(expiresIn), refreshExpiresAt: nil, authSession: "post")
  }

  @Test func storeRoundTripAndClear() async throws {
    let store = InMemorySecureStore()
    let manager = makeManager(store: store, transport: ScriptedTransport { _ in HTTPResponse(statusCode: 500) })
    let v1 = try await manager.stored()
    #expect(v1 == nil)
    let error = await #expect(throws: NativeAuthError.self) { try await manager.credentials() }
    #expect(error?.code == NativeAuthError.Code.credentialsNotFound)

    let credentials = credentials(expiresIn: 600)
    try await manager.store(credentials)
    let v2 = try await manager.stored()
    #expect(v2 == credentials)
    let valid500 = try await manager.hasValid(minTTL: 500)
    let valid600 = try await manager.hasValid(minTTL: 600)
    #expect(valid500 && !valid600)
    let v3 = try await manager.credentials()
    #expect(v3 == credentials, "valid credentials are returned without a network call")
    try await manager.clear()
    let v4 = try await manager.stored()
    #expect(v4 == nil)
    let v5 = try await manager.authSession()
    #expect(v5 == nil)
  }

  @Test func corruptStorageIsCleared() async throws {
    let store = InMemorySecureStore()
    try store.set(Data("garbage".utf8), forKey: "k")
    let manager = makeManager(store: store, transport: ScriptedTransport { _ in HTTPResponse(statusCode: 500) })
    let v6 = try await manager.stored()
    #expect(v6 == nil)
    #expect(try store.data(forKey: "k") == nil)
  }

  @Test func concurrentCallersShareOneRefresh() async throws {
    let store = InMemorySecureStore()
    let transport = ScriptedTransport { request in
      #expect(request.formFields?.contains { $0.name == "grant_type" && $0.value == "refresh_token" } == true)
      return ScriptedTransport.json(200, ["access_token": "new", "refresh_token": "r2", "expires_in": 300])
    }
    let manager = makeManager(store: store, transport: transport)
    try await manager.store(credentials(expiresIn: -10))
    async let a = manager.credentials()
    async let b = manager.credentials()
    async let c = manager.credentials()
    let all = try await [a, b, c]
    #expect(all.allSatisfy { $0.accessToken == "new" && $0.authSession == "post" })
    #expect(transport.sent.count == 1)
  }

  @Test func reauthenticationRequiredMapping() async throws {
    let store = InMemorySecureStore()
    let manager = makeManager(store: store, transport: ScriptedTransport { _ in ScriptedTransport.json(400, ["error": "insufficient_authorization", "auth_session": "s2"]) })
    try await manager.store(credentials(expiresIn: -10))
    let error = await #expect(throws: NativeAuthError.self) { try await manager.credentials() }
    #expect(error?.code == NativeAuthError.Code.reauthenticationRequired && error?.authSession == "s2")
    let v7 = try await manager.stored()
    #expect(v7 != nil, "kept: the server offered a step-up session")

    let gone = makeManager(store: store, transport: ScriptedTransport { _ in ScriptedTransport.json(400, ["error": "invalid_grant"]) })
    let error2 = await #expect(throws: NativeAuthError.self) { try await gone.credentials() }
    #expect(error2?.code == NativeAuthError.Code.reauthenticationRequired && error2?.authSession == nil)
    let v8 = try await gone.stored()
    #expect(v8 == nil, "cleared: the session behind the refresh token is gone")
  }

  @Test func logoutClearsEvenWhenTheServerFails() async throws {
    let store = InMemorySecureStore()
    let transport = ScriptedTransport { _ in throw NativeAuthError(code: "network_error", isNetworkError: true) }
    let manager = makeManager(store: store, transport: transport)
    try await manager.store(credentials(expiresIn: 100))
    await manager.logout()
    #expect(transport.sent.count == 1 && transport.sent.first?.url.path == "/realms/demo/protocol/openid-connect/logout")
    let v9 = try await manager.stored()
    #expect(v9 == nil)
  }
}
