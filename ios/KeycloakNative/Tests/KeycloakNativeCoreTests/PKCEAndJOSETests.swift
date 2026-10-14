import CryptoKit
import Foundation
import Testing
@testable import KeycloakNativeCore

@Suite struct PKCETests {
  @Test func rfc7636AppendixBVector() {
    let pkce = PKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    #expect(pkce.challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    #expect(PKCE.method == "S256")
  }

  @Test func generatedVerifiersAre43CharsAndUnique() {
    let a = PKCE.generate()
    let b = PKCE.generate()
    #expect(a.verifier.count == 43)
    #expect(a.verifier != b.verifier)
    #expect(a.verifier.allSatisfy { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".contains($0) })
  }
}

@Suite struct Base64URLTests {
  @Test func rfc4648Vectors() {
    let vectors: [(String, String)] = [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")]
    for (plain, encoded) in vectors {
      #expect(Base64URL.encode(plain) == encoded)
      #expect(Base64URL.decode(encoded) == Data(plain.utf8))
    }
  }

  @Test func usesUrlSafeAlphabetWithoutPadding() {
    let bytes = Data([0xfb, 0xff, 0xbf, 0x3e, 0x3f])
    let encoded = Base64URL.encode(bytes)
    #expect(!encoded.contains("+") && !encoded.contains("/") && !encoded.contains("="))
    #expect(Base64URL.decode(encoded) == bytes)
    #expect(Base64URL.decode(bytes.base64EncodedString()) == bytes, "padded standard input is accepted")
    #expect(Base64URL.decode("a") == nil)
    #expect(Base64URL.decode("not*valid") == nil)
  }
}

@Suite struct JWKTests {
  /// RFC 9449 §4.1 example key; its thumbprint is the `jkt` used throughout that RFC (§6.1).
  @Test func rfc7638ThumbprintOfRfc9449ExampleKey() {
    let jwk = ECPublicJWK(x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
    #expect(jwk.thumbprint == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
  }

  @Test func jwkFromCryptoKitKeyRoundTrips() throws {
    let key = P256.Signing.PrivateKey()
    let jwk = ECPublicJWK(publicKey: key.publicKey)
    #expect(jwk.kty == "EC" && jwk.crv == "P-256")
    let x = try #require(Base64URL.decode(jwk.x))
    let y = try #require(Base64URL.decode(jwk.y))
    let raw = x + y
    #expect(raw == key.publicKey.rawRepresentation)
  }

  @Test func unverifiedJwtPayloadDecoding() {
    let payload = Base64URL.encode("{\"sub\":\"alice\",\"exp\":1760000000}")
    let jwt = "eyJhbGciOiJub25lIn0.\(payload).sig"
    #expect(JWT.decodePayload(jwt)?["sub"]?.stringValue == "alice")
    #expect(JWT.decodePayload(jwt)?["exp"]?.intValue == 1_760_000_000)
    #expect(JWT.decodeHeader(jwt)?["alg"]?.stringValue == "none")
    #expect(JWT.decodePayload("garbage") == nil)
  }
}

@Suite struct FormEncodingTests {
  @Test func encodesReservedCharacters() {
    let data = FormEncoding.encode([("username", "al ice+&=/é"), ("empty", "")])
    #expect(String(data: data, encoding: .utf8) == "username=al%20ice%2B%26%3D%2F%C3%A9&empty=")
  }

  @Test func decodeRoundTripsAndAcceptsPlus() {
    let fields = FormEncoding.decode(FormEncoding.encode([("a", "x y"), ("b", "1&2")]))
    #expect(fields.map(\.name) == ["a", "b"])
    #expect(fields.map(\.value) == ["x y", "1&2"])
    #expect(FormEncoding.decode(Data("a=x+y".utf8)).first?.value == "x y")
  }
}

@Suite struct JSONValueTests {
  @Test func decodesAndNavigates() throws {
    let json = try #require(JSONValue(jsonString: #"{"a":[1,2,{"b":true}],"s":"x","n":null,"f":1.5}"#))
    #expect(json["a"]?[2]?["b"]?.boolValue == true)
    #expect(json["a"]?[0]?.intValue == 1)
    #expect(json["f"]?.intValue == nil)
    #expect(json["n"]?.isNull == true)
    #expect(json["s"]?.stringValue == "x")
    #expect(json["missing"] == nil)
    #expect(json.serialized() == #"{"a":[1,2,{"b":true}],"f":1.5,"n":null,"s":"x"}"#)
  }
}
