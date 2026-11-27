package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.AndroidOriginIT.setExtraOrigins;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.challengeId;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.flatten;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Browser clients (the web SDK, spec/22): CORS on the native endpoint for the client's Web Origins,
 * and passkeys whose origin is the single-page app's, allowed through the Passwordless policy's extra
 * origins. Client {@code demo-web} lists {@code http://localhost:5173}. Not recorded as transcripts:
 * the exchanges are the same as {@code demo-native}'s, and the {@code Origin} header is not part of
 * the contract the SDKs replay.
 */
class WebClientIT {

  static final String WEB_CLIENT = "demo-web";
  static final String WEB_ORIGIN = "http://localhost:5173";
  static final String OTHER_ORIGIN = "https://evil.example";

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static Response challenge(String origin, Map<String, String> form) {
    return given()
        .header("Origin", origin)
        .accept("application/json")
        .contentType("application/x-www-form-urlencoded; charset=UTF-8")
        .formParams(form)
        .post(realmUrl() + "/native-auth/challenge")
        .andReturn();
  }

  static Response start(String origin, Pkce pkce) {
    return challenge(
        origin,
        params(
            "client_id", WEB_CLIENT,
            "response_type", "code",
            "scope", "openid profile",
            "code_challenge", pkce.challenge(),
            "code_challenge_method", "S256"));
  }

  static Response answer(String origin, Response previous, String type, String... fields) {
    Map<String, String> p =
        params(
            "auth_session", previous.jsonPath().getString("auth_session"),
            "challenge_type", type,
            "challenge_id", challengeId(previous, type));
    for (int i = 0; i < fields.length; i += 2) p.put(fields[i], fields[i + 1]);
    return challenge(origin, p);
  }

  static Response exchange(String origin, String code, Pkce pkce) {
    return given()
        .header("Origin", origin)
        .formParam("grant_type", "authorization_code")
        .formParam("client_id", WEB_CLIENT)
        .formParam("code", code)
        .formParam("code_verifier", pkce.verifier())
        .post(realmUrl() + "/protocol/openid-connect/token")
        .andReturn();
  }

  static void assertCors(Response r, String origin) {
    assertEquals(origin, r.header("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin on " + r.asString());
    assertNull(r.header("Access-Control-Allow-Credentials"), "no credentials: the endpoint uses no cookies");
    assertTrue(r.header("Access-Control-Expose-Headers").contains("DPoP-Nonce"));
  }

  @Test
  void aPreflightIsAnsweredForTheChallengeEndpoint() {
    Response r =
        given()
            .header("Origin", WEB_ORIGIN)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type, dpop")
            .options(realmUrl() + "/native-auth/challenge")
            .andReturn();
    assertEquals(204, r.statusCode(), r.asString());
    assertEquals(WEB_ORIGIN, r.header("Access-Control-Allow-Origin"));
    assertTrue(r.header("Access-Control-Allow-Methods").contains("POST"));
    assertTrue(r.header("Access-Control-Allow-Headers").contains("DPoP"));
    assertNull(r.header("Access-Control-Allow-Credentials"));
  }

  @Test
  void metadataIsReadableFromAnyOrigin() {
    Response r = given().header("Origin", OTHER_ORIGIN).get(realmUrl() + "/native-auth/metadata").andReturn();
    assertEquals(200, r.statusCode());
    assertEquals("*", r.header("Access-Control-Allow-Origin"));
  }

  @Test
  void aWebOriginSignsInAndReadsEveryResponse() {
    Pkce pkce = Pkce.s256();
    Response r = start(WEB_ORIGIN, pkce);
    assertChallenge(r, "username");
    assertCors(r, WEB_ORIGIN);
    r = answer(WEB_ORIGIN, r, "username", "username", "alice");
    assertCors(r, WEB_ORIGIN);
    r = answer(WEB_ORIGIN, r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    assertCors(r, WEB_ORIGIN);
    r = answer(WEB_ORIGIN, r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    assertCors(r, WEB_ORIGIN);

    // Keycloak's token endpoint answers the same origin from the client's Web Origins.
    Response tokens = exchange(WEB_ORIGIN, r.jsonPath().getString("authorization_code"), pkce);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals(WEB_ORIGIN, tokens.header("Access-Control-Allow-Origin"));
  }

  @Test
  void anOriginTheClientDoesNotListGetsNoCorsHeaders() {
    Response r = start(OTHER_ORIGIN, Pkce.s256());
    assertChallenge(r, "username");
    assertNull(r.header("Access-Control-Allow-Origin"), "the browser must not let evil.example read the answer");

    // demo-native lists no Web Origins: a browser on the web client's origin cannot use it either.
    Response nativeClient =
        challenge(
            WEB_ORIGIN,
            params(
                "client_id", NativeAuthIT.CLIENT,
                "response_type", "code",
                "code_challenge", Pkce.s256().challenge(),
                "code_challenge_method", "S256"));
    assertEquals(403, nativeClient.statusCode());
    assertNull(nativeClient.header("Access-Control-Allow-Origin"));
  }

  @Test
  void anErrorWithoutAKnownClientIsReadableByARegisteredOrigin() {
    // An auth_session that no longer decodes names no client: the origin is checked against every
    // native-auth client of the realm, so the SDK sees invalid_session instead of a network error.
    Response r = challenge(WEB_ORIGIN, params("auth_session", "not-a-session", "challenge_type", "username", "challenge_id", "x"));
    assertEquals(400, r.statusCode(), r.asString());
    assertEquals("invalid_session", r.jsonPath().getString("error"));
    assertCors(r, WEB_ORIGIN);

    Response other = challenge(OTHER_ORIGIN, params("auth_session", "not-a-session", "challenge_type", "username", "challenge_id", "x"));
    assertNull(other.header("Access-Control-Allow-Origin"));
  }

  @Test
  void aPasskeyFromTheSinglePageAppsOriginRegistersAndSignsIn() {
    // The browser reports the page's origin (http://localhost:5173) in clientDataJSON; the RP ID stays
    // the realm's (localhost), a registrable suffix of the page's host.
    setExtraOrigins(WEB_ORIGIN);
    try {
      Pkce pkce = Pkce.s256();
      Response r = start(WEB_ORIGIN, pkce);
      r = answer(WEB_ORIGIN, r, "username", "username", "bob");
      r = answer(WEB_ORIGIN, r, "password", "password", "bob-password");
      assertEquals(200, r.statusCode(), r.asString());
      String token = exchange(WEB_ORIGIN, r.jsonPath().getString("authorization_code"), pkce).jsonPath().getString("access_token");

      Response options =
          given().header("Origin", WEB_ORIGIN).header("Authorization", "Bearer " + token).accept("application/json")
              .post(realmUrl() + "/native-auth/passkey/register/options").andReturn();
      assertEquals(200, options.statusCode(), options.asString());
      assertCors(options, WEB_ORIGIN);
      JsonPath o = options.jsonPath();
      SoftwareAuthenticator browser = new SoftwareAuthenticator(o.getString("rp.id"), WEB_ORIGIN);
      Map<String, String> body = new LinkedHashMap<>(browser.register(o.getString("challenge"), o.getString("user.id")));
      body.put("registration_id", o.getString("registration_id"));
      body.put("label", "Browser");
      Response finish = PasskeyIT.registerFinish(token, body);
      assertEquals(201, finish.statusCode(), finish.asString());

      Pkce login = Pkce.s256();
      r = start(WEB_ORIGIN, login);
      r = answer(WEB_ORIGIN, r, "username", "username", "bob");
      List<String> offered = r.jsonPath().getList("challenges.type");
      assertTrue(offered.contains("passkey"), "passkey offered: " + offered);
      r = answer(WEB_ORIGIN, r, "passkey", flatten(browser.assertion(passkeyChallenge(r))));
      assertEquals(200, r.statusCode(), r.asString());
      assertNotNull(r.jsonPath().getString("authorization_code"));

      // Without the page's origin in the policy the same assertion is refused.
      setExtraOrigins();
      pauseForQuickLoginWindow();
      r = start(WEB_ORIGIN, Pkce.s256());
      r = answer(WEB_ORIGIN, r, "username", "username", "bob");
      r = answer(WEB_ORIGIN, r, "passkey", flatten(browser.assertion(passkeyChallenge(r))));
      assertEquals("invalid_credential", errorCode(r, "passkey"), r.asString());
    } finally {
      setExtraOrigins();
      EnrolOnFirstLoginIT.deletePasskeys("bob");
    }
  }

  @SuppressWarnings("unchecked")
  static String passkeyChallenge(Response r) {
    for (Map<String, Object> c : r.jsonPath().<Map<String, Object>>getList("challenges")) {
      if ("passkey".equals(c.get("type"))) return (String) ((Map<String, Object>) c.get("params")).get("challenge");
    }
    throw new AssertionError("no passkey challenge in " + r.asString());
  }
}
