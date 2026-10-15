package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.utils.TimeBasedOTP;

/**
 * HTTP-level tests of the native flow against a real Keycloak (Testcontainers). Each test name is
 * referenced from spec/09-phase0-decisions.md as evidence; passkeys are covered by {@link PasskeyIT}.
 */
@ExtendWith(TranscriptRecorder.class)
class NativeAuthIT {

  static final String CLIENT = "demo-ios";
  static final String CLIENT_ALT = "demo-ios-alt";
  static final String ALICE_TOTP_SECRET = "alice-totp-secret-20261014";

  @BeforeAll
  static void start() {
    KeycloakContainerSupport.baseUrl();
  }

  @AfterAll
  static void dumpInterestingLogs() {
    KeycloakContainerSupport.logs()
        .lines()
        .filter(l -> l.contains("ERROR") || l.contains("nativeauth"))
        .limit(200)
        .forEach(System.out::println);
  }

  // ---------------------------------------------------------------------------------------------
  // helpers

  static String totp(String secret) {
    return new TimeBasedOTP("HmacSHA1", 6, 30, 1).generateTOTP(secret);
  }

  static String wrongTotp(String secret) {
    int code = Integer.parseInt(totp(secret));
    return String.format("%06d", (code + 1) % 1_000_000);
  }

  static Response start(String clientId, Pkce pkce) {
    return challenge(
        params(
            "client_id", clientId,
            "response_type", "code",
            "scope", "openid profile",
            "code_challenge", pkce.challenge(),
            "code_challenge_method", "S256",
            "device_name", "NativeAuthIT"));
  }

  static String challengeId(Response r, String type) {
    List<Map<String, Object>> challenges = r.jsonPath().getList("challenges");
    for (Map<String, Object> c : challenges) {
      if (type.equals(c.get("type"))) return (String) c.get("id");
    }
    throw new AssertionError("no '" + type + "' challenge in " + r.asString());
  }

  static Response answer(Response previous, String type, String... fields) {
    String session = previous.jsonPath().getString("auth_session");
    assertNotNull(session, "auth_session missing in " + previous.asString());
    Map<String, String> p =
        params("auth_session", session, "challenge_type", type, "challenge_id", challengeId(previous, type));
    for (int i = 0; i < fields.length; i += 2) p.put(fields[i], fields[i + 1]);
    return challenge(p);
  }

  /** Like {@link #assertChallenge} but only requires {@code type} to be offered (alice's primary-factor set gains 'passkey' once PasskeyIT registered one). */
  static void assertOffers(Response r, String type) {
    assertEquals(403, r.statusCode(), r.asString());
    assertEquals("insufficient_authorization", r.jsonPath().getString("error"), r.asString());
    assertNotNull(r.jsonPath().getString("auth_session"));
    List<String> types = r.jsonPath().getList("challenges.type");
    assertTrue(types.contains(type), "expected '" + type + "' among " + types + ": " + r.asString());
  }

  static Map<String, Object> descriptor(Response r, String type) {
    List<Map<String, Object>> challenges = r.jsonPath().getList("challenges");
    for (Map<String, Object> c : challenges) {
      if (type.equals(c.get("type"))) return c;
    }
    throw new AssertionError("no '" + type + "' challenge in " + r.asString());
  }

  @SuppressWarnings("unchecked")
  static String errorCode(Response r, String type) {
    Map<String, Object> error = (Map<String, Object>) descriptor(r, type).get("error");
    return error == null ? null : (String) error.get("code");
  }

  static void assertChallenge(Response r, String... expectedTypes) {
    assertEquals(403, r.statusCode(), r.asString());
    JsonPath j = r.jsonPath();
    assertEquals("insufficient_authorization", j.getString("error"), r.asString());
    assertEquals("1", j.getString("protocol_version"));
    assertNotNull(j.getString("auth_session"));
    assertTrue(j.getLong("expires_in") > 0);
    List<String> types = j.getList("challenges.type");
    assertEquals(List.of(expectedTypes), types, r.asString());
  }

  /** Username -> password -> (optional) TOTP; returns the final response. */
  static Response login(String clientId, Pkce pkce, String username, String password, String totpSecret) {
    Response r = start(clientId, pkce);
    assertChallenge(r, "username");
    r = answer(r, "username", "username", username);
    assertOffers(r, "password");
    assertEquals(username, r.jsonPath().getString("context.username"));
    r = answer(r, "password", "password", password);
    if (totpSecret != null) {
      assertChallenge(r, "totp");
      r = answer(r, "totp", "totp", totp(totpSecret));
    }
    return r;
  }

  static Response exchange(String clientId, String code, Pkce pkce, String redirectUri) {
    var req =
        given()
            .formParam("grant_type", "authorization_code")
            .formParam("client_id", clientId)
            .formParam("code", code)
            .formParam("code_verifier", pkce.verifier());
    if (redirectUri != null) req = req.formParam("redirect_uri", redirectUri);
    return req.post(realmUrl() + "/protocol/openid-connect/token").andReturn();
  }

  static Response refresh(String clientId, String refreshToken) {
    return given()
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", clientId)
        .formParam("refresh_token", refreshToken)
        .post(realmUrl() + "/protocol/openid-connect/token")
        .andReturn();
  }

  static Response revoke(String clientId, String token, String hint) {
    return given()
        .formParam("client_id", clientId)
        .formParam("token", token)
        .formParam("token_type_hint", hint)
        .post(realmUrl() + "/protocol/openid-connect/revoke")
        .andReturn();
  }

  static Response logout(String clientId, String refreshToken) {
    return given()
        .formParam("client_id", clientId)
        .formParam("refresh_token", refreshToken)
        .post(realmUrl() + "/protocol/openid-connect/logout")
        .andReturn();
  }

  static JsonPath claims(String jwt) {
    String payload = jwt.split("\\.")[1];
    return JsonPath.from(new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8));
  }

  /** Partial realm update: Keycloak only touches the fields present in the representation. */
  static void updateRealm(String partialRepresentationJson) {
    given()
        .auth()
        .oauth2(adminToken())
        .contentType("application/json")
        .body(partialRepresentationJson)
        .put(adminRealmUrl())
        .then()
        .statusCode(204);
  }

  /** A PUT with {@code attributes} replaces the whole map, so read-modify-write it. */
  static void setRealmAttribute(String name, String value) {
    Map<String, String> attributes =
        given().auth().oauth2(adminToken()).get(adminRealmUrl()).then().statusCode(200).extract().jsonPath().getMap("attributes");
    Map<String, String> updated = new java.util.LinkedHashMap<>(attributes);
    updated.put(name, value);
    StringBuilder json = new StringBuilder("{\"attributes\": {");
    boolean first = true;
    for (Map.Entry<String, String> e : updated.entrySet()) {
      if (!first) json.append(',');
      first = false;
      json.append('"').append(e.getKey().replace("\"", "\\\"")).append("\": \"")
          .append(String.valueOf(e.getValue()).replace("\"", "\\\"")).append('"');
    }
    json.append("}}");
    updateRealm(json.toString());
  }

  /**
   * Keycloak's brute-force detector treats two failures of one user within
   * quickLoginCheckMilliSeconds (1 s) as an attack and locks the account for a minute. Tests that
   * provoke a failure on purpose wait that window out first so they stay independent of ordering.
   */
  static void pauseForQuickLoginWindow() {
    try {
      Thread.sleep(1100);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  static void setRealmField(String name, int value) {
    updateRealm("{\"" + name + "\": " + value + "}");
  }

  // ---------------------------------------------------------------------------------------------
  // Q3: endpoint path & metadata

  @Test
  void metadataIsServedUnderRealmNativeAuthPath() {
    given()
        .get(realmUrl() + "/native-auth/metadata")
        .then()
        .statusCode(200)
        .header("Cache-Control", containsString("no-store"))
        .body("protocol_version", equalTo("1"))
        .body("fipa_draft", equalTo("draft-ietf-oauth-first-party-apps-04"))
        .body("authorization_challenge_endpoint", equalTo(realmUrl() + "/native-auth/challenge"))
        .body("token_endpoint", equalTo(realmUrl() + "/protocol/openid-connect/token"))
        .body("code_exchange.redirect_uri_required", equalTo(false))
        .body("challenge_types_supported", hasItems("username", "password", "totp", "passkey", "passkey_registration"))
        .body("passkey.rp_id", equalTo("localhost"))
        .body("passkey.register_options_endpoint", equalTo(realmUrl() + "/native-auth/passkey/register/options"))
        .body("passkey.register_finish_endpoint", equalTo(realmUrl() + "/native-auth/passkey/register/finish"))
        .body("client_attestation.required", equalTo(false));
  }

  // ---------------------------------------------------------------------------------------------
  // Happy path + Q1 (code stored without redirect_uri, token request omits it)

  @Test
  void happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri() throws Exception {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    assertEquals(200, r.statusCode(), r.asString());
    String code = r.jsonPath().getString("authorization_code");
    assertNotNull(code);
    assertTrue(code.split("\\.").length == 3, "Keycloak code format id.userSessionId.clientUUID: " + code);

    Response tokens = exchange(CLIENT, code, pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    String accessToken = tokens.jsonPath().getString("access_token");
    assertNotNull(tokens.jsonPath().getString("refresh_token"));
    assertNotNull(tokens.jsonPath().getString("id_token"));
    JsonPath claims = claims(accessToken);
    assertEquals("alice", claims.getString("preferred_username"));
    assertEquals(CLIENT, claims.getString("azp"));
    assertEquals(realmUrl(), claims.getString("iss"));

    // Code is single use.
    assertEquals(400, exchange(CLIENT, code, pkce, null).statusCode());

    // Exit criterion "events show in the admin console": a LOGIN event tagged native_protocol=1.
    String token = adminToken();
    List<Map<String, Object>> events =
        given().auth().oauth2(token).queryParam("type", "LOGIN").queryParam("user", claims.getString("sub"))
            .get(adminRealmUrl() + "/events").then().statusCode(200).extract().jsonPath().getList("$");
    assertTrue(
        events.stream().anyMatch(e -> "1".equals(((Map<?, ?>) e.get("details")).get("native_protocol"))),
        "expected a LOGIN event with native_protocol=1, got " + events);
  }

  @Test
  void q1_sentinelModeRejectsTokenRequestWithoutRedirectUri() {
    setRealmAttribute("native-auth.code-redirect-uri-mode", "sentinel");
    try {
      given().get(realmUrl() + "/native-auth/metadata").then()
          .body("code_exchange.redirect_uri_required", equalTo(true))
          .body("code_exchange.redirect_uri", equalTo("urn:keycloak:native-auth"));

      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
      assertEquals(200, r.statusCode(), r.asString());
      String code = r.jsonPath().getString("authorization_code");
      // Keycloak compares the stored value with the parameter: omitting it fails, matching it works.
      Response noRedirect = exchange(CLIENT, code, pkce, null);
      assertEquals(400, noRedirect.statusCode(), noRedirect.asString());
      assertEquals("invalid_grant", noRedirect.jsonPath().getString("error"));
    } finally {
      setRealmAttribute("native-auth.code-redirect-uri-mode", "none");
    }
  }

  @Test
  void q1_sentinelModeRoundTrip() {
    setRealmAttribute("native-auth.code-redirect-uri-mode", "sentinel");
    try {
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
      assertEquals(200, r.statusCode(), r.asString());
      Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, "urn:keycloak:native-auth");
      assertEquals(200, tokens.statusCode(), tokens.asString());
    } finally {
      setRealmAttribute("native-auth.code-redirect-uri-mode", "none");
    }
  }

  @Test
  void q1_noneModeAlsoToleratesAnyRedirectUriParameter() {
    // Documented side effect of storing null: AuthorizationCodeGrantType skips the comparison entirely.
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, "demoapp://auth/callback");
    assertEquals(200, tokens.statusCode(), tokens.asString());
  }

  @Test
  void pkceVerifierIsEnforced() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), Pkce.s256(), null);
    assertEquals(400, tokens.statusCode(), tokens.asString());
    assertEquals("invalid_grant", tokens.jsonPath().getString("error"));
  }

  @Test
  void passwordOnlyUserSkipsConditionalSecondFactor() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "bob", "bob-password", null);
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }

  // ---------------------------------------------------------------------------------------------
  // Failure branches

  @Test
  void wrongPasswordRechallengesWithErrorDescriptorThenSucceeds() {
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "alice");
    String firstPasswordId = challengeId(r, "password");

    pauseForQuickLoginWindow();
    r = answer(r, "password", "password", "wrong-password");
    assertOffers(r, "password");
    assertEquals("invalid_credential", errorCode(r, "password"), r.asString());
    assertNotNull(((Map<?, ?>) descriptor(r, "password").get("error")).get("message"));
    assertEquals(firstPasswordId, challengeId(r, "password"), "same execution is re-challenged");
    boolean single = r.jsonPath().getList("challenges").size() == 1;
    assertEquals(single, descriptor(r, "password").get("required"), "required iff it is the only alternative");

    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    assertEquals(null, r.jsonPath().getString("challenges[0].error"));
  }

  @Test
  void wrongTotpRechallengesThenSucceeds() {
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "alice");
    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    assertEquals(6, r.jsonPath().getInt("challenges[0].params.digits"));
    assertEquals(30, r.jsonPath().getInt("challenges[0].params.period"));
    assertEquals(List.of("Phone"), r.jsonPath().getList("challenges[0].params.credential_labels"));

    pauseForQuickLoginWindow();
    r = answer(r, "totp", "totp", wrongTotp(ALICE_TOTP_SECRET));
    assertChallenge(r, "totp");
    assertEquals("invalid_credential", r.jsonPath().getString("challenges[0].error.code"));

    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    assertNotNull(r.jsonPath().getString("authorization_code"));
  }

  @Test
  void emptyPasswordRechallengesWithoutCountingAFailure() {
    Response r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "alice");
    r = answer(r, "password", "password", "");
    assertOffers(r, "password");
    assertEquals("missing_credential", errorCode(r, "password"));
  }

  @Test
  void unknownUsernameGetsAPhantomPasswordChallengeThatLocksLikeARealAccount() {
    // spec/03 §4.1: an unknown user cannot be told from a real one with a wrong password — the same
    // [password] set, the same invalid_credential + retry.remaining countdown, the same lock-out
    // after failureFactor (5) attempts. Nothing is sent that could lead anywhere.
    Response r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "nobody-" + System.nanoTime());
    assertChallenge(r, "password");
    assertEquals(true, descriptor(r, "password").get("required"));
    assertEquals(true, ((Map<?, ?>) descriptor(r, "password").get("params")).get("username_known"));
    assertEquals(null, r.jsonPath().getString("context.username"));
    assertNull(errorCode(r, "password"));

    r = answer(r, "password", "password", "");
    assertEquals("missing_credential", errorCode(r, "password"));

    for (int attempt = 1; attempt <= 4; attempt++) {
      r = answer(r, "password", "password", "wrong-" + attempt);
      assertChallenge(r, "password");
      assertEquals("invalid_credential", errorCode(r, "password"), r.asString());
      assertEquals(5 - attempt, r.jsonPath().getInt("challenges[0].retry.remaining"), r.asString());
    }
    r = answer(r, "password", "password", "wrong-5");
    assertEquals(403, r.statusCode(), r.asString());
    assertEquals("access_denied", r.jsonPath().getString("error"));
    assertTrue(r.jsonPath().getString("error_description").toLowerCase().contains("locked"), r.asString());
  }

  @Test
  void invalidAuthSessionValuesAreRejectedWithInvalidSession() {
    Response garbage = challenge(params("auth_session", "not-a-jwe", "challenge_type", "username", "challenge_id", "x"));
    assertEquals(400, garbage.statusCode(), garbage.asString());
    assertEquals("invalid_session", garbage.jsonPath().getString("error"));
    assertEquals(null, garbage.jsonPath().getString("auth_session"));

    Response r = start(CLIENT, Pkce.s256());
    String session = r.jsonPath().getString("auth_session");
    String[] parts = session.split("\\.");
    char c = parts[3].charAt(0);
    parts[3] = (c == 'A' ? 'B' : 'A') + parts[3].substring(1);
    Response tampered =
        challenge(params("auth_session", String.join(".", parts), "challenge_type", "username", "challenge_id", challengeId(r, "username"), "username", "alice"));
    assertEquals(400, tampered.statusCode(), tampered.asString());
    assertEquals("invalid_session", tampered.jsonPath().getString("error"));
  }

  @Test
  void cancelledAuthSessionCannotBeReused() {
    Response r = start(CLIENT, Pkce.s256());
    String session = r.jsonPath().getString("auth_session");
    Response cancel = challenge(params("auth_session", session, "action", "cancel"));
    assertEquals(400, cancel.statusCode(), cancel.asString());
    assertEquals("invalid_session", cancel.jsonPath().getString("error"));

    Response reuse = challenge(params("auth_session", session, "challenge_type", "username", "challenge_id", challengeId(r, "username"), "username", "alice"));
    assertEquals(400, reuse.statusCode(), reuse.asString());
    assertEquals("invalid_session", reuse.jsonPath().getString("error"));
  }

  @Test
  void expiredAuthSessionIsRejectedWithInvalidSession() throws Exception {
    setRealmField("accessCodeLifespanLogin", 1);
    try {
      Response r = start(CLIENT, Pkce.s256());
      assertChallenge(r, "username");
      assertTrue(r.jsonPath().getLong("expires_in") <= 1);
      Thread.sleep(2500);
      Response late = answer(r, "username", "username", "alice");
      assertEquals(400, late.statusCode(), late.asString());
      assertEquals("invalid_session", late.jsonPath().getString("error"));
    } finally {
      setRealmField("accessCodeLifespanLogin", 1800);
    }
  }

  @Test
  void unknownChallengeIdIsInvalidRequestAndSessionSurvives() {
    Response r = start(CLIENT, Pkce.s256());
    String session = r.jsonPath().getString("auth_session");

    Response unknown = challenge(params("auth_session", session, "challenge_type", "username", "challenge_id", "00000000-0000-0000-0000-000000000000", "username", "alice"));
    assertEquals(400, unknown.statusCode(), unknown.asString());
    assertEquals("invalid_request", unknown.jsonPath().getString("error"));
    assertNotNull(unknown.jsonPath().getString("auth_session"), "session remains valid, auth_session echoed");

    // Right id, wrong type.
    Response mismatch = challenge(params("auth_session", unknown.jsonPath().getString("auth_session"), "challenge_type", "password", "challenge_id", challengeId(r, "username"), "password", "x"));
    assertEquals(400, mismatch.statusCode(), mismatch.asString());
    assertEquals("invalid_request", mismatch.jsonPath().getString("error"));

    // Answering an execution that is not pending yet (password before username) is also invalid_request.
    // The session is still usable afterwards:
    Response ok = challenge(params("auth_session", mismatch.jsonPath().getString("auth_session"), "challenge_type", "username", "challenge_id", challengeId(r, "username"), "username", "alice"));
    assertOffers(ok, "password");
  }

  @Test
  void missingOrUnknownClientIsRejected() {
    Response noClient = challenge(params("response_type", "code"));
    assertEquals(400, noClient.statusCode());
    assertEquals("invalid_request", noClient.jsonPath().getString("error"));

    Response unknown = challenge(params("client_id", "does-not-exist", "response_type", "code"));
    assertEquals(401, unknown.statusCode());
    assertEquals("invalid_client", unknown.jsonPath().getString("error"));

    Response notEnabled = challenge(params("client_id", "web-app", "response_type", "code"));
    assertEquals(401, notEnabled.statusCode());
    assertEquals("invalid_client", notEnabled.jsonPath().getString("error"));

    Response noPkce = challenge(params("client_id", CLIENT, "response_type", "code"));
    assertEquals(400, noPkce.statusCode());
    assertEquals("invalid_request", noPkce.jsonPath().getString("error"));
  }

  // carol's pending UPDATE_PASSWORD (a non-native required action) is covered by RedirectToWebIT.

  // ---------------------------------------------------------------------------------------------
  // Token lifecycle after a native login (standard Keycloak endpoints; fixtures for the SDK's Tokens client)

  @Test
  void tokensCanBeRefreshedLoggedOutAndRevoked() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "bob", "bob-password", null);
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());

    Response refreshed = refresh(CLIENT, tokens.jsonPath().getString("refresh_token"));
    assertEquals(200, refreshed.statusCode(), refreshed.asString());
    assertNotNull(refreshed.jsonPath().getString("access_token"));
    assertNotNull(refreshed.jsonPath().getString("refresh_token"));
    assertEquals("bob", claims(refreshed.jsonPath().getString("access_token")).getString("preferred_username"));

    // RP-initiated logout with the refresh token ends the session: a further refresh is refused.
    Response loggedOut = logout(CLIENT, refreshed.jsonPath().getString("refresh_token"));
    assertEquals(204, loggedOut.statusCode(), loggedOut.asString());
    Response afterLogout = refresh(CLIENT, refreshed.jsonPath().getString("refresh_token"));
    assertEquals(400, afterLogout.statusCode(), afterLogout.asString());
    assertEquals("invalid_grant", afterLogout.jsonPath().getString("error"));

    // RFC 7009 revocation of the refresh token has the same effect.
    pkce = Pkce.s256();
    r = login(CLIENT, pkce, "bob", "bob-password", null);
    tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    String refreshToken = tokens.jsonPath().getString("refresh_token");
    Response revoked = revoke(CLIENT, refreshToken, "refresh_token");
    assertEquals(200, revoked.statusCode(), revoked.asString());
    Response afterRevoke = refresh(CLIENT, refreshToken);
    assertEquals(400, afterRevoke.statusCode(), afterRevoke.asString());
    assertEquals("invalid_grant", afterRevoke.jsonPath().getString("error"));
  }

  // ---------------------------------------------------------------------------------------------
  // Brute force (spec/06 S14): repeated wrong passwords end with access_denied

  @Test
  void bruteForceLockEndsWithAccessDenied() {
    // erin exists only for this scenario; the lock lasts a minute. failureFactor is 5 in the demo
    // realm, and two failures within quickLoginCheckMilliSeconds lock even earlier, so at most 6
    // attempts are needed whichever rule fires first.
    Response r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "erin");
    assertChallenge(r, "password");
    boolean locked = false;
    Integer previousRemaining = null;
    for (int attempt = 1; attempt <= 6 && !locked; attempt++) {
      r = answer(r, "password", "password", "wrong-password-" + attempt);
      if (r.statusCode() == 403 && "access_denied".equals(r.jsonPath().getString("error"))) {
        locked = true;
        assertTrue(r.jsonPath().getString("error_description").toLowerCase().contains("locked"), r.asString());
        assertNull(r.jsonPath().getString("auth_session"), "the session is gone after a terminal failure");
      } else {
        assertOffers(r, "password");
        assertEquals("invalid_credential", errorCode(r, "password"), r.asString());
        // spec/03 §3.3 retry.remaining counts down from failureFactor - 1 (the lock may come earlier
        // through the quick-login rule, which the counter does not model).
        int remaining = r.jsonPath().getInt("challenges[0].retry.remaining");
        assertTrue(remaining >= 0 && remaining <= 5 - attempt, "remaining " + remaining + " after attempt " + attempt);
        if (previousRemaining != null) assertTrue(remaining < previousRemaining, r.asString());
        previousRemaining = remaining;
      }
    }
    assertTrue(locked, "expected access_denied within 6 attempts, last response: " + r.asString());

    // A new login for the locked account must not reveal it: the username step answers with the
    // same phantom password challenge an unknown user gets (spec/03 §4.1).
    r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "erin");
    assertChallenge(r, "password");
    assertNull(errorCode(r, "password"), r.asString());
    assertEquals(null, r.jsonPath().getString("context.username"));
  }

  // ---------------------------------------------------------------------------------------------
  // Q2: several ALTERNATIVE executions in one challenges[] set

  @Test
  void q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered() {
    // password + totp are ALTERNATIVE siblings in the 'native-alternatives' flow bound to demo-ios-alt.
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_ALT, pkce);
    r = answer(r, "username", "username", "alice");
    assertChallenge(r, "password", "totp");
    assertEquals(false, r.jsonPath().getBoolean("challenges[0].required"));
    assertEquals(false, r.jsonPath().getBoolean("challenges[1].required"));
    assertNotEquals(challengeId(r, "password"), challengeId(r, "totp"));

    // Answer the second alternative (not the one the engine considers "current").
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT_ALT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());

    // And the first one, after a failed attempt on the second keeps both on offer.
    pkce = Pkce.s256();
    r = start(CLIENT_ALT, pkce);
    r = answer(r, "username", "username", "alice");
    pauseForQuickLoginWindow();
    r = answer(r, "totp", "totp", wrongTotp(ALICE_TOTP_SECRET));
    // Flow order (password before totp in the subflow) is kept; the error sits on the failed entry (spec/11 D3).
    assertChallenge(r, "password", "totp");
    assertEquals("invalid_credential", errorCode(r, "totp"));
    assertNull(errorCode(r, "password"));
    r = answer(r, "password", "password", "alice-password");
    assertEquals(200, r.statusCode(), r.asString());
  }

  @Test
  void q2_alternativesAreFilteredByConfiguredCredentials() {
    Response r = start(CLIENT_ALT, Pkce.s256());
    r = answer(r, "username", "username", "bob");
    assertChallenge(r, "password");
    assertEquals(true, r.jsonPath().getBoolean("challenges[0].required"));
  }
}
