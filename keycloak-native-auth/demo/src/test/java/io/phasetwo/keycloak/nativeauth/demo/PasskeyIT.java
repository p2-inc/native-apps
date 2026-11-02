package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertOffers;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.setRealmAttribute;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Phase 1 passkey tests (spec/03 §4.3, §4.4, §6; spec/11). A {@link SoftwareAuthenticator} plays the
 * platform authenticator; test names are referenced from spec/11-phase1-decisions.md.
 */
@ExtendWith(TranscriptRecorder.class)
class PasskeyIT {

  static final String CLIENT_PASSKEY = "demo-ios-passkey";

  /** alice's passkey, registered once through the authenticated endpoints and shared by the tests. */
  private static SoftwareAuthenticator alicePasskey;

  @BeforeAll
  static void startContainer() {
    baseUrl();
    // Register alice's passkey up front (own transcript) so no test's transcript depends on order.
    TranscriptRecorder.scenario("PasskeyIT.setupAlicePasskey", PasskeyIT::alicePasskey);
  }

  @AfterAll
  static void restore() {
    forgetAlicePasskey();
  }

  // ---------------------------------------------------------------------------------------------
  // helpers

  static String origin() {
    return baseUrl();
  }

  static String accessTokenAfterPasswordTotpLogin() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    return tokens.jsonPath().getString("access_token");
  }

  static Response registerOptions(String accessToken) {
    return given().header("Authorization", "Bearer " + accessToken).accept("application/json").post(realmUrl() + "/native-auth/passkey/register/options").andReturn();
  }

  static Response registerFinish(String accessToken, Map<String, String> body) {
    StringBuilder json = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String, String> e : body.entrySet()) {
      if (!first) json.append(',');
      first = false;
      json.append('"').append(e.getKey()).append("\":\"").append(e.getValue().replace("\"", "\\\"")).append('"');
    }
    json.append('}');
    return given()
        .header("Authorization", "Bearer " + accessToken)
        .contentType("application/json")
        .accept("application/json")
        .body(json.toString())
        .post(realmUrl() + "/native-auth/passkey/register/finish")
        .andReturn();
  }

  /** Registers alice's passkey through §6 once; later tests reuse it. */
  static synchronized SoftwareAuthenticator alicePasskey() {
    if (alicePasskey == null) {
      String token = accessTokenAfterPasswordTotpLogin();
      Response options = registerOptions(token);
      assertEquals(200, options.statusCode(), options.asString());
      JsonPath o = options.jsonPath();
      SoftwareAuthenticator authenticator = new SoftwareAuthenticator(o.getString("rp.id"), origin());
      Map<String, String> created = authenticator.register(o.getString("challenge"), o.getString("user.id"));
      Map<String, String> body = new LinkedHashMap<>(created);
      body.put("registration_id", o.getString("registration_id"));
      body.put("label", "Test iPhone");
      Response finish = registerFinish(token, body);
      assertEquals(201, finish.statusCode(), finish.asString());
      alicePasskey = authenticator;
    }
    return alicePasskey;
  }

  /**
   * Deletes alice's passkeys and forgets the shared authenticator. Every class that registers it calls
   * this when done: the IT classes run in file-system order, and a passkey left behind would add a
   * {@code passkey} alternative to alice's challenge sets in later classes and their transcripts.
   */
  static synchronized void forgetAlicePasskey() {
    EnrolOnFirstLoginIT.deletePasskeys("alice");
    alicePasskey = null;
  }

  static List<Map<String, Object>> credentials(String username) {
    String token = adminToken();
    String userId =
        given().auth().oauth2(token).queryParam("username", username).queryParam("exact", true)
            .get(adminRealmUrl() + "/users").then().statusCode(200).extract().jsonPath().getString("[0].id");
    return given().auth().oauth2(token).get(adminRealmUrl() + "/users/" + userId + "/credentials").then().statusCode(200).extract().jsonPath().getList("$");
  }

  static String[] flatten(Map<String, String> fields) {
    List<String> kv = new ArrayList<>();
    fields.forEach((k, v) -> { kv.add(k); kv.add(v); });
    return kv.toArray(new String[0]);
  }

  // ---------------------------------------------------------------------------------------------
  // §6 authenticated registration

  @Test
  void registerThroughAuthenticatedEndpointsAfterPasswordTotpLogin() {
    String token = accessTokenAfterPasswordTotpLogin();
    Response options = registerOptions(token);
    assertEquals(200, options.statusCode(), options.asString());
    JsonPath o = options.jsonPath();
    assertNotNull(o.getString("registration_id"));
    assertNotNull(o.getString("challenge"));
    assertEquals("localhost", o.getString("rp.id"));
    assertEquals("Native Auth Demo", o.getString("rp.name"));
    assertEquals("alice", o.getString("user.name"));
    assertEquals("Alice Example", o.getString("user.display_name"));
    assertNotNull(o.getString("user.id"));
    assertEquals(List.of(-7, -257), o.getList("pub_key_cred_params.alg"));
    assertEquals("required", o.getString("authenticator_selection.user_verification"));
    assertEquals("required", o.getString("authenticator_selection.resident_key"));
    assertEquals("none", o.getString("attestation"));
    assertEquals(60000, o.getInt("timeout"));

    SoftwareAuthenticator authenticator = new SoftwareAuthenticator(o.getString("rp.id"), origin());
    Map<String, String> created = authenticator.register(o.getString("challenge"), o.getString("user.id"));
    Map<String, String> body = new LinkedHashMap<>(created);
    body.put("registration_id", o.getString("registration_id"));
    body.put("label", "Second device");
    Response finish = registerFinish(token, body);
    assertEquals(201, finish.statusCode(), finish.asString());
    assertEquals(authenticator.credentialId(), finish.jsonPath().getString("credential_id"));
    assertEquals("Second device", finish.jsonPath().getString("label"));

    // Stored as a webauthn-passwordless credential with the label.
    assertTrue(
        credentials("alice").stream().anyMatch(c -> "webauthn-passwordless".equals(c.get("type")) && "Second device".equals(c.get("userLabel"))),
        "credential not stored: " + credentials("alice"));

    // registration_id is single use.
    Response replay = registerFinish(token, body);
    assertEquals(400, replay.statusCode(), replay.asString());
    assertEquals("invalid_request", replay.jsonPath().getString("error"));
  }

  @Test
  void registrationEndpointsRequireABearerToken() {
    Response noToken = given().accept("application/json").post(realmUrl() + "/native-auth/passkey/register/options").andReturn();
    assertEquals(401, noToken.statusCode(), noToken.asString());
    assertEquals("invalid_token", noToken.jsonPath().getString("error"));
    assertTrue(noToken.header("WWW-Authenticate").startsWith("Bearer"), noToken.headers().toString());

    Response garbage = registerOptions("not-a-token");
    assertEquals(401, garbage.statusCode(), garbage.asString());
  }

  @Test
  void staleAuthenticationIsRefusedForRegistrationUntilAStepUpWithMaxAge() throws Exception {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    String token = tokens.jsonPath().getString("access_token");
    setRealmAttribute("native-auth.passkey-registration-max-age", "1");
    try {
      Thread.sleep(2100);
      Response options = registerOptions(token);
      assertEquals(403, options.statusCode(), options.asString());
      assertEquals("insufficient_authorization", options.jsonPath().getString("error"));
      // spec/03 §6: the body names the limit and carries a post-login auth_session for a step-up.
      assertEquals(1, options.jsonPath().getInt("max_age"));
      String stepUpSession = options.jsonPath().getString("auth_session");
      assertNotNull(stepUpSession, "post-login auth_session for the step-up");

      // Step up with max_age: full re-authentication of the 'native' flow, username skipped.
      Pkce pkce2 = Pkce.s256();
      Response s = StepUpIT.stepUp(CLIENT, pkce2, stepUpSession, "max_age", "1");
      assertOffers(s, "password");
      assertEquals("alice", s.jsonPath().getString("context.username"));
      s = answer(s, "password", "password", "alice-password");
      assertChallenge(s, "totp");
      s = answer(s, "totp", "totp", totp(ALICE_TOTP_SECRET));
      assertEquals(200, s.statusCode(), s.asString());
      Response fresh = exchange(CLIENT, s.jsonPath().getString("authorization_code"), pkce2, null);
      assertEquals(200, fresh.statusCode(), fresh.asString());
      Response optionsAgain = registerOptions(fresh.jsonPath().getString("access_token"));
      assertEquals(200, optionsAgain.statusCode(), optionsAgain.asString());
    } finally {
      setRealmAttribute("native-auth.passkey-registration-max-age", "300");
    }
  }

  // ---------------------------------------------------------------------------------------------
  // §4.3 login

  @Test
  void allowListLoginAfterUsernameOffersPasskeyAndPassword() {
    SoftwareAuthenticator passkey = alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "alice");
    assertChallenge(r, "passkey", "password");
    assertEquals(false, descriptor(r, "passkey").get("required"));
    JsonPath p = r.jsonPath();
    assertEquals("localhost", p.getString("challenges[0].params.rp_id"));
    assertEquals("required", p.getString("challenges[0].params.user_verification"));
    assertEquals(false, p.getBoolean("challenges[0].params.discoverable"));
    List<String> allowed = p.getList("challenges[0].params.allow_credentials.id");
    assertTrue(allowed.contains(passkey.credentialId()), "allow_credentials " + allowed);
    assertEquals(List.of("hybrid", "internal"), new ArrayList<>(new java.util.TreeSet<>(p.<String>getList("challenges[0].params.allow_credentials.find { it.id == '" + passkey.credentialId() + "' }.transports"))));

    r = answer(r, "passkey", flatten(passkey.assertion(p.getString("challenges[0].params.challenge"))));
    assertChallenge(r, "totp");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    String code = r.jsonPath().getString("authorization_code");
    assertNotNull(code);
    // §5: a post-login auth_session is returned for later step-up.
    String postLogin = r.jsonPath().getString("auth_session");
    assertNotNull(postLogin);
    Response tokens = exchange(CLIENT, code, pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("alice", NativeAuthIT.claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

    // The post-login value is for step-up (§5, StepUpIT); as a plain continuation it is invalid_request.
    Response resumed = challenge(params("auth_session", postLogin, "challenge_type", "passkey", "challenge_id", "x"));
    assertEquals(400, resumed.statusCode(), resumed.asString());
    assertEquals("invalid_request", resumed.jsonPath().getString("error"));
    assertTrue(resumed.jsonPath().getString("error_description").contains("step-up"), resumed.asString());
  }

  @Test
  void discoverableLoginWithUserHandle() {
    SoftwareAuthenticator passkey = alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_PASSKEY, pkce);
    assertChallenge(r, "passkey", "username");
    JsonPath p = r.jsonPath();
    assertEquals(true, p.getBoolean("challenges[0].params.discoverable"));
    assertEquals(List.of(), p.getList("challenges[0].params.allow_credentials"));
    assertNull(p.getString("context.username"));

    Map<String, String> assertion = passkey.assertion(p.getString("challenges[0].params.challenge"));
    assertNotNull(assertion.get("user_handle"));
    r = answer(r, "passkey", flatten(assertion));
    assertChallenge(r, "totp");
    assertEquals("alice", r.jsonPath().getString("context.username"));
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT_PASSKEY, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());

    // The username alternative of the same set still works (passkey-less users).
    r = start(CLIENT_PASSKEY, Pkce.s256());
    r = answer(r, "username", "username", "bob");
    assertChallenge(r, "password");
    r = answer(r, "password", "password", "bob-password");
    assertEquals(200, r.statusCode(), r.asString());
  }

  @Test
  void wrongSignatureRechallengesWithInvalidCredential() {
    SoftwareAuthenticator passkey = alicePasskey();
    Response r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "alice");
    assertChallenge(r, "passkey", "password");
    String challenge = r.jsonPath().getString("challenges[0].params.challenge");

    pauseForQuickLoginWindow();
    r = answer(r, "passkey", flatten(passkey.assertionWithWrongKey(challenge)));
    assertOffers(r, "passkey");
    assertEquals("passkey", r.jsonPath().getString("challenges[0].type"));
    assertEquals("invalid_credential", errorCode(r, "passkey"), r.asString());
    String fresh = r.jsonPath().getString("challenges[0].params.challenge");
    assertNotNull(fresh);
    assertFalse(challenge.equals(fresh), "a new challenge is issued after a failed attempt");

    // Replaying the old challenge value fails too; the right one succeeds.
    pauseForQuickLoginWindow();
    r = answer(r, "passkey", flatten(passkey.assertion(challenge)));
    assertEquals("invalid_credential", errorCode(r, "passkey"), r.asString());
    r = answer(r, "passkey", flatten(passkey.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
    assertChallenge(r, "totp");
  }

  @Test
  void missingAssertionFieldsRechallengeWithoutCountingAFailure() {
    alicePasskey();
    Response r = start(CLIENT, Pkce.s256());
    r = answer(r, "username", "username", "alice");
    r = answer(r, "passkey", "credential_id", "abc");
    assertOffers(r, "passkey");
    assertEquals("missing_credential", errorCode(r, "passkey"), r.asString());
  }

  // ---------------------------------------------------------------------------------------------
  // §4.4 registration through the native required action

  @Test
  void requiredActionRegistersPasskeyForNewUserThenPasskeyLoginWorks() {
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "dave");
    assertChallenge(r, "password"); // no passkey yet: the passkey alternative is not offered
    r = answer(r, "password", "password", "dave-password");
    assertChallenge(r, "passkey_registration");
    JsonPath p = r.jsonPath();
    assertEquals(true, p.getBoolean("challenges[0].required"));
    assertEquals("native-passkey-register", p.getString("challenges[0].id"));
    assertEquals("dave", p.getString("challenges[0].params.user.name"));
    assertEquals("localhost", p.getString("challenges[0].params.rp.id"));
    assertEquals("dave", p.getString("context.username"));
    assertTrue(p.getLong("expires_in") > 0);

    // A bad attestation re-challenges with error.code=invalid_attestation and a fresh challenge.
    SoftwareAuthenticator passkey = new SoftwareAuthenticator("wrong.example", origin());
    Map<String, String> bad = passkey.register(p.getString("challenges[0].params.challenge"), p.getString("challenges[0].params.user.id"));
    r = answer(r, "passkey_registration", flatten(bad));
    assertChallenge(r, "passkey_registration");
    assertEquals("invalid_attestation", errorCode(r, "passkey_registration"), r.asString());
    p = r.jsonPath();

    passkey = new SoftwareAuthenticator(p.getString("challenges[0].params.rp.id"), origin());
    Map<String, String> created = passkey.register(p.getString("challenges[0].params.challenge"), p.getString("challenges[0].params.user.id"));
    created.put("label", "Dave's phone");
    r = answer(r, "passkey_registration", flatten(created));
    assertEquals(200, r.statusCode(), r.asString());
    assertNotNull(r.jsonPath().getString("authorization_code"));
    assertNotNull(r.jsonPath().getString("auth_session"));
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
    assertTrue(credentials("dave").stream().anyMatch(c -> "webauthn-passwordless".equals(c.get("type")) && "Dave's phone".equals(c.get("userLabel"))));

    // The action is done: the next login offers the passkey and does not ask again.
    pkce = Pkce.s256();
    r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "dave");
    assertChallenge(r, "passkey", "password");
    r = answer(r, "passkey", flatten(passkey.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }
}
