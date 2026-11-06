package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertOffers;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.logout;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Step-up / re-authentication with the post-login {@code auth_session} (spec/03 §5, spec/13 D1) on
 * the {@code native-step-up} flow: level 1 = passkey or password (valid 10 h), level 2 = TOTP
 * (loa-max-age 0). Client {@code demo-native-stepup}.
 */
@ExtendWith(TranscriptRecorder.class)
class StepUpIT {

  static final String CLIENT_STEP_UP = "demo-native-stepup";

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  /** A §2.1 request carrying the post-login auth_session (spec/03 §5). */
  static Response stepUp(String clientId, Pkce pkce, String postLoginSession, String... extra) {
    Map<String, String> p =
        params(
            "client_id", clientId,
            "response_type", "code",
            "scope", "openid profile",
            "code_challenge", pkce.challenge(),
            "code_challenge_method", "S256",
            "device_name", "NativeAuthIT",
            "auth_session", postLoginSession);
    for (int i = 0; i < extra.length; i += 2) p.put(extra[i], extra[i + 1]);
    return challenge(p);
  }

  /** alice at level 1 on the step-up flow: username → password (TOTP is level 2 and not requested). */
  static Response loginAliceLevel1(Pkce pkce) {
    Response r = start(CLIENT_STEP_UP, pkce);
    assertChallenge(r, "username");
    r = answer(r, "username", "username", "alice");
    assertOffers(r, "password");
    r = answer(r, "password", "password", "alice-password");
    assertEquals(200, r.statusCode(), r.asString());
    return r;
  }

  @Test
  void stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession() {
    Pkce pkce = Pkce.s256();
    Response r = loginAliceLevel1(pkce);
    String postLogin = r.jsonPath().getString("auth_session");
    assertNotNull(postLogin);
    Response tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    JsonPath first = claims(tokens.jsonPath().getString("access_token"));
    assertEquals("1", first.getString("acr"), "primary factor only = level 1");
    String sid = first.getString("sid");
    int authTime = first.getInt("auth_time");

    // Step up to level 2: the username step is skipped, only the level-2 condition fires.
    Pkce pkce2 = Pkce.s256();
    r = stepUp(CLIENT_STEP_UP, pkce2, postLogin, "acr_values", "2");
    assertChallenge(r, "totp");
    assertEquals(true, r.jsonPath().getBoolean("context.step_up"));
    assertEquals("2", r.jsonPath().getString("context.acr_requested"));
    assertEquals("alice", r.jsonPath().getString("context.username"));
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    String postLogin2 = r.jsonPath().getString("auth_session");
    assertNotNull(postLogin2);
    assertNotEquals(postLogin, postLogin2, "a fresh post-login auth_session is minted");

    tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce2, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    JsonPath second = claims(tokens.jsonPath().getString("access_token"));
    assertEquals("2", second.getString("acr"));
    assertEquals(sid, second.getString("sid"), "same user session");
    assertTrue(second.getInt("auth_time") >= authTime, "a factor ran, so auth_time moves forward");

    // Level 1 is still valid: requesting it again yields a code without any challenge (SSO-style).
    Pkce pkce3 = Pkce.s256();
    r = stepUp(CLIENT_STEP_UP, pkce3, postLogin2, "acr_values", "1");
    assertEquals(200, r.statusCode(), r.asString());
    tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce3, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    JsonPath third = claims(tokens.jsonPath().getString("access_token"));
    assertEquals(sid, third.getString("sid"));
    assertEquals("1", third.getString("acr"), "nothing above level 1 was authenticated in this request");
    assertEquals(second.getInt("auth_time"), third.getInt("auth_time"), "no factor ran: auth_time untouched");
  }

  @Test
  void maxAgeForcesAFullReauthentication() throws Exception {
    Pkce pkce = Pkce.s256();
    Response r = loginAliceLevel1(pkce);
    String postLogin = r.jsonPath().getString("auth_session");
    Response tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce, null);
    int authTime = claims(tokens.jsonPath().getString("access_token")).getInt("auth_time");

    Thread.sleep(1100); // make auth_time + max_age=0 < now observable and stay outside the quick-login window
    Pkce pkce2 = Pkce.s256();
    r = stepUp(CLIENT_STEP_UP, pkce2, postLogin, "max_age", "0");
    // Forced re-authentication: level 1 must be proven again (the username step stays skipped).
    assertOffers(r, "password");
    assertEquals(true, r.jsonPath().getBoolean("context.step_up"));
    assertNull(r.jsonPath().getString("context.acr_requested"));
    r = answer(r, "password", "password", "alice-password");
    assertEquals(200, r.statusCode(), r.asString());
    tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce2, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    JsonPath c = claims(tokens.jsonPath().getString("access_token"));
    assertEquals("1", c.getString("acr"));
    assertTrue(c.getInt("auth_time") > authTime, "re-authentication refreshed auth_time");
  }

  @Test
  void acrValuesOnAFreshLoginRequestsLevel2Directly() {
    Pkce pkce = Pkce.s256();
    Map<String, String> p =
        params(
            "client_id", CLIENT_STEP_UP, "response_type", "code", "scope", "openid profile",
            "code_challenge", pkce.challenge(), "code_challenge_method", "S256",
            "device_name", "NativeAuthIT", "acr_values", "2");
    Response r = challenge(p);
    assertChallenge(r, "username");
    r = answer(r, "username", "username", "alice");
    assertOffers(r, "password");
    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals("2", claims(tokens.jsonPath().getString("access_token")).getString("acr"));
  }

  @Test
  void stepUpOnAFlowWithoutLevelsRerunsEveryFactor() {
    // The plain 'native' flow has no LoA conditions: a step-up re-authenticates fully, acr stays 1.
    Pkce pkce = Pkce.s256();
    Response r = NativeAuthIT.login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    assertEquals(200, r.statusCode(), r.asString());
    String postLogin = r.jsonPath().getString("auth_session");
    Pkce pkce2 = Pkce.s256();
    r = stepUp(CLIENT, pkce2, postLogin, "acr_values", "2");
    assertOffers(r, "password");
    assertEquals("alice", r.jsonPath().getString("context.username"));
    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce2, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("1", claims(tokens.jsonPath().getString("access_token")).getString("acr"));
  }

  @Test
  void postLoginAuthSessionDiesWithTheIdleTimeoutEvenIfTheSessionIsKeptAlive() throws Exception {
    // spec/08 Q11 (spec/14 D6): the post-login auth_session lives for the SSO *idle* timeout from
    // the moment it was minted. Idle = 10 s; a refresh at 5 s keeps the user session alive until
    // 15 s, but the auth_session minted at 0 s is dead at 10 s and a step-up at 12 s is
    // invalid_session. The ~2 s margins keep it stable on slower CI runners (3 s idle was not).
    NativeAuthIT.setRealmField("ssoSessionIdleTimeout", 10);
    try {
      Pkce pkce = Pkce.s256();
      Response r = loginAliceLevel1(pkce);
      String postLogin = r.jsonPath().getString("auth_session");
      Response tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());
      Thread.sleep(5_000);
      Response refreshed = NativeAuthIT.refresh(CLIENT_STEP_UP, tokens.jsonPath().getString("refresh_token"));
      assertEquals(200, refreshed.statusCode(), "the refresh keeps the user session alive: " + refreshed.asString());
      Thread.sleep(7_000);
      Response late = stepUp(CLIENT_STEP_UP, Pkce.s256(), postLogin, "acr_values", "2");
      assertEquals(400, late.statusCode(), late.asString());
      assertEquals("invalid_session", late.jsonPath().getString("error"));
      // The session itself is still alive (refreshed at 5 s, idle until 15 s).
      Response alive = NativeAuthIT.refresh(CLIENT_STEP_UP, refreshed.jsonPath().getString("refresh_token"));
      assertEquals(200, alive.statusCode(), alive.asString());
    } finally {
      NativeAuthIT.setRealmField("ssoSessionIdleTimeout", 1800);
    }
  }

  @Test
  void stepUpAfterLogoutOrWithAnotherClientIsInvalidSession() {
    Pkce pkce = Pkce.s256();
    Response r = loginAliceLevel1(pkce);
    String postLogin = r.jsonPath().getString("auth_session");
    Response tokens = exchange(CLIENT_STEP_UP, r.jsonPath().getString("authorization_code"), pkce, null);

    Response wrongClient = stepUp(CLIENT, Pkce.s256(), postLogin, "acr_values", "2");
    assertEquals(400, wrongClient.statusCode(), wrongClient.asString());
    assertEquals("invalid_session", wrongClient.jsonPath().getString("error"));

    assertEquals(204, logout(CLIENT_STEP_UP, tokens.jsonPath().getString("refresh_token")).statusCode());
    Response ended = stepUp(CLIENT_STEP_UP, Pkce.s256(), postLogin, "acr_values", "2");
    assertEquals(400, ended.statusCode(), ended.asString());
    assertEquals("invalid_session", ended.jsonPath().getString("error"));
    assertNull(ended.jsonPath().getString("auth_session"));
  }
}
