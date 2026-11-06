package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.setRealmAttribute;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.credentials;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.flatten;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.origin;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.registerOptions;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * spec/04 §4 "enrol on first login" (spec/14 D4): with {@code enrol-on-first-login=true} on the
 * {@code native-passkey} execution, a user without a passkey (bob) authenticates with the password
 * and is then asked for {@code passkey_registration} in-band; and the spec/11 D5 option that
 * restricts {@code /passkey/register/*} to native-enabled clients. Both tests restore the realm.
 */
@ExtendWith(TranscriptRecorder.class)
class EnrolOnFirstLoginIT {

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  /** The {@code native-passkey} execution of the top-level {@code native} flow. */
  static String passkeyExecutionId() {
    List<Map<String, Object>> executions =
        given().auth().oauth2(adminToken()).get(adminRealmUrl() + "/authentication/flows/native/executions")
            .then().statusCode(200).extract().jsonPath().getList("$");
    return executions.stream()
        .filter(e -> "native-passkey".equals(e.get("providerId")))
        .map(e -> String.valueOf(e.get("id")))
        .findFirst()
        .orElseThrow();
  }

  static String setEnrolOnFirstLogin(String executionId, boolean enabled) {
    return setEnrolOnFirstLogin(executionId, enabled, false);
  }

  static String setEnrolOnFirstLogin(String executionId, boolean enabled, boolean optional) {
    Response r =
        given().auth().oauth2(adminToken()).contentType("application/json")
            .body("{\"alias\":\"native-passkey enrol-on-first-login\",\"config\":{\"enrol-on-first-login\":\"" + enabled + "\",\"enrol-optional\":\"" + optional + "\"}}")
            .post(adminRealmUrl() + "/authentication/executions/" + executionId + "/config");
    assertEquals(201, r.statusCode(), r.asString());
    String location = r.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  static void deleteConfig(String configId) {
    given().auth().oauth2(adminToken()).delete(adminRealmUrl() + "/authentication/config/" + configId).then().statusCode(204);
  }

  static void deletePasskeys(String username) {
    String token = adminToken();
    String userId = Admin.userId(username);
    for (Map<String, Object> c : credentials(username)) {
      if ("webauthn-passwordless".equals(c.get("type"))) {
        given().auth().oauth2(token).delete(adminRealmUrl() + "/users/" + userId + "/credentials/" + c.get("id")).then().statusCode(204);
      }
    }
  }

  @Test
  void bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin() {
    String configId = setEnrolOnFirstLogin(passkeyExecutionId(), true);
    try {
      // 1-3: bob has no passkey: the password is the only primary factor, then registration is asked.
      Pkce pkce = Pkce.s256();
      Response r = start(CLIENT, pkce);
      r = answer(r, "username", "username", "bob");
      assertChallenge(r, "password");
      r = answer(r, "password", "password", "bob-password");
      assertChallenge(r, "passkey_registration");
      JsonPath p = r.jsonPath();
      assertEquals("native-passkey-register", p.getString("challenges[0].id"));
      assertEquals("bob", p.getString("challenges[0].params.user.name"));

      // 4-5: the ceremony, then the code; bob has a passkey now.
      SoftwareAuthenticator passkey = new SoftwareAuthenticator(p.getString("challenges[0].params.rp.id"), origin());
      Map<String, String> created = passkey.register(p.getString("challenges[0].params.challenge"), p.getString("challenges[0].params.user.id"));
      created.put("label", "Bob's phone");
      r = answer(r, "passkey_registration", flatten(created));
      assertEquals(200, r.statusCode(), r.asString());
      assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
      assertTrue(credentials("bob").stream().anyMatch(c -> "webauthn-passwordless".equals(c.get("type")) && "Bob's phone".equals(c.get("userLabel"))));

      // 6-7: the next login offers the passkey beside the password and asks nothing more.
      r = start(CLIENT, Pkce.s256());
      r = answer(r, "username", "username", "bob");
      assertChallenge(r, "passkey", "password");
      assertEquals(false, r.jsonPath().getBoolean("challenges[0].params.discoverable"));
    } finally {
      deleteConfig(configId);
      deletePasskeys("bob");
    }
  }

  /** Username + password up to the passkey_registration challenge for bob. */
  static Response bobUpToRegistration(Pkce pkce) {
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "bob");
    r = answer(r, "password", "password", "bob-password");
    assertChallenge(r, "passkey_registration");
    return r;
  }

  @Test
  void bobMayDeclineAnOptionalEnrolmentAndIsOfferedItAgainAtTheNextLogin() {
    String configId = setEnrolOnFirstLogin(passkeyExecutionId(), true, true);
    try {
      Pkce pkce = Pkce.s256();
      Response r = bobUpToRegistration(pkce);
      assertEquals(true, r.jsonPath().getBoolean("challenges[0].skippable"), r.asString());

      // spec/03 §4.11: "Not now" completes the login without a passkey.
      r = answer(r, "passkey_registration", "action", "skip");
      assertEquals(200, r.statusCode(), r.asString());
      assertNotNull(r.jsonPath().getString("auth_session"));
      assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
      assertFalse(credentials("bob").stream().anyMatch(c -> "webauthn-passwordless".equals(c.get("type"))));
      assertFalse(Admin.user("bob").getList("requiredActions").contains("native-passkey-register"));

      // The next login offers it again.
      r = bobUpToRegistration(Pkce.s256());
      assertEquals(true, r.jsonPath().getBoolean("challenges[0].skippable"), r.asString());
    } finally {
      deleteConfig(configId);
      deletePasskeys("bob");
    }
  }

  @Test
  void aMandatoryEnrolmentIsNotSkippableAndRefusesSkip() {
    String configId = setEnrolOnFirstLogin(passkeyExecutionId(), true, false);
    try {
      Response r = bobUpToRegistration(Pkce.s256());
      assertNull(r.jsonPath().get("challenges[0].skippable"), r.asString());
      Response refused = answer(r, "passkey_registration", "action", "skip");
      assertEquals(400, refused.statusCode(), refused.asString());
      assertEquals("invalid_request", refused.jsonPath().getString("error"));
      // The session is still valid and still waiting for the registration.
      assertNotNull(refused.jsonPath().getString("auth_session"));
      Response cancelled = challenge(params("auth_session", refused.jsonPath().getString("auth_session"), "challenge_type", "passkey_registration", "challenge_id", "native-passkey-register", "action", "cancel"));
      assertEquals("invalid_session", cancelled.jsonPath().getString("error"), cancelled.asString());
    } finally {
      deleteConfig(configId);
    }
  }

  @Test
  void anEnrolmentStoredOnTheUserIsNeverSkippable() {
    String configId = setEnrolOnFirstLogin(passkeyExecutionId(), true, true);
    Admin.updateUser("bob", "{\"requiredActions\": [\"native-passkey-register\"]}");
    try {
      Response r = bobUpToRegistration(Pkce.s256());
      assertNull(r.jsonPath().get("challenges[0].skippable"), r.asString());
      assertEquals(400, answer(r, "passkey_registration", "action", "skip").statusCode());
    } finally {
      Admin.updateUser("bob", "{\"requiredActions\": []}");
      deleteConfig(configId);
    }
  }

  @Test
  void withoutTheFlagAUserWithoutAPasskeyIsNotAskedToEnrol() {
    Response r = login(CLIENT, Pkce.s256(), "bob", "bob-password", null);
    assertEquals(200, r.statusCode(), r.asString());
    assertNotNull(r.jsonPath().getString("authorization_code"));
  }

  @Test
  void registrationEndpointsCanBeRestrictedToNativeClients() {
    // A token from the native login of demo-native …
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "bob", "bob-password", null);
    String token = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).jsonPath().getString("access_token");
    assertEquals(200, registerOptions(token).statusCode());

    // … is refused once the realm restricts registration and the client loses its native flag.
    String clientUuid = given().auth().oauth2(adminToken()).queryParam("clientId", CLIENT).get(adminRealmUrl() + "/clients").then().statusCode(200).extract().jsonPath().getString("[0].id");
    Map<String, Object> client = given().auth().oauth2(adminToken()).get(adminRealmUrl() + "/clients/" + clientUuid).then().statusCode(200).extract().jsonPath().getMap("$");
    @SuppressWarnings("unchecked")
    Map<String, Object> attributes = (Map<String, Object>) client.get("attributes");
    try {
      setRealmAttribute("native-auth.passkey-registration-native-clients-only", "true");
      assertEquals(200, registerOptions(token).statusCode(), "a native-enabled client is still fine");
      attributes.put("native-auth.enabled", "false");
      given().auth().oauth2(adminToken()).contentType("application/json").body(client).put(adminRealmUrl() + "/clients/" + clientUuid).then().statusCode(204);
      Response refused = registerOptions(token);
      assertEquals(403, refused.statusCode(), refused.asString());
      assertEquals("access_denied", refused.jsonPath().getString("error"));
    } finally {
      attributes.put("native-auth.enabled", "true");
      given().auth().oauth2(adminToken()).contentType("application/json").body(client).put(adminRealmUrl() + "/clients/" + clientUuid).then().statusCode(204);
      setRealmAttribute("native-auth.passkey-registration-native-clients-only", "false");
    }
  }
}
