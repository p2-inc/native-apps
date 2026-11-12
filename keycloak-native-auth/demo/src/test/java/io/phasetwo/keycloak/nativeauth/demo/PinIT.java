package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.restassured.response.Response;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * The PIN extension on the native profile (spec/03 §4.17, §4.18, spec/20 D7): {@code native-pin}
 * and {@code native-configure-pin} from {@code native-auth-pin} on top of keycloak-pin, on the
 * {@code native-pin} flow (username, password, then the PIN when the user has one; client {@code
 * demo-native-pin}; the PIN execution allows 3 attempts). {@code pia} has the PIN 2580 seeded in
 * the realm export, {@code pete} must set one on his next login; the lockout tests work on users
 * they create from pia's export entry and delete afterwards.
 */
@ExtendWith(TranscriptRecorder.class)
class PinIT {

  static final String CLIENT = "demo-native-pin";
  static final String PIA_PIN = "2580";
  static final int MAX_ATTEMPTS = 3;

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> params(Response r, String type) {
    return (Map<String, Object>) descriptor(r, type).get("params");
  }

  @SuppressWarnings("unchecked")
  static Integer remaining(Response r, String type) {
    Map<String, Object> retry = (Map<String, Object>) descriptor(r, type).get("retry");
    return retry == null ? null : (Integer) retry.get("remaining");
  }

  @Test
  void metadataAdvertisesPinWhenTheExtensionIsInstalled() {
    given().get(realmUrl() + "/native-auth/metadata").then().statusCode(200)
        .body("challenge_types_supported", hasItems("pin", "pin_setup"));
  }

  @Test
  void peteSetsAPinInBand() {
    try {
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "pete", "pete-password", null);
      assertChallenge(r, "pin_setup");
      Map<String, Object> d = descriptor(r, "pin_setup");
      assertEquals("native-configure-pin", d.get("id"), "challenge_id is the native action's provider id");
      assertEquals(true, d.get("required"));
      assertEquals(Map.of("length", 4), params(r, "pin_setup"));

      Response missing = answer(r, "pin_setup", "pin", "", "pin_confirm", "");
      assertChallenge(missing, "pin_setup");
      assertEquals("missing_credential", errorCode(missing, "pin_setup"));

      Response mismatch = answer(missing, "pin_setup", "pin", "1357", "pin_confirm", "1358");
      assertEquals("pin_mismatch", errorCode(mismatch, "pin_setup"));

      Response weak = answer(mismatch, "pin_setup", "pin", "1111", "pin_confirm", "1111");
      assertEquals("weak_pin", errorCode(weak, "pin_setup"));

      Response format = answer(weak, "pin_setup", "pin", "12", "pin_confirm", "12");
      assertEquals("invalid_format", errorCode(format, "pin_setup"));

      Response ok = answer(format, "pin_setup", "pin", PIA_PIN, "pin_confirm", PIA_PIN);
      assertEquals(200, ok.statusCode(), ok.asString());
      Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());
      assertEquals("pete", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

      // The substituted keycloak-pin action is gone and pete has a PIN credential now.
      assertEquals(List.of(), Admin.user("pete").getList("requiredActions"));
      assertTrue(credentialTypes("pete").contains("phasetwo-pin"), credentialTypes("pete").toString());
    } finally {
      removePin("pete");
      Admin.updateUser("pete", "{\"requiredActions\":[\"phasetwo-configure-pin\"]}");
    }
  }

  @Test
  void piaSignsInWithHerPinAfterAWrongOne() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "pia", "pia-password", null);
    assertChallenge(r, "pin");
    assertEquals(true, descriptor(r, "pin").get("required"));
    assertEquals(Map.of("length", 4), params(r, "pin"));
    assertNull(errorCode(r, "pin"));

    Response wrong = answer(r, "pin", "pin", "0000");
    assertChallenge(wrong, "pin");
    assertEquals("invalid_credential", errorCode(wrong, "pin"));
    assertEquals(MAX_ATTEMPTS - 1, remaining(wrong, "pin"), "the PIN's own attempts, not the realm's");

    pauseForQuickLoginWindow();
    Response ok = answer(wrong, "pin", "pin", PIA_PIN);
    assertEquals(200, ok.statusCode(), ok.asString());
    Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    String sub = claims(tokens.jsonPath().getString("access_token")).getString("sub");

    // The wrong PIN is an INVALID_USER_CREDENTIALS login error tagged with the PIN credential type.
    List<Map<String, Object>> errors =
        given().auth().oauth2(adminToken()).queryParam("type", "LOGIN_ERROR").queryParam("user", sub)
            .get(adminRealmUrl() + "/events").then().statusCode(200).extract().jsonPath().getList("$");
    assertTrue(
        errors.stream().anyMatch(e -> "invalid_user_credentials".equals(e.get("error"))
            && "phasetwo-pin".equals(((Map<?, ?>) e.get("details")).get("credential_type"))),
        "expected a LOGIN_ERROR with credential_type=phasetwo-pin, got " + errors);
  }

  @Test
  void aLockedPinCanOnlyBeCancelled() {
    String user = "rita";
    createUserWithPiasPin(user);
    try {
      Response r = login(CLIENT, Pkce.s256(), user, "pia-password", null);
      assertChallenge(r, "pin");
      for (int attempt = 1; attempt < MAX_ATTEMPTS; attempt++) {
        r = answer(r, "pin", "pin", "000" + attempt);
        assertEquals("invalid_credential", errorCode(r, "pin"));
        assertEquals(MAX_ATTEMPTS - attempt, remaining(r, "pin"));
        pauseForQuickLoginWindow();
      }
      // The attempt that reaches the limit locks the PIN.
      Response locked = answer(r, "pin", "pin", "0009");
      assertChallenge(locked, "pin");
      assertEquals("credential_locked", errorCode(locked, "pin"));
      assertEquals(0, remaining(locked, "pin"));

      // action=cancel ends the login; the session is gone (spec/03 §3).
      Response cancelled = cancel(locked);
      assertEquals(400, cancelled.statusCode(), cancelled.asString());
      assertEquals("invalid_session", cancelled.jsonPath().getString("error"));

      List<Map<String, Object>> errors =
          given().auth().oauth2(adminToken()).queryParam("type", "LOGIN_ERROR").queryParam("user", Admin.userId(user))
              .get(adminRealmUrl() + "/events").then().statusCode(200).extract().jsonPath().getList("$");
      assertTrue(
          errors.stream().anyMatch(e -> "pin_locked".equals(((Map<?, ?>) e.get("details")).get("reason"))),
          "expected a LOGIN_ERROR with reason=pin_locked, got " + errors);
    } finally {
      deleteUser(user);
    }
  }

  @Test
  void anAdministratorResetsALockedPin() {
    String user = "sam";
    createUserWithPiasPin(user);
    try {
      // Lock the PIN in one login.
      Response r = login(CLIENT, Pkce.s256(), user, "pia-password", null);
      for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        pauseForQuickLoginWindow();
        r = answer(r, "pin", "pin", "000" + attempt);
      }
      assertEquals("credential_locked", errorCode(r, "pin"));
      cancel(r);

      // A new login announces the lock on the first descriptor, and even the right PIN is refused.
      pauseForQuickLoginWindow();
      r = login(CLIENT, Pkce.s256(), user, "pia-password", null);
      assertChallenge(r, "pin");
      assertEquals("credential_locked", errorCode(r, "pin"));
      assertEquals(0, remaining(r, "pin"));
      Response refused = answer(r, "pin", "pin", PIA_PIN);
      assertEquals("credential_locked", errorCode(refused, "pin"));
      cancel(refused);

      // Reset 1: the administrator deletes the PIN; the conditional sub-flow then skips it.
      removePin(user);
      pauseForQuickLoginWindow();
      Response noPin = login(CLIENT, Pkce.s256(), user, "pia-password", null);
      assertEquals(200, noPin.statusCode(), noPin.asString());

      // Reset 2: the administrator asks for a new PIN (Configure PIN), set in-band.
      Admin.updateUser(user, "{\"requiredActions\":[\"phasetwo-configure-pin\"]}");
      r = login(CLIENT, Pkce.s256(), user, "pia-password", null);
      assertChallenge(r, "pin_setup");
      Response set = answer(r, "pin_setup", "pin", "4826", "pin_confirm", "4826");
      assertEquals(200, set.statusCode(), set.asString());

      Pkce pkce = Pkce.s256();
      r = login(CLIENT, pkce, user, "pia-password", null);
      assertChallenge(r, "pin");
      assertNull(errorCode(r, "pin"), "a new PIN starts unlocked");
      Response empty = answer(r, "pin", "pin", "");
      assertEquals("missing_credential", errorCode(empty, "pin"));
      assertNull(remaining(empty, "pin"), "an empty PIN is not counted");
      Response ok = answer(empty, "pin", "pin", "4826");
      assertEquals(200, ok.statusCode(), ok.asString());
      assertEquals(200, exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null).statusCode());
    } finally {
      deleteUser(user);
    }
  }

  @Test
  void theAccountConsoleStillListsThePin() {
    // Only native-pin verifies PINs in this realm (no browser flow uses phasetwo-pin): its reference
    // category keeps the PIN on the account console's Signing in page.
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "pia", "pia-password", null);
    Response ok = answer(r, "pin", "pin", PIA_PIN);
    assertEquals(200, ok.statusCode(), ok.asString());
    String accessToken =
        exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null).jsonPath().getString("access_token");

    List<Map<String, Object>> types =
        given().auth().oauth2(accessToken).accept("application/json")
            .get(realmUrl() + "/account/credentials").then().statusCode(200).extract().jsonPath().getList("$");
    Map<String, Object> pin =
        types.stream().filter(t -> "phasetwo-pin".equals(t.get("type"))).findFirst()
            .orElseThrow(() -> new AssertionError("no phasetwo-pin among " + types));
    assertEquals("two-factor", pin.get("category"));
    List<?> metadatas = (List<?>) pin.get("userCredentialMetadatas");
    assertFalse(metadatas == null || metadatas.isEmpty(), "pia's PIN is listed: " + pin);
  }

  // ---------------------------------------------------------------------------------------------

  /** {@code action=cancel} as the SDKs send it: the session and the action only. */
  static Response cancel(Response previous) {
    return challenge(KeycloakContainerSupport.params("auth_session", previous.jsonPath().getString("auth_session"), "action", "cancel"));
  }

  static List<String> credentialTypes(String username) {
    return given().auth().oauth2(adminToken())
        .get(adminRealmUrl() + "/users/" + Admin.userId(username) + "/credentials")
        .then().statusCode(200).extract().jsonPath().getList("type");
  }

  /** What an administrator does on the user's Credentials tab: delete the PIN. */
  static void removePin(String username) {
    String token = adminToken();
    String id = Admin.userId(username);
    List<Map<String, Object>> credentials =
        given().auth().oauth2(token).get(adminRealmUrl() + "/users/" + id + "/credentials")
            .then().statusCode(200).extract().jsonPath().getList("$");
    for (Map<String, Object> c : credentials) {
      if ("phasetwo-pin".equals(c.get("type"))) {
        given().auth().oauth2(token).delete(adminRealmUrl() + "/users/" + id + "/credentials/" + c.get("id"))
            .then().statusCode(204);
      }
    }
  }

  /** A copy of pia's realm-export entry (password pia-password, PIN 2580) under another name. */
  static void createUserWithPiasPin(String username) {
    try {
      JsonNode realm = new ObjectMapper().readTree(new File(System.getProperty("realm.export", "realm-export/demo-realm.json")));
      ObjectNode user = null;
      for (JsonNode u : realm.get("users")) {
        if ("pia".equals(u.get("username").asText())) user = ((ObjectNode) u).deepCopy();
      }
      if (user == null) throw new AssertionError("no pia in the realm export");
      user.put("username", username);
      user.put("email", username + "@example.com");
      given().auth().oauth2(adminToken()).contentType("application/json").body(user.toString())
          .post(adminRealmUrl() + "/users").then().statusCode(201);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static void deleteUser(String username) {
    given().auth().oauth2(adminToken()).delete(adminRealmUrl() + "/users/" + Admin.userId(username)).then().statusCode(204);
  }
}
