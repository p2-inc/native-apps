package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.response.Response;
import java.io.File;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * {@code recovery_code} (spec/03 §4.8, spec/14 D2) on the {@code native} flow: user {@code ivy}
 * (password, TOTP, three recovery codes seeded hashed in the realm export) picks a recovery code
 * instead of the TOTP; using the last code schedules {@code CONFIGURE_RECOVERY_AUTHN_CODES}, which
 * the native flow hands to the browser. ivy is re-created from the export afterwards.
 */
@ExtendWith(TranscriptRecorder.class)
class RecoveryCodeIT {

  /** The raw codes behind the hashes in realm-export/demo-realm.json. */
  static final List<String> IVY_CODES = List.of("IVY1IVY1IVY1", "IVY2IVY2IVY2", "IVY3IVY3IVY3");

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> params(Response r) {
    return (Map<String, Object>) descriptor(r, "recovery_code").get("params");
  }

  static Response loginIvyToSecondFactor(Pkce pkce) {
    Response r = start(CLIENT, pkce);
    r = answer(r, "username", "username", "ivy");
    r = answer(r, "password", "password", "ivy-password");
    assertChallenge(r, "totp", "recovery_code");
    assertEquals(false, descriptor(r, "recovery_code").get("required"));
    return r;
  }

  @Test
  void ivyUsesRecoveryCodesUntilTheyRunOut() {
    try {
      // Exchanges 1-7: wrong code → invalid_credential, then a code in display format → tokens.
      Pkce pkce = Pkce.s256();
      Response r = loginIvyToSecondFactor(pkce);
      assertEquals(3, params(r).get("remaining"));
      assertEquals(4, params(r).get("warning_threshold"), "Keycloak's default recoveryCodesWarningThreshold");

      pauseForQuickLoginWindow();
      Response wrong = answer(r, "recovery_code", "recovery_code", "IVY9-IVY9-IVY9");
      assertChallenge(wrong, "totp", "recovery_code");
      assertEquals("invalid_credential", errorCode(wrong, "recovery_code"));
      assertEquals(3, params(wrong).get("remaining"), "a wrong code consumes nothing");

      Response ok = answer(wrong, "recovery_code", "recovery_code", "ivy1-ivy1-ivy1");
      assertEquals(200, ok.statusCode(), ok.asString());
      Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());
      assertEquals("ivy", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

      // 8-11: the second code; the count went down and a used code is refused.
      Pkce pkce2 = Pkce.s256();
      r = loginIvyToSecondFactor(pkce2);
      assertEquals(2, params(r).get("remaining"));
      pauseForQuickLoginWindow();
      Response reused = answer(r, "recovery_code", "recovery_code", IVY_CODES.get(0));
      assertEquals("invalid_credential", errorCode(reused, "recovery_code"), "codes are single use and consumed in order");
      r = answer(reused, "recovery_code", "recovery_code", IVY_CODES.get(1));
      assertEquals(200, r.statusCode(), r.asString());

      // 12-15: the last code works but leaves CONFIGURE_RECOVERY_AUTHN_CODES behind, which has no
      // native variant: the login is handed to the browser (spec/03 §3.4).
      Pkce pkce3 = Pkce.s256();
      r = loginIvyToSecondFactor(pkce3);
      assertEquals(1, params(r).get("remaining"));
      r = answer(r, "recovery_code", "recovery_code", IVY_CODES.get(2));
      assertEquals(403, r.statusCode(), r.asString());
      assertEquals("redirect_to_web", r.jsonPath().getString("error"));
      assertEquals("required_action:CONFIGURE_RECOVERY_AUTHN_CODES", r.jsonPath().getString("reason"));
      assertTrue(Admin.user("ivy").getList("requiredActions").contains("CONFIGURE_RECOVERY_AUTHN_CODES"));

      // 16-18: with no code left, the second factor offers the TOTP only.
      Response again = start(CLIENT, Pkce.s256());
      again = answer(again, "username", "username", "ivy");
      again = answer(again, "password", "password", "ivy-password");
      assertChallenge(again, "totp");
      assertNull(errorCode(again, "totp"));
    } finally {
      recreateIvy();
    }
  }

  /** Deletes ivy and re-creates her from the realm export (credentials included) so codes are fresh again. */
  static void recreateIvy() {
    try {
      String token = adminToken();
      given().auth().oauth2(token).delete(adminRealmUrl() + "/users/" + Admin.userId("ivy")).then().statusCode(204);
      JsonNode realm = new ObjectMapper().readTree(new File(System.getProperty("realm.export", "realm-export/demo-realm.json")));
      JsonNode ivy = null;
      for (JsonNode user : realm.get("users")) {
        if ("ivy".equals(user.get("username").asText())) ivy = user;
      }
      given().auth().oauth2(token).contentType("application/json").body(ivy.toString())
          .post(adminRealmUrl() + "/users").then().statusCode(201);
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }
}
