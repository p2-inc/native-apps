package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Native required actions substituting for Keycloak's own (spec/03 §4.11–§4.14, spec/14 D1):
 * carol's {@code UPDATE_PASSWORD}, grace's {@code VERIFY_EMAIL} and hank's {@code
 * TERMS_AND_CONDITIONS} complete in-band on the {@code native} flow; each test restores the
 * user's state so the scenarios stay reproducible in the container (and in the demo app).
 */
@ExtendWith(TranscriptRecorder.class)
class RequiredActionsIT {

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> params(Response r, String type) {
    return (Map<String, Object>) descriptor(r, type).get("params");
  }

  @Test
  void metadataAdvertisesTheNativeRequiredActions() {
    given().get(KeycloakContainerSupport.realmUrl() + "/native-auth/metadata").then().statusCode(200)
        .body("challenge_types_supported", hasItems("update_password", "verify_email", "terms", "passkey_registration"));
  }

  @Test
  void carolUpdatesHerPasswordInBand() {
    Admin.setPasswordPolicy("length(8)");
    try {
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "carol", "carol-password", null);
      assertChallenge(r, "update_password");
      Map<String, Object> d = descriptor(r, "update_password");
      assertEquals("native-update-password", d.get("id"), "challenge_id is the native action's provider id");
      assertEquals(true, d.get("required"));
      assertEquals("carol", params(r, "update_password").get("username"));
      assertEquals(Map.of("length", 8), params(r, "update_password").get("policy"), r.asString());

      Response missing = answer(r, "update_password", "password", "", "password_confirm", "");
      assertChallenge(missing, "update_password");
      assertEquals("missing_credential", errorCode(missing, "update_password"));

      Response mismatch = answer(missing, "update_password", "password", "carol-password", "password_confirm", "other");
      assertEquals("password_mismatch", errorCode(mismatch, "update_password"));

      Response tooShort = answer(mismatch, "update_password", "password", "short", "password_confirm", "short");
      assertEquals("invalid_password", errorCode(tooShort, "update_password"));
      String message = String.valueOf(((Map<?, ?>) descriptor(tooShort, "update_password").get("error")).get("message"));
      assertTrue(message.contains("8"), "policy message is rendered, not a key: " + message);

      Response ok = answer(tooShort, "update_password", "password", "carol-password", "password_confirm", "carol-password");
      assertEquals(200, ok.statusCode(), ok.asString());
      Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());
      assertEquals("carol", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

      // UPDATE_PASSWORD is gone from the user: the next login needs no action.
      assertEquals(List.of(), Admin.user("carol").getList("requiredActions"));
      Response again = login(CLIENT, Pkce.s256(), "carol", "carol-password", null);
      assertEquals(200, again.statusCode(), again.asString());
    } finally {
      Admin.setPasswordPolicy("");
      Admin.resetPassword("carol", "carol-password");
      Admin.updateUser("carol", "{\"requiredActions\":[\"UPDATE_PASSWORD\"]}");
    }
  }

  @Test
  void disablingTheNativeVariantFallsBackToRedirectToWeb() {
    Admin.setRequiredActionEnabled("native-update-password", false);
    try {
      Response r = login(CLIENT, Pkce.s256(), "carol", "carol-password", null);
      assertEquals(403, r.statusCode(), r.asString());
      assertEquals("redirect_to_web", r.jsonPath().getString("error"));
      assertEquals("required_action:UPDATE_PASSWORD", r.jsonPath().getString("reason"));
    } finally {
      Admin.setRequiredActionEnabled("native-update-password", true);
    }
  }

  @Test
  void graceVerifiesHerEmailWithACode() {
    Mailpit.clear();
    try {
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "grace", "grace-password", null);
      assertChallenge(r, "verify_email");
      assertEquals("native-verify-email", descriptor(r, "verify_email").get("id"));
      Map<String, Object> p = params(r, "verify_email");
      assertEquals("g***@example.com", p.get("email_masked"));
      assertEquals(6, p.get("digits"));
      assertEquals(300, p.get("ttl"));
      assertEquals(true, p.get("sent"), "a required action is the single option: sent at once");
      assertNotNull(p.get("resend_allowed_at"));
      assertEquals(1, Mailpit.count());
      String code = Mailpit.latestCode("grace@example.com");

      Response tooSoon = answer(r, "verify_email", "action", "resend");
      assertEquals("resend_too_soon", errorCode(tooSoon, "verify_email"));
      assertEquals(1, Mailpit.count());

      Response wrong = answer(tooSoon, "verify_email", "code", "000000".equals(code) ? "111111" : "000000");
      assertEquals("invalid_credential", errorCode(wrong, "verify_email"));
      assertEquals(true, params(wrong, "verify_email").get("sent"));

      Response ok = answer(wrong, "verify_email", "code", code);
      assertEquals(200, ok.statusCode(), ok.asString());
      Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());
      assertEquals(true, claims(tokens.jsonPath().getString("access_token")).getBoolean("email_verified"));
      assertEquals(true, Admin.user("grace").getBoolean("emailVerified"));
      assertEquals(List.of(), Admin.user("grace").getList("requiredActions"));
    } finally {
      Admin.updateUser("grace", "{\"emailVerified\":false,\"requiredActions\":[\"VERIFY_EMAIL\"]}");
    }
  }

  @Test
  void hankMustAcceptTheTermsAndDecliningEndsTheLogin() {
    try {
      // Exchanges 1-4: decline ends the login. 5-8: accept, code, tokens. 9-12: an unusable answer
      // re-issues the challenge (kept last so the SDK can replay the first two logins contiguously).
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "hank", "hank-password", null);
      assertChallenge(r, "terms");
      assertEquals("native-terms", descriptor(r, "terms").get("id"));
      Map<String, Object> p = params(r, "terms");
      assertTrue(String.valueOf(p.get("text")).startsWith("Demo terms"), r.asString());
      assertEquals("https://example.com/terms", p.get("url"));
      assertEquals("2026-10", p.get("version"));

      Response declined = answer(r, "terms", "accepted", "false");
      assertEquals(403, declined.statusCode(), declined.asString());
      assertEquals("access_denied", declined.jsonPath().getString("error"));
      assertTrue(declined.jsonPath().getString("error_description").contains("required_action:TERMS_AND_CONDITIONS"), declined.asString());
      assertNull(Admin.user("hank").getMap("attributes"), "declining leaves no acceptance attribute");

      // A new login: accepting continues to the code and records the acceptance time.
      Pkce pkce2 = Pkce.s256();
      r = login(CLIENT, pkce2, "hank", "hank-password", null);
      assertChallenge(r, "terms");
      Response ok = answer(r, "terms", "accepted", "true");
      assertEquals(200, ok.statusCode(), ok.asString());
      assertEquals(200, exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce2, null).statusCode());
      Map<String, Object> attributes = Admin.user("hank").getMap("attributes");
      assertNotNull(attributes);
      assertNotNull(attributes.get("terms_and_conditions"), String.valueOf(attributes));
      assertEquals(List.of(), Admin.user("hank").getList("requiredActions"));

      // Anything but true/false re-issues the challenge with missing_credential.
      Admin.updateUser("hank", "{\"requiredActions\":[\"TERMS_AND_CONDITIONS\"]}");
      r = login(CLIENT, Pkce.s256(), "hank", "hank-password", null);
      assertChallenge(r, "terms");
      Response unanswered = answer(r, "terms", "accepted", "maybe");
      assertEquals("missing_credential", errorCode(unanswered, "terms"));
    } finally {
      Admin.updateUser("hank", "{\"attributes\":{},\"requiredActions\":[\"TERMS_AND_CONDITIONS\"]}");
    }
  }
}
