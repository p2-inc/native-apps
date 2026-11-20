package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertOffers;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.refresh;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.phasetwo.keycloak.nativeauth.demo.StepUpIT.stepUp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Application-initiated actions (spec/21): a signed-in app sends {@code kc_action} with its post-login
 * {@code auth_session}, Keycloak's own rules decide whether the user re-authenticates first (the
 * action's maximum authentication age, {@code max_age}, {@code prompt=login}), the native variant
 * serves the action, and the success body reports {@code kc_action_status}. alice signs in on the
 * plain {@code native} flow (password + TOTP); every test restores her password.
 */
@ExtendWith(TranscriptRecorder.class)
class KcActionIT {

  private static final String NEW_PASSWORD = "alice-new-password";

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> params(Response r, String type) {
    return (Map<String, Object>) descriptor(r, type).get("params");
  }

  /** A signed-in app: alice's login with the code exchanged, as an SDK does. */
  private record SignedIn(String postLogin, String refreshToken) {}

  private static SignedIn signIn() {
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "alice", "alice-password", ALICE_TOTP_SECRET);
    assertEquals(200, r.statusCode(), r.asString());
    assertNull(r.jsonPath().getString("kc_action_status"), "no kc_action, no status");
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    return new SignedIn(r.jsonPath().getString("auth_session"), tokens.jsonPath().getString("refresh_token"));
  }

  @Test
  void aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd() {
    try {
      // Another device, signed in first.
      String otherRefresh = signIn().refreshToken();

      // This app.
      SignedIn app = signIn();
      String refreshToken = app.refreshToken();

      // Within Update Password's maximum authentication age (300 s): straight to the action, no factor.
      Pkce pkce2 = Pkce.s256();
      Response r = stepUp(CLIENT, pkce2, app.postLogin(), "kc_action", "UPDATE_PASSWORD");
      assertChallenge(r, "update_password");
      Map<String, Object> d = descriptor(r, "update_password");
      assertEquals("native-update-password", d.get("id"));
      assertEquals(true, d.get("skippable"), "the user may cancel an action the app asked for");
      assertEquals(true, params(r, "update_password").get("logout_other_sessions"), "offered, checked by default");

      r = answer(r, "update_password", "password", NEW_PASSWORD, "password_confirm", NEW_PASSWORD, "logout_other_sessions", "true");
      assertEquals(200, r.statusCode(), r.asString());
      assertEquals("success", r.jsonPath().getString("kc_action_status"));
      Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce2, null);
      assertEquals(200, tokens.statusCode(), tokens.asString());

      // The app's own session survives; the other device is signed out.
      assertEquals(200, refresh(CLIENT, refreshToken).statusCode(), "the session the app is signed in with is kept");
      assertEquals(400, refresh(CLIENT, otherRefresh).statusCode(), "other sessions are ended");

      // The new password works; nothing is left pending on the user.
      assertEquals(200, login(CLIENT, Pkce.s256(), "alice", NEW_PASSWORD, ALICE_TOTP_SECRET).statusCode());
      assertEquals(List.of(), Admin.user("alice").getList("requiredActions"));
    } finally {
      Admin.resetPassword("alice", "alice-password");
    }
  }

  @Test
  void theRealmsMaxAuthAgeForcesReauthenticationFirst() throws Exception {
    // Update Password follows the password policy's maxAuthAge (Keycloak's UpdatePassword.getMaxAuthAge).
    Admin.setPasswordPolicy("maxAuthAge(0)");
    try {
      String postLogin = signIn().postLogin();
      Thread.sleep(1100); // auth_time + 0 < now, and outside the quick-login window

      Pkce pkce2 = Pkce.s256();
      Response r = stepUp(CLIENT, pkce2, postLogin, "kc_action", "UPDATE_PASSWORD");
      assertOffers(r, "password");
      assertEquals("alice", r.jsonPath().getString("context.username"));
      r = answer(r, "password", "password", "alice-password");
      assertChallenge(r, "totp");
      r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
      assertChallenge(r, "update_password");
      r = answer(r, "update_password", "password", NEW_PASSWORD, "password_confirm", NEW_PASSWORD);
      assertEquals(200, r.statusCode(), r.asString());
      assertEquals("success", r.jsonPath().getString("kc_action_status"));
    } finally {
      Admin.setPasswordPolicy("");
      Admin.resetPassword("alice", "alice-password");
    }
  }

  @Test
  void maxAgeZeroReauthenticatesAndCancellingKeepsThePassword() throws Exception {
    String postLogin = signIn().postLogin();
    Thread.sleep(1100);

    Pkce pkce2 = Pkce.s256();
    Response r = stepUp(CLIENT, pkce2, postLogin, "kc_action", "UPDATE_PASSWORD", "max_age", "0");
    assertOffers(r, "password");
    r = answer(r, "password", "password", "alice-password");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertChallenge(r, "update_password");

    r = answer(r, "update_password", "action", "skip");
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals("cancelled", r.jsonPath().getString("kc_action_status"));
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce2, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("alice", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

    // Unchanged: the old password still signs in.
    assertEquals(200, login(CLIENT, Pkce.s256(), "alice", "alice-password", ALICE_TOTP_SECRET).statusCode());
  }

  @Test
  void anActionThatCannotBeInitiatedReportsError() {
    String postLogin = signIn().postLogin();

    // Terms are only shown when Keycloak schedules them; an unknown alias is not configured at all.
    for (String action : new String[] {"TERMS_AND_CONDITIONS", "no-such-action"}) {
      Pkce p = Pkce.s256();
      Response r = stepUp(CLIENT, p, postLogin, "kc_action", action);
      assertEquals(200, r.statusCode(), action + ": " + r.asString());
      assertEquals("error", r.jsonPath().getString("kc_action_status"), action);
      assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), p, null).statusCode());
      postLogin = r.jsonPath().getString("auth_session");
    }
  }

  @Test
  void anActionParameterIsSplitOffTheAlias() {
    // Keycloak's `alias:parameter` form (delete_credential:<id>, idp_link:<alias>, …): the alias is
    // what runs; UPDATE_PASSWORD ignores the parameter.
    String postLogin = signIn().postLogin();
    Pkce pkce = Pkce.s256();
    Response r = stepUp(CLIENT, pkce, postLogin, "kc_action", "UPDATE_PASSWORD:unused");
    assertChallenge(r, "update_password");
    r = answer(r, "update_password", "action", "skip");
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals("cancelled", r.jsonPath().getString("kc_action_status"));
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }

  @Test
  void verifyEmailCanBeStartedByTheApp() {
    String postLogin = signIn().postLogin();
    Pkce pkce = Pkce.s256();
    Response r = stepUp(CLIENT, pkce, postLogin, "kc_action", "VERIFY_EMAIL");
    assertChallenge(r, "verify_email");
    assertEquals(true, descriptor(r, "verify_email").get("skippable"));
    r = answer(r, "verify_email", "action", "skip");
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals("cancelled", r.jsonPath().getString("kc_action_status"));
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }

  @Test
  void anActionWithoutANativeVariantRunsInTheBrowserAndReportsItsStatus() throws Exception {
    // frank has nothing pending; the app asks for UPDATE_PROFILE, which has no native variant.
    Admin.updateUser("frank", "{\"requiredActions\":[]}");
    try {
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "frank", "frank-password", null);
      assertEquals(200, r.statusCode(), r.asString());
      assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());

      Pkce pkce2 = Pkce.s256();
      r = stepUp(CLIENT, pkce2, r.jsonPath().getString("auth_session"), "kc_action", "UPDATE_PROFILE");
      assertEquals(403, r.statusCode(), r.asString());
      assertEquals("redirect_to_web", r.jsonPath().getString("error"));
      assertEquals("required_action:UPDATE_PROFILE", r.jsonPath().getString("reason"));
      String requestUri = r.jsonPath().getString("request_uri");
      String state = r.jsonPath().getString("state");

      // The browser signs frank in and, because the stored request carries kc_action, shows the profile page.
      RedirectToWebIT.Browser browser = new RedirectToWebIT.Browser();
      HttpResponse<String> page =
          browser.get(realmUrl() + "/protocol/openid-connect/auth?client_id=" + CLIENT + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
      for (int hops = 0; page.statusCode() == 302 && hops < 3; hops++) {
        page = browser.get(page.headers().firstValue("Location").orElseThrow());
      }
      assertEquals(200, page.statusCode(), page.body());
      HttpResponse<String> afterLogin = browser.post(formAction(page.body()), "username=frank&password=frank-password");
      assertEquals(302, afterLogin.statusCode(), afterLogin.body());
      String actionUrl = afterLogin.headers().firstValue("Location").orElseThrow();
      assertTrue(actionUrl.contains("required-action"), actionUrl);
      HttpResponse<String> actionPage = browser.get(actionUrl);
      assertTrue(actionPage.body().contains("firstName"), actionPage.body());
      HttpResponse<String> done =
          browser.post(formAction(actionPage.body()), "username=frank&email=frank%40example.com&firstName=Frank&lastName=Example");
      assertEquals(302, done.statusCode(), done.body());
      String location = done.headers().firstValue("Location").orElseThrow();
      assertTrue(location.startsWith("demoapp://auth/callback?"), location);
      assertTrue(location.contains("state=" + URLEncoder.encode(state, StandardCharsets.UTF_8)), location);
      assertTrue(location.contains("kc_action_status=success"), "the callback reports the action: " + location);

      // The app exchanges the browser's code with the native flow's verifier, as after any redirect_to_web.
      Matcher code = Pattern.compile("[?&]code=([^&]+)").matcher(location);
      assertTrue(code.find(), location);
      Response tokens = exchange(CLIENT, URLDecoder.decode(code.group(1), StandardCharsets.UTF_8), pkce2, "demoapp://auth/callback");
      assertEquals(200, tokens.statusCode(), tokens.asString());
    } finally {
      Admin.updateUser("frank", "{\"requiredActions\":[\"UPDATE_PROFILE\"]}");
    }
  }

  private static String formAction(String html) {
    Matcher m = Pattern.compile("action=\"([^\"]+)\"").matcher(html);
    assertTrue(m.find(), "no form in page:\n" + html);
    return m.group(1).replace("&amp;", "&");
  }
}
