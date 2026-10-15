package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * {@code redirect_to_web} (spec/03 §3.4, spec/13 D2): a required action without a native variant hands the login
 * to the browser through a PAR {@code request_uri}; the browser flow completes it and the code it
 * returns is exchanged with the native flow's PKCE verifier. The "browser" is RestAssured with a
 * cookie jar driving Keycloak's HTML forms.
 */
@ExtendWith(TranscriptRecorder.class)
class RedirectToWebIT {

  private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  private static String formAction(String html) {
    Matcher m = FORM_ACTION.matcher(html);
    assertTrue(m.find(), "no form in page:\n" + html);
    return m.group(1).replace("&amp;", "&");
  }

  private static Map<String, String> query(String url) {
    Map<String, String> out = new HashMap<>();
    String q = URI.create(url).getRawQuery();
    if (q == null) return out;
    for (String pair : q.split("&")) {
      int eq = pair.indexOf('=');
      out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8), URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return out;
  }

  @Test
  void pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt() {
    // frank must update his profile; no native variant serves UPDATE_PROFILE (spec/03 §4.11), so
    // the login is handed to the browser. (carol's UPDATE_PASSWORD runs in-band since Phase 2b.)
    Pkce pkce = Pkce.s256();
    Response r = login(CLIENT, pkce, "frank", "frank-password", null);
    assertEquals(403, r.statusCode(), r.asString());
    JsonPath j = r.jsonPath();
    assertEquals("redirect_to_web", j.getString("error"));
    String requestUri = j.getString("request_uri");
    assertTrue(requestUri.startsWith("urn:ietf:params:oauth:request_uri:"), r.asString());
    assertTrue(j.getLong("expires_in") > 0);
    assertEquals("demoapp://auth/callback", j.getString("redirect_uri"));
    String state = j.getString("state");
    assertNotNull(state);
    assertEquals("required_action:UPDATE_PROFILE", j.getString("reason"));

    try {
      // 1. The system browser opens the authorization endpoint with client_id + request_uri. The
      // "browser" is the JDK HttpClient with a cookie jar (Keycloak sets AUTH_SESSION_ID / KC_RESTART).
      Browser browser = new Browser();
      HttpResponse<String> page =
          browser.get(realmUrl() + "/protocol/openid-connect/auth?client_id=" + CLIENT + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
      // Keycloak bounces once within the realm (/login-actions/authenticate) before rendering the form.
      for (int hops = 0; page.statusCode() == 302 && hops < 3; hops++) {
        page = browser.get(page.headers().firstValue("Location").orElseThrow());
      }
      assertEquals(200, page.statusCode(), page.body());
      String html = page.body();
      assertTrue(html.contains("value=\"frank\""), "login_hint pre-fills the username:\n" + html);

      // 2. frank signs in again in the browser flow …
      HttpResponse<String> afterLogin = browser.post(formAction(html), "username=frank&password=frank-password");
      // … and is sent to the required action.
      assertEquals(302, afterLogin.statusCode(), afterLogin.body());
      String actionUrl = afterLogin.headers().firstValue("Location").orElseThrow();
      assertTrue(actionUrl.contains("required-action"), actionUrl);
      HttpResponse<String> actionPage = browser.get(actionUrl);
      assertEquals(200, actionPage.statusCode(), actionPage.body());
      assertTrue(actionPage.body().contains("firstName"), actionPage.body());

      // 3. The action completes and the browser is redirected to the app with a code.
      HttpResponse<String> done = browser.post(formAction(actionPage.body()), "username=frank&email=frank%40example.com&firstName=Frank&lastName=Example");
      assertEquals(302, done.statusCode(), done.body());
      String location = done.headers().firstValue("Location").orElseThrow();
      assertTrue(location.startsWith("demoapp://auth/callback?"), location);
      Map<String, String> callback = query(location);
      assertEquals(state, callback.get("state"), "state from the redirect_to_web body");
      String code = callback.get("code");
      assertNotNull(code, location);

      // 4. The native app exchanges the code with its own verifier and the redirect_uri.
      Response tokens = NativeAuthIT.exchange(CLIENT, code, pkce, "demoapp://auth/callback");
      assertEquals(200, tokens.statusCode(), tokens.asString());
      assertEquals("frank", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));

      // 5. The request_uri was single use.
      HttpResponse<String> reused =
          new Browser().get(realmUrl() + "/protocol/openid-connect/auth?client_id=" + CLIENT + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
      assertEquals(400, reused.statusCode(), reused.body());

      // 6. With the action done, the native flow now logs frank in directly.
      Pkce pkce2 = Pkce.s256();
      Response again = login(CLIENT, pkce2, "frank", "frank-password", null);
      assertEquals(200, again.statusCode(), again.asString());
    } finally {
      Admin.updateUser("frank", "{\"requiredActions\":[\"UPDATE_PROFILE\"]}");
    }
  }

  /**
   * A browser with a cookie jar that does not follow redirects (so the app callback is observable).
   * The jar is hand-rolled: Keycloak sets {@code Version=1} cookies, which the JDK's CookieManager
   * would send back RFC 2965-style ({@code $Version}, quoted values) and Keycloak then cannot read.
   */
  static final class Browser {
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final Map<String, String> cookies = new java.util.LinkedHashMap<>();

    HttpResponse<String> get(String url) {
      return send(HttpRequest.newBuilder(URI.create(url)).GET());
    }

    HttpResponse<String> post(String url, String form) {
      return send(HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)));
    }

    private HttpResponse<String> send(HttpRequest.Builder request) {
      if (!cookies.isEmpty()) {
        request.header("Cookie", cookies.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).reduce((a, b) -> a + "; " + b).orElse(""));
      }
      try {
        HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        for (String header : response.headers().allValues("set-cookie")) {
          String pair = header.split(";", 2)[0];
          int eq = pair.indexOf('=');
          if (eq <= 0) continue;
          String name = pair.substring(0, eq).trim();
          String value = pair.substring(eq + 1).trim();
          if (value.isEmpty() || header.contains("Max-Age=0")) {
            cookies.remove(name);
          } else {
            cookies.put(name, value);
          }
        }
        return response;
      } catch (IOException e) {
        throw new java.io.UncheckedIOException(e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException(e);
      }
    }
  }
}
