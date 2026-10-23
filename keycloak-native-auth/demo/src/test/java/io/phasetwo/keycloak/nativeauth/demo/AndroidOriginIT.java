package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.flatten;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.registerFinish;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.registerOptions;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Android readiness (spec/17 §6 A1): Credential Manager reports a native app's origin as {@code
 * android:apk-key-hash:<base64url SHA-256 of the signing certificate>} instead of {@code
 * https://<rp_id>}. With that value in the Passwordless policy's extra origins, a passkey is
 * registered (spec/03 §6) and used (spec/03 §4.3) with it; without it the assertion is refused. bob's
 * passkeys and the policy are restored.
 */
@ExtendWith(TranscriptRecorder.class)
class AndroidOriginIT {

  /** A made-up signing-certificate hash in the format Android reports. */
  static final String ANDROID_ORIGIN = "android:apk-key-hash:" + hash("demo-android-signing-cert");

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static String hash(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Keycloak applies the Passwordless policy of a realm update only when the representation carries
   * {@code webAuthnPolicyPasswordlessRpEntityName}, and then rebuilds the whole policy from it; a
   * representation with only the extra origins is accepted (204) and ignored. So send every
   * {@code webAuthnPolicyPasswordless*} field with the new origins.
   */
  static void setExtraOrigins(String... origins) {
    Map<String, Object> realm =
        given().auth().oauth2(adminToken()).get(adminRealmUrl()).then().statusCode(200).extract().jsonPath().getMap("$");
    Map<String, Object> policy = new LinkedHashMap<>();
    realm.forEach((k, v) -> {
      if (k.startsWith("webAuthnPolicyPasswordless")) policy.put(k, v);
    });
    policy.put("webAuthnPolicyPasswordlessExtraOrigins", List.of(origins));
    given().auth().oauth2(adminToken()).contentType("application/json").body(policy).put(adminRealmUrl()).then().statusCode(204);
    List<String> stored =
        given().auth().oauth2(adminToken()).get(adminRealmUrl()).then().statusCode(200).extract().jsonPath().getList("webAuthnPolicyPasswordlessExtraOrigins");
    assertEquals(List.of(origins), stored, "the policy kept the extra origins");
  }

  @Test
  void aPasskeyWithAnAndroidOriginRegistersAndSignsInWhenTheOriginIsAllowed() {
    setExtraOrigins(ANDROID_ORIGIN); // the admin API accepts and stores the value
    try {
      // §6 registration from "the Android app" after a password login.
      Pkce pkce = Pkce.s256();
      Response r = login(CLIENT, pkce, "bob", "bob-password", null);
      String token = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).jsonPath().getString("access_token");
      Response options = registerOptions(token);
      assertEquals(200, options.statusCode(), options.asString());
      JsonPath o = options.jsonPath();
      SoftwareAuthenticator android = new SoftwareAuthenticator(o.getString("rp.id"), ANDROID_ORIGIN);
      Map<String, String> body = new LinkedHashMap<>(android.register(o.getString("challenge"), o.getString("user.id")));
      body.put("registration_id", o.getString("registration_id"));
      body.put("label", "Android phone");
      Response finish = registerFinish(token, body);
      assertEquals(201, finish.statusCode(), finish.asString());

      // §4.3 sign-in with the same origin.
      Pkce login = Pkce.s256();
      r = start(CLIENT, login);
      r = answer(r, "username", "username", "bob");
      assertChallenge(r, "passkey", "password");
      r = answer(r, "passkey", flatten(android.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
      assertEquals(200, r.statusCode(), r.asString());
      assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), login, null).statusCode());

      // Without the origin in the policy the same authenticator is refused.
      setExtraOrigins();
      pauseForQuickLoginWindow();
      r = start(CLIENT, Pkce.s256());
      r = answer(r, "username", "username", "bob");
      r = answer(r, "passkey", flatten(android.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
      assertEquals("invalid_credential", errorCode(r, "passkey"), r.asString());
    } finally {
      setExtraOrigins();
      EnrolOnFirstLoginIT.deletePasskeys("bob");
    }
  }
}
