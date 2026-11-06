package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * The {@code sms-webhook} sender (spec/03 §4.6, spec/13 D4) against a host-side sink reachable from
 * the container as {@code host.testcontainers.internal} (spec/14 D5): flow {@code native-sms}
 * (client {@code demo-native-sms}) asks bob for an SMS code after the password; the webhook receives
 * {@code {"to","message"}} with the configured bearer token.
 */
@ExtendWith(TranscriptRecorder.class)
class SmsOtpIT {

  static final String CLIENT_SMS = "demo-native-sms";
  static final String BOB_PHONE = "+15555550123";

  @BeforeAll
  static void startContainer() {
    baseUrl();
    // The declarative user profile drops unmanaged attributes by default; bob's phoneNumber
    // (seeded in the export) is only stored when the realm allows them.
    String token = adminToken();
    Map<String, Object> profile = given().auth().oauth2(token).get(adminRealmUrl() + "/users/profile").then().statusCode(200).extract().jsonPath().getMap("$");
    profile.put("unmanagedAttributePolicy", "ENABLED");
    given().auth().oauth2(token).contentType("application/json").body(profile).put(adminRealmUrl() + "/users/profile").then().statusCode(200);
    Admin.updateUser("bob", "{\"attributes\":{\"phoneNumber\":[\"" + BOB_PHONE + "\"]}}");
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> otpParams(Response r) {
    return (Map<String, Object>) descriptor(r, "otp").get("params");
  }

  @Test
  void bobGetsAnSmsCodeThroughTheWebhook() {
    SmsSink sink = KeycloakContainerSupport.smsSink();
    sink.clear();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_SMS, pkce);
    r = answer(r, "username", "username", "bob");
    r = answer(r, "password", "password", "bob-password");
    assertChallenge(r, "otp");
    Map<String, Object> p = otpParams(r);
    assertEquals("sms", p.get("channel"));
    assertEquals("***23", p.get("destination_masked"));
    assertEquals(true, p.get("sent"), "the single option is sent unasked");
    assertEquals(1, sink.messages().size(), String.valueOf(sink.messages()));
    SmsSink.Message sms = sink.messages().get(0);
    assertEquals(BOB_PHONE, sms.to());
    assertEquals("Bearer " + SmsSink.TOKEN, sms.authorization());
    assertTrue(sms.message().startsWith("Your verification code is "), sms.message());
    String code = sink.latestCode(BOB_PHONE);

    pauseForQuickLoginWindow();
    Response wrong = answer(r, "otp", "otp", "000000".equals(code) ? "111111" : "000000");
    assertEquals("invalid_credential", errorCode(wrong, "otp"));

    Response ok = answer(wrong, "otp", "otp", code);
    assertEquals(200, ok.statusCode(), ok.asString());
    Response tokens = exchange(CLIENT_SMS, ok.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("bob", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));
  }
}
