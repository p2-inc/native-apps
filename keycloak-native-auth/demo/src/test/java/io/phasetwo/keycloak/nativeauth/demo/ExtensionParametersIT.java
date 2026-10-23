package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * {@code x_*} extension parameters (spec/03 §2.3): accepted on initial and continuation requests
 * without changing the flow, and bounded in number and size.
 */
@ExtendWith(TranscriptRecorder.class)
class ExtensionParametersIT {

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static Map<String, String> initial(Pkce pkce) {
    return params(
        "client_id", CLIENT,
        "response_type", "code",
        "scope", "openid profile",
        "code_challenge", pkce.challenge(),
        "code_challenge_method", "S256");
  }

  @Test
  void extensionParametersAreAcceptedOnEveryRequest() {
    Pkce pkce = Pkce.s256();
    Map<String, String> start = initial(pkce);
    start.put("x_device_signal", "a1b2c3d4");
    Response r = challenge(start);
    assertChallenge(r, "username");
    r = answer(r, "username", "username", "bob", "x_device_signal", "a1b2c3d4", "x_risk_score", "12");
    assertChallenge(r, "password");
    r = answer(r, "password", "password", "bob-password", "x_risk_score", "12");
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }

  @Test
  void moreThanSixteenExtensionParametersAreInvalidRequest() {
    Map<String, String> start = initial(Pkce.s256());
    for (int i = 0; i < 17; i++) start.put("x_p" + i, "v");
    Response r = challenge(start);
    assertEquals(400, r.statusCode(), r.asString());
    assertEquals("invalid_request", r.jsonPath().getString("error"));
  }

  @Test
  void anOversizedExtensionValueIsInvalidRequestAndKeepsTheSession() {
    Response r = challenge(initial(Pkce.s256()));
    assertChallenge(r, "username");
    Response refused = answer(r, "username", "username", "bob", "x_blob", "a".repeat(2049));
    assertEquals(400, refused.statusCode(), refused.asString());
    assertEquals("invalid_request", refused.jsonPath().getString("error"));
    // The rejected request did not touch the session: the earlier auth_session still answers.
    assertChallenge(answer(r, "username", "username", "bob"), "password");
  }
}
