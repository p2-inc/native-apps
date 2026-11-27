package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.challenge;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.login;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Native registration and forgotten-password reset (spec/22 phase 3). {@code native_flow} (or OIDC
 * {@code prompt=create}) picks the realm's {@code native-registration} / {@code
 * native-reset-credentials} flow; the demo realm allows both. rita is created here and only here.
 */
@ExtendWith(TranscriptRecorder.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RegistrationIT {

  static final String RITA = "rita";
  static final String RITA_EMAIL = "rita@example.com";
  static final String RITA_PASSWORD = "rita-password-1";
  static final String RITA_NEW_PASSWORD = "rita-password-2";

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static Response start(String nativeFlow, Pkce pkce) {
    return challenge(
        params(
            "client_id", CLIENT,
            "response_type", "code",
            "scope", "openid profile",
            "code_challenge", pkce.challenge(),
            "code_challenge_method", "S256",
            "device_name", "NativeAuthIT",
            "native_flow", nativeFlow));
  }

  @Test
  @Order(1)
  void metadataAdvertisesRegistrationAndReset() {
    List<String> flows = given().get(realmUrl() + "/native-auth/metadata").then().statusCode(200).extract().jsonPath().getList("flows_supported");
    assertEquals(List.of("login", "registration", "reset_credentials"), flows);
  }

  @Test
  @Order(2)
  void fieldErrorsComeBackOnTheRegistrationChallenge() {
    Response r = start("registration", Pkce.s256());
    assertChallenge(r, "registration");
    Map<String, Object> d = descriptor(r, "registration");
    @SuppressWarnings("unchecked")
    Map<String, Object> params = (Map<String, Object>) d.get("params");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> attributes = (List<Map<String, Object>>) params.get("attributes");
    List<Object> names = attributes.stream().map(a -> a.get("name")).toList();
    assertTrue(names.containsAll(List.of("username", "email", "firstName", "lastName")), "attributes: " + names);
    Map<String, Object> email = attributes.stream().filter(a -> "email".equals(a.get("name"))).findFirst().orElseThrow();
    assertEquals("Email", email.get("display_name"), "the ${email} key resolves through the login theme");

    // bob's username is taken, the email is malformed, the passwords differ.
    r = answer(r, "registration", "username", "bob", "email", "not-an-email", "firstName", "Rita", "lastName", "Example", "password", "x", "password_confirm", "y");
    assertChallenge(r, "registration");
    assertEquals("invalid_profile", errorCode(r, "registration"));
    @SuppressWarnings("unchecked")
    Map<String, List<String>> fieldErrors = (Map<String, List<String>>) ((Map<String, Object>) descriptor(r, "registration").get("params")).get("field_errors");
    assertNotNull(fieldErrors, r.asString());
    assertTrue(fieldErrors.containsKey("username") && fieldErrors.containsKey("email") && fieldErrors.containsKey("password_confirm"), "field_errors: " + fieldErrors);
  }

  @Test
  @Order(3)
  void ritaRegistersAndIsSignedIn() {
    Pkce pkce = Pkce.s256();
    Response r = start("registration", pkce);
    assertChallenge(r, "registration");
    r = answer(r, "registration", "username", RITA, "email", RITA_EMAIL, "firstName", "Rita", "lastName", "Example", "password", RITA_PASSWORD, "password_confirm", RITA_PASSWORD);
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());

    // And she can sign in with the password she chose.
    Response again = login(CLIENT, Pkce.s256(), RITA, RITA_PASSWORD, null);
    assertEquals(200, again.statusCode(), again.asString());
  }

  @Test
  @Order(4)
  void ritaResetsHerPasswordWithAnEmailedCode() {
    Mailpit.clear();
    Pkce pkce = Pkce.s256();
    Response r = start("reset_credentials", pkce);
    assertChallenge(r, "username");
    r = answer(r, "username", "username", RITA_EMAIL);
    assertChallenge(r, "otp");
    @SuppressWarnings("unchecked")
    Map<String, Object> otp = (Map<String, Object>) descriptor(r, "otp").get("params");
    assertEquals(true, otp.get("sent"));
    assertEquals("r***@example.com", otp.get("destination_masked"));

    r = answer(r, "otp", "otp", "000000");
    assertEquals("invalid_credential", errorCode(r, "otp"));
    r = answer(r, "otp", "otp", Mailpit.latestCode(RITA_EMAIL));
    assertChallenge(r, "update_password");
    r = answer(r, "update_password", "password", RITA_NEW_PASSWORD, "password_confirm", RITA_NEW_PASSWORD);
    assertEquals(200, r.statusCode(), r.asString());
    assertEquals(200, exchange(CLIENT, r.jsonPath().getString("authorization_code"), pkce, null).statusCode());

    Response newPassword = login(CLIENT, Pkce.s256(), RITA, RITA_NEW_PASSWORD, null);
    assertEquals(200, newPassword.statusCode(), newPassword.asString());
  }

  @Test
  @Order(5)
  void anUnknownAccountLooksTheSameAndNoCodeWorks() {
    Mailpit.clear();
    Response r = start("reset_credentials", Pkce.s256());
    r = answer(r, "username", "username", "nobody@example.com");
    assertChallenge(r, "otp");
    @SuppressWarnings("unchecked")
    Map<String, Object> otp = (Map<String, Object>) descriptor(r, "otp").get("params");
    assertEquals(true, otp.get("sent"));
    assertEquals("n***@example.com", otp.get("destination_masked"));
    assertEquals(0, Mailpit.count(), "nothing was sent");
    r = answer(r, "otp", "otp", "123456");
    assertEquals("invalid_credential", errorCode(r, "otp"));
    assertFalse(r.asString().contains("unknown"));
  }

  @Test
  @Order(6)
  void anUnknownNativeFlowIsInvalidRequest() {
    Response r = start("magic", Pkce.s256());
    assertEquals(400, r.statusCode(), r.asString());
    assertEquals("invalid_request", r.jsonPath().getString("error"));
    assertNull(r.jsonPath().getString("auth_session"));
  }
}
