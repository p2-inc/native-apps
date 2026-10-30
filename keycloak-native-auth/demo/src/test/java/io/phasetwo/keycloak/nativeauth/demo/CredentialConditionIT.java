package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertOffers;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.phasetwo.keycloak.nativeauth.demo.PasskeyIT.flatten;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Keycloak's stock "Condition - credential" ({@code conditional-credential}) sees a native-passkey
 * login: {@code native-passkey} ends with {@code context.success(webauthn-passwordless)}, which the
 * processor records in the {@code AUTHN_CREDENTIALS} auth note the condition reads. Each demo flow
 * is copied, its second-factor sub-flow gains the condition (credentials {@code
 * webauthn-passwordless}, not included), and a new client is bound to the copy, so the shared flows
 * and clients the other ITs use are untouched.
 */
@ExtendWith(TranscriptRecorder.class)
class CredentialConditionIT {

  static final String CLIENT_ALLOW_LIST = "demo-ios-cc";
  static final String CLIENT_PASSKEY_FIRST = "demo-ios-passkey-cc";

  @BeforeAll
  static void arrange() {
    baseUrl();
    TranscriptRecorder.scenario("CredentialConditionIT.setupAlicePasskey", PasskeyIT::alicePasskey);
    copyFlowWithPasskeySkipsSecondFactor("native", "native-cc");
    copyFlowWithPasskeySkipsSecondFactor("native-passkey-first", "native-passkey-first-cc");
    createClient(CLIENT_ALLOW_LIST, "native-cc");
    createClient(CLIENT_PASSKEY_FIRST, "native-passkey-first-cc");
  }

  @AfterAll
  static void restore() {
    PasskeyIT.forgetAlicePasskey();
  }

  // ---------------------------------------------------------------------------------------------
  // username -> [passkey | password] -> conditional second factor ('native')

  @Test
  void allowListPasskeyLoginSkipsTheSecondFactor() {
    SoftwareAuthenticator passkey = PasskeyIT.alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_ALLOW_LIST, pkce);
    r = answer(r, "username", "username", "alice");
    assertChallenge(r, "passkey", "password");
    r = answer(r, "passkey", flatten(passkey.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
    assertCode(r, CLIENT_ALLOW_LIST, pkce);
  }

  @Test
  void allowListPasswordLoginStillAsksForTheSecondFactor() {
    PasskeyIT.alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_ALLOW_LIST, pkce);
    r = answer(r, "username", "username", "alice");
    r = answer(r, "password", "password", "alice-password");
    assertOffers(r, "totp");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertCode(r, CLIENT_ALLOW_LIST, pkce);
  }

  // ---------------------------------------------------------------------------------------------
  // [discoverable passkey | username + password] -> conditional second factor ('native-passkey-first')

  @Test
  void discoverablePasskeyLoginSkipsTheSecondFactor() {
    SoftwareAuthenticator passkey = PasskeyIT.alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_PASSKEY_FIRST, pkce);
    assertChallenge(r, "passkey", "username");
    r = answer(r, "passkey", flatten(passkey.assertion(r.jsonPath().getString("challenges[0].params.challenge"))));
    assertCode(r, CLIENT_PASSKEY_FIRST, pkce);
  }

  @Test
  void passkeyFirstPasswordLoginStillAsksForTheSecondFactor() {
    PasskeyIT.alicePasskey();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_PASSKEY_FIRST, pkce);
    r = answer(r, "username", "username", "alice");
    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp");
    r = answer(r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertCode(r, CLIENT_PASSKEY_FIRST, pkce);
  }

  // ---------------------------------------------------------------------------------------------
  // helpers (admin REST, not recorded)

  static void assertCode(Response r, String clientId, Pkce pkce) {
    assertEquals(200, r.statusCode(), r.asString());
    String code = r.jsonPath().getString("authorization_code");
    assertNotNull(code, r.asString());
    assertEquals(200, exchange(clientId, code, pkce, null).statusCode());
  }

  /** Copies {@code source} and adds the condition to the copy's top-level CONDITIONAL sub-flow. */
  static void copyFlowWithPasskeySkipsSecondFactor(String source, String copy) {
    String token = adminToken();
    String flows = adminRealmUrl() + "/authentication/flows";
    given().auth().oauth2(token).contentType("application/json").body(Map.of("newName", copy))
        .post(flows + "/" + source + "/copy").then().statusCode(201);

    List<Map<String, Object>> executions =
        given().auth().oauth2(token).get(flows + "/" + copy + "/executions").then().statusCode(200).extract().jsonPath().getList("$");
    String secondFactor =
        executions.stream()
            .filter(e -> Integer.valueOf(0).equals(e.get("level")) && "CONDITIONAL".equals(e.get("requirement")) && Boolean.TRUE.equals(e.get("authenticationFlow")))
            .map(e -> (String) e.get("displayName"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no conditional sub-flow in " + copy + ": " + executions));

    given().auth().oauth2(token).contentType("application/json").body(Map.of("provider", "conditional-credential"))
        .post(flows + "/" + secondFactor + "/executions/execution").then().statusCode(201);
    Map<String, Object> condition =
        given().auth().oauth2(token).get(flows + "/" + secondFactor + "/executions").then().statusCode(200).extract().jsonPath()
            .<Map<String, Object>>getList("$").stream()
            .filter(e -> "conditional-credential".equals(e.get("providerId")))
            .findFirst()
            .orElseThrow();
    condition.put("requirement", "REQUIRED");
    given().auth().oauth2(token).contentType("application/json").body(condition)
        .put(flows + "/" + secondFactor + "/executions").then().statusCode(204);
    given().auth().oauth2(token).contentType("application/json")
        .body(Map.of("alias", copy + "-not-after-passkey", "config", Map.of("credentials", "webauthn-passwordless", "included", "false")))
        .post(adminRealmUrl() + "/authentication/executions/" + condition.get("id") + "/config").then().statusCode(201);
  }

  static void createClient(String clientId, String flowAlias) {
    given().auth().oauth2(adminToken()).contentType("application/json")
        .body(
            Map.of(
                "clientId", clientId,
                "enabled", true,
                "publicClient", true,
                "standardFlowEnabled", true,
                "redirectUris", List.of("demoapp://auth/callback"),
                "attributes",
                    Map.of("pkce.code.challenge.method", "S256", "native-auth.enabled", "true", "native-auth.flow-alias", flowAlias)))
        .post(adminRealmUrl() + "/clients").then().statusCode(201);
  }
}
