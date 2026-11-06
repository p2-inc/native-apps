package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.setRealmAttribute;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * A native flow that reaches a browser form authenticator (spec/03 §3.4, spec/08 R8): {@code 500
 * server_error} by default, {@code redirect_to_web} with {@code reason: execution:<provider id>}
 * when the realm attribute {@code native-auth.non-native-execution} is {@code redirect_to_web}. The
 * flow and its client are created here; nothing shared is changed except the attribute, restored.
 */
@ExtendWith(TranscriptRecorder.class)
class NonNativeExecutionIT {

  static final String CLIENT_FORM = "demo-native-form";
  static final String FLOW = "native-with-form";
  static final String FORM_AUTHENTICATOR = "auth-username-password-form";

  @BeforeAll
  static void arrange() {
    baseUrl();
    String token = adminToken();
    String flows = adminRealmUrl() + "/authentication/flows";
    given().auth().oauth2(token).contentType("application/json")
        .body(Map.of("alias", FLOW, "providerId", "basic-flow", "topLevel", true, "builtIn", false, "description", "native flow with a browser form (NonNativeExecutionIT)"))
        .post(flows).then().statusCode(201);
    given().auth().oauth2(token).contentType("application/json").body(Map.of("provider", FORM_AUTHENTICATOR))
        .post(flows + "/" + FLOW + "/executions/execution").then().statusCode(201);
    Map<String, Object> execution =
        given().auth().oauth2(token).get(flows + "/" + FLOW + "/executions").then().statusCode(200).extract().jsonPath().<Map<String, Object>>getList("$").get(0);
    execution.put("requirement", "REQUIRED");
    given().auth().oauth2(token).contentType("application/json").body(execution).put(flows + "/" + FLOW + "/executions").then().statusCode(204);
    given().auth().oauth2(token).contentType("application/json")
        .body(
            Map.of(
                "clientId", CLIENT_FORM,
                "enabled", true,
                "publicClient", true,
                "standardFlowEnabled", true,
                "redirectUris", List.of("demoapp://auth/callback"),
                "attributes", Map.of("pkce.code.challenge.method", "S256", "native-auth.enabled", "true", "native-auth.flow-alias", FLOW)))
        .post(adminRealmUrl() + "/clients").then().statusCode(201);
  }

  @Test
  void aFormAuthenticatorIsAServerErrorByDefault() {
    Response r = start(CLIENT_FORM, Pkce.s256());
    assertEquals(500, r.statusCode(), r.asString());
    assertEquals("server_error", r.jsonPath().getString("error"));
  }

  @Test
  void aFormAuthenticatorRedirectsToWebWhenTheRealmSaysSo() {
    setRealmAttribute("native-auth.non-native-execution", "redirect_to_web");
    try {
      Response r = start(CLIENT_FORM, Pkce.s256());
      assertEquals(403, r.statusCode(), r.asString());
      assertEquals("redirect_to_web", r.jsonPath().getString("error"));
      assertEquals("execution:" + FORM_AUTHENTICATOR, r.jsonPath().getString("reason"));
      assertNotNull(r.jsonPath().getString("request_uri"));
      assertTrue(r.jsonPath().getString("request_uri").startsWith("urn:ietf:params:oauth:request_uri:"), r.asString());
      assertEquals("demoapp://auth/callback", r.jsonPath().getString("redirect_uri"));
    } finally {
      setRealmAttribute("native-auth.non-native-execution", "error");
    }
  }
}
