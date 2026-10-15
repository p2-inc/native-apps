package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.restassured.RestAssured.given;

import io.restassured.path.json.JsonPath;
import java.util.List;
import java.util.Map;

/** Small admin REST helpers the ITs use to arrange and restore realm state (not recorded). */
final class Admin {

  private Admin() {}

  static String userId(String username) {
    List<Map<String, Object>> users =
        given().auth().oauth2(adminToken()).queryParam("username", username).queryParam("exact", "true")
            .get(adminRealmUrl() + "/users").then().statusCode(200).extract().jsonPath().getList("$");
    if (users.isEmpty()) throw new AssertionError("no user " + username);
    return String.valueOf(users.get(0).get("id"));
  }

  static JsonPath user(String username) {
    return given().auth().oauth2(adminToken()).get(adminRealmUrl() + "/users/" + userId(username)).then().statusCode(200).extract().jsonPath();
  }

  /** Partial user update (Keycloak merges the fields present in the representation). */
  static void updateUser(String username, String partialJson) {
    given().auth().oauth2(adminToken()).contentType("application/json").body(partialJson)
        .put(adminRealmUrl() + "/users/" + userId(username)).then().statusCode(204);
  }

  static void resetPassword(String username, String password) {
    given().auth().oauth2(adminToken()).contentType("application/json")
        .body("{\"type\":\"password\",\"value\":\"" + password + "\",\"temporary\":false}")
        .put(adminRealmUrl() + "/users/" + userId(username) + "/reset-password").then().statusCode(204);
  }

  /** Enables / disables a registered required action by alias. */
  static void setRequiredActionEnabled(String alias, boolean enabled) {
    String token = adminToken();
    Map<String, Object> rep =
        given().auth().oauth2(token).get(adminRealmUrl() + "/authentication/required-actions/" + alias).then().statusCode(200).extract().jsonPath().getMap("$");
    rep.put("enabled", enabled);
    given().auth().oauth2(token).contentType("application/json").body(rep)
        .put(adminRealmUrl() + "/authentication/required-actions/" + alias).then().statusCode(204);
  }

  /** The realm's password policy string (e.g. {@code length(8)}); empty clears it. */
  static void setPasswordPolicy(String policy) {
    NativeAuthIT.updateRealm("{\"passwordPolicy\": \"" + policy + "\"}");
  }
}
