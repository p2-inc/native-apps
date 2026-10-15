package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.restassured.RestAssured.given;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.path.json.JsonPath;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
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

  /**
   * Partial user update as read-modify-write: with the declarative user profile a PUT replaces the
   * profile with what the representation carries, so a representation holding only {@code
   * requiredActions} or {@code attributes} would wipe first/last name and e-mail (and then trigger
   * {@code VERIFY_PROFILE}). The partial JSON's top-level fields are merged into the current one.
   */
  static void updateUser(String username, String partialJson) {
    String token = adminToken();
    String id = userId(username);
    Map<String, Object> current = given().auth().oauth2(token).get(adminRealmUrl() + "/users/" + id).then().statusCode(200).extract().jsonPath().getMap("$");
    Map<String, Object> merged = new LinkedHashMap<>(current);
    try {
      merged.putAll(new ObjectMapper().readValue(partialJson, new TypeReference<Map<String, Object>>() {}));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    given().auth().oauth2(token).contentType("application/json").body(merged)
        .put(adminRealmUrl() + "/users/" + id).then().statusCode(204);
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
