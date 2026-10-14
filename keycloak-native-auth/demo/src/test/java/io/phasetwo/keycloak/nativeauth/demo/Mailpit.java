package io.phasetwo.keycloak.nativeauth.demo;

import static io.restassured.RestAssured.given;

import io.restassured.path.json.JsonPath;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The mailpit HTTP API the email OTP tests read the delivered codes from. */
final class Mailpit {

  private static final Pattern CODE = Pattern.compile("code is (\\d{4,10})");

  private Mailpit() {}

  static void clear() {
    given().delete(KeycloakContainerSupport.mailpitUrl() + "/api/v1/messages").then().statusCode(200);
  }

  static int count() {
    return given().get(KeycloakContainerSupport.mailpitUrl() + "/api/v1/messages").then().statusCode(200).extract().jsonPath().getInt("total");
  }

  /** The code in the newest message addressed to {@code email}; fails when there is none. */
  static String latestCode(String email) {
    JsonPath list = given().get(KeycloakContainerSupport.mailpitUrl() + "/api/v1/messages?limit=50").then().statusCode(200).extract().jsonPath();
    List<Map<String, Object>> messages = list.getList("messages");
    for (Map<String, Object> message : messages) {
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> to = (List<Map<String, Object>>) message.get("To");
      if (to == null || to.stream().noneMatch(t -> email.equalsIgnoreCase(String.valueOf(t.get("Address"))))) continue;
      String text =
          given().get(KeycloakContainerSupport.mailpitUrl() + "/api/v1/message/" + message.get("ID")).then().statusCode(200).extract().jsonPath().getString("Text");
      Matcher m = CODE.matcher(text == null ? "" : text);
      if (m.find()) return m.group(1);
      throw new AssertionError("no code in message to " + email + ": " + text);
    }
    throw new AssertionError("no message to " + email + " in mailpit");
  }
}
