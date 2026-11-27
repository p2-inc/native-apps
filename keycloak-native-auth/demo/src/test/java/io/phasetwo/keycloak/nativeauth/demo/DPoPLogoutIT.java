package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.DPoPBindingIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.DPoPBindingIT.loginBobWithProofs;
import static io.phasetwo.keycloak.nativeauth.demo.DPoPBindingIT.tokenUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Ending a DPoP-bound session (the SDKs' {@code CredentialsManager.logout()}): Keycloak's logout
 * endpoint refuses a DPoP-bound refresh token even with a proof ({@code TokenManager.verifyRefreshToken}
 * reads a proof only the token endpoint parses), and revocation with a proof ends the session. When a
 * Keycloak release fixes the logout endpoint, the first assertion fails and the SDKs can go back to it.
 */
class DPoPLogoutIT {

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static Response refresh(String refreshToken, DPoPProofs key) {
    return given()
        .header("DPoP", key.proof("POST", tokenUrl()))
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", CLIENT)
        .formParam("refresh_token", refreshToken)
        .post(tokenUrl())
        .andReturn();
  }

  static String boundRefreshToken(DPoPProofs key) {
    Pkce pkce = Pkce.s256();
    Response tokens = exchange(loginBobWithProofs(key, pkce).jsonPath().getString("authorization_code"), pkce, key);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("DPoP", tokens.jsonPath().getString("token_type"));
    return tokens.jsonPath().getString("refresh_token");
  }

  @Test
  void theLogoutEndpointRefusesABoundRefreshTokenAndRevocationEndsTheSession() {
    DPoPProofs key = new DPoPProofs();
    String refreshToken = boundRefreshToken(key);
    String logoutUrl = realmUrl() + "/protocol/openid-connect/logout";

    Response logout =
        given()
            .header("DPoP", key.proof("POST", logoutUrl))
            .formParam("client_id", CLIENT)
            .formParam("refresh_token", refreshToken)
            .post(logoutUrl)
            .andReturn();
    assertEquals(400, logout.statusCode(), logout.asString());
    assertEquals("invalid_grant", logout.jsonPath().getString("error"));
    assertEquals(200, refresh(refreshToken, key).statusCode(), "the session survived the refused logout");

    String revokeUrl = realmUrl() + "/protocol/openid-connect/revoke";
    Response revoke =
        given()
            .header("DPoP", key.proof("POST", revokeUrl))
            .formParam("client_id", CLIENT)
            .formParam("token", refreshToken)
            .formParam("token_type_hint", "refresh_token")
            .post(revokeUrl)
            .andReturn();
    assertEquals(200, revoke.statusCode(), revoke.asString());
    Response after = refresh(refreshToken, key);
    assertEquals(400, after.statusCode(), after.asString());
    assertEquals("invalid_grant", after.jsonPath().getString("error"));
  }
}
