package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertOffers;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.challengeId;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * DPoP at the challenge endpoint (spec/03 §8, spec/13 D3): a proof on the first request binds the
 * in-flow {@code auth_session}, the code and the post-login {@code auth_session} to the key.
 */
@ExtendWith(TranscriptRecorder.class)
class DPoPBindingIT {

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  static String challengeUrl() {
    return realmUrl() + "/native-auth/challenge";
  }

  static String tokenUrl() {
    return realmUrl() + "/protocol/openid-connect/token";
  }

  static Response post(Map<String, String> form, String proof) {
    var req = given().accept("application/json").contentType("application/x-www-form-urlencoded; charset=UTF-8").formParams(form);
    if (proof != null) req = req.header("DPoP", proof);
    return req.post(challengeUrl()).andReturn();
  }

  static Map<String, String> startParams(String clientId, Pkce pkce) {
    return params(
        "client_id", clientId, "response_type", "code", "scope", "openid profile",
        "code_challenge", pkce.challenge(), "code_challenge_method", "S256", "device_name", "NativeAuthIT");
  }

  static Map<String, String> answerParams(Response previous, String type, String... fields) {
    Map<String, String> p = params("auth_session", previous.jsonPath().getString("auth_session"), "challenge_type", type, "challenge_id", challengeId(previous, type));
    for (int i = 0; i < fields.length; i += 2) p.put(fields[i], fields[i + 1]);
    return p;
  }

  static Response exchange(String code, Pkce pkce, DPoPProofs key) {
    var req = given().formParam("grant_type", "authorization_code").formParam("client_id", CLIENT).formParam("code", code).formParam("code_verifier", pkce.verifier());
    if (key != null) req = req.header("DPoP", key.proof("POST", tokenUrl()));
    return req.post(tokenUrl()).andReturn();
  }

  @Test
  void metadataAdvertisesTheVerifiedProofAlgorithms() {
    given().get(realmUrl() + "/native-auth/metadata").then().statusCode(200)
        .body("dpop_signing_alg_values_supported", hasItem("ES256"))
        .body("authorization_endpoint", org.hamcrest.Matchers.equalTo(realmUrl() + "/protocol/openid-connect/auth"));
  }

  /** bob's login with proofs from {@code key} on every request; returns the 200 with the code. */
  static Response loginBobWithProofs(DPoPProofs key, Pkce pkce) {
    Response r = post(startParams(CLIENT, pkce), key.proof("POST", challengeUrl()));
    assertChallenge(r, "username");
    r = post(answerParams(r, "username", "username", "bob"), key.proof("POST", challengeUrl()));
    assertOffers(r, "password");
    r = post(answerParams(r, "password", "password", "bob-password"), key.proof("POST", challengeUrl()));
    assertEquals(200, r.statusCode(), r.asString());
    return r;
  }

  @Test
  void sessionCodeAndPostLoginSessionAreBoundToTheProofKey() {
    DPoPProofs key = new DPoPProofs();
    DPoPProofs other = new DPoPProofs();
    Pkce pkce = Pkce.s256();
    Response r = post(startParams(CLIENT, pkce), key.proof("POST", challengeUrl()));
    assertChallenge(r, "username");

    // Same session, no proof / another key: refused; the session itself survives.
    Response noProof = post(answerParams(r, "username", "username", "bob"), null);
    assertEquals(400, noProof.statusCode(), noProof.asString());
    assertEquals("invalid_session", noProof.jsonPath().getString("error"));
    Response otherKey = post(answerParams(r, "username", "username", "bob"), other.proof("POST", challengeUrl()));
    assertEquals(400, otherKey.statusCode(), otherKey.asString());
    assertEquals("invalid_session", otherKey.jsonPath().getString("error"));

    r = post(answerParams(r, "username", "username", "bob"), key.proof("POST", challengeUrl()));
    assertOffers(r, "password");
    r = post(answerParams(r, "password", "password", "bob-password"), key.proof("POST", challengeUrl()));
    assertEquals(200, r.statusCode(), r.asString());
    String code = r.jsonPath().getString("authorization_code");
    String postLogin = r.jsonPath().getString("auth_session");

    // The code carries dpop_jkt: Keycloak's token endpoint refuses an exchange without the key, and
    // a failed exchange consumes the code (single use), so the negative cases need their own logins.
    Response unbound = exchange(code, pkce, null);
    assertEquals(400, unbound.statusCode(), unbound.asString());
    Pkce pkceWrong = Pkce.s256();
    Response wrongKey = exchange(loginBobWithProofs(key, pkceWrong).jsonPath().getString("authorization_code"), pkceWrong, other);
    assertEquals(400, wrongKey.statusCode(), wrongKey.asString());
    Pkce pkceOk = Pkce.s256();
    Response okLogin = loginBobWithProofs(key, pkceOk);
    Response tokens = exchange(okLogin.jsonPath().getString("authorization_code"), pkceOk, key);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    postLogin = okLogin.jsonPath().getString("auth_session");
    assertEquals("DPoP", tokens.jsonPath().getString("token_type"));
    assertEquals(key.thumbprint(), claims(tokens.jsonPath().getString("access_token")).getString("cnf.jkt"));

    // The post-login auth_session is bound too: a step-up needs the same key.
    Map<String, String> stepUp = startParams(CLIENT, Pkce.s256());
    stepUp.put("auth_session", postLogin);
    stepUp.put("acr_values", "2");
    Response stepUpNoProof = post(stepUp, null);
    assertEquals(400, stepUpNoProof.statusCode(), stepUpNoProof.asString());
    assertEquals("invalid_session", stepUpNoProof.jsonPath().getString("error"));
    Response stepUpOtherKey = post(stepUp, other.proof("POST", challengeUrl()));
    assertEquals("invalid_session", stepUpOtherKey.jsonPath().getString("error"));
    Response stepUpOk = post(stepUp, key.proof("POST", challengeUrl()));
    assertOffers(stepUpOk, "password");
    assertNotNull(stepUpOk.jsonPath().getString("auth_session"));
  }

  @Test
  void aSessionStartedWithoutAProofStaysUnbound() {
    Pkce pkce = Pkce.s256();
    Response r = post(startParams(CLIENT, pkce), null);
    assertChallenge(r, "username");
    // A later (valid) proof is verified but does not bind; the exchange works without a key.
    r = post(answerParams(r, "username", "username", "bob"), new DPoPProofs().proof("POST", challengeUrl()));
    assertOffers(r, "password");
    r = post(answerParams(r, "password", "password", "bob-password"), null);
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchange(r.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("Bearer", tokens.jsonPath().getString("token_type"));
  }

  @Test
  void anInvalidProofIsRejectedBeforeAnythingElse() {
    Response garbage = post(startParams(CLIENT, Pkce.s256()), "not.a.proof");
    assertEquals(400, garbage.statusCode(), garbage.asString());
    assertEquals("invalid_dpop_proof", garbage.jsonPath().getString("error"));

    DPoPProofs key = new DPoPProofs();
    Response wrongUrl = post(startParams(CLIENT, Pkce.s256()), key.proof("POST", realmUrl() + "/somewhere-else"));
    assertEquals(400, wrongUrl.statusCode(), wrongUrl.asString());
    assertEquals("invalid_dpop_proof", wrongUrl.jsonPath().getString("error"));
  }
}
