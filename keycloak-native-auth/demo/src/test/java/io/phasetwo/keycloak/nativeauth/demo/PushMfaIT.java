package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminRealmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.adminToken;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.params;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.challengeId;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Push MFA (spec/02 §3 scenarios A, B, C; spec/03 §4.7, §4.15, §7; spec/14 D9/D10) with the
 * ba-itsys extension and the APNs sender posting to a fake APNs:
 *
 * <ol>
 *   <li>C: alice enrols from inside the app — a DPoP-bound native login, {@code
 *       /native-auth/push/enroll/start}, then {@code /push-mfa/enroll/complete} with the DPoP key
 *       as device key and the native access token as device token (§7.1).
 *   <li>A: a browser login of alice on the {@code browser-push} flow sends a push through the
 *       sink; the "phone" (this test, with the enrolment key) lists and approves it; the browser
 *       completes.
 *   <li>B: a native login offers {@code [totp, push]}; the push is only sent on {@code
 *       action=resend}; number match; deny and the alternative.
 *   <li>judy enrols mid-flow through {@code native-push-enroll} in a DPoP-bound session.
 * </ol>
 */
@ExtendWith(TranscriptRecorder.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PushMfaIT {

  static final String ALICE_DEVICE_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  static final String ALICE_CREDENTIAL_ID = "cred-alice-test";
  static final String ALICE_DEVICE_ID = "device-alice-test";
  private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");

  /** alice's device key: the DPoP key of her native login, reused as the push device key (§7.1). */
  private static DPoPProofs aliceKey;
  private static String aliceAccessToken;
  private static String aliceUserId;

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @AfterAll
  static void restore() {
    // alice's push credential would turn every other IT's second factor into [totp, push].
    deletePushCredentials("alice");
    deletePushCredentials("judy");
    Admin.updateUser("judy", "{\"requiredActions\":[\"push-mfa-register\"]}");
    Admin.updateUser("alice", "{\"enabled\":true}");
  }

  // ---------------------------------------------------------------------------------------------
  // helpers

  static String challengeUrl() {
    return realmUrl() + "/native-auth/challenge";
  }

  static Response challengeWithProof(DPoPProofs key, Map<String, String> form) {
    return given().accept("application/json").contentType("application/x-www-form-urlencoded; charset=UTF-8")
        .header("DPoP", key.proof("POST", challengeUrl())).formParams(form).post(challengeUrl()).andReturn();
  }

  static Response answerWithProof(DPoPProofs key, Response previous, String type, String... fields) {
    Map<String, String> p = params("auth_session", previous.jsonPath().getString("auth_session"), "challenge_type", type, "challenge_id", challengeId(previous, type));
    for (int i = 0; i < fields.length; i += 2) p.put(fields[i], fields[i + 1]);
    return challengeWithProof(key, p);
  }

  static Response startWithProof(DPoPProofs key, String clientId, Pkce pkce) {
    return challengeWithProof(key, params("client_id", clientId, "response_type", "code", "scope", "openid profile", "code_challenge", pkce.challenge(), "code_challenge_method", "S256", "device_name", "NativeAuthIT"));
  }

  static Response exchangeWithProof(DPoPProofs key, String clientId, String code, Pkce pkce) {
    String url = realmUrl() + "/protocol/openid-connect/token";
    return given().header("DPoP", key.proof("POST", url)).formParam("grant_type", "authorization_code").formParam("client_id", clientId)
        .formParam("code", code).formParam("code_verifier", pkce.verifier()).post(url).andReturn();
  }

  /** The device API headers (spec/03 §7.1): the native DPoP-bound token plus a proof with ath, sub and deviceId. */
  static io.restassured.specification.RequestSpecification device(DPoPProofs key, String method, String url, String accessToken, String userId, String deviceId) {
    return given().accept("application/json")
        .header("Authorization", "DPoP " + accessToken)
        .header("DPoP", key.proof(method, url, accessToken, Map.of("sub", userId, "deviceId", deviceId)));
  }

  static String deviceApi(String suffix) {
    return realmUrl() + "/push-mfa/" + suffix;
  }

  static JsonPath jwtPayload(String jwt) {
    return claims(jwt);
  }

  /** The device-signed enrolment JWT ba-itsys expects at /push-mfa/enroll/complete (spec/03 §7). */
  static String enrolmentJwt(DPoPProofs key, JsonPath enrollment, String credentialId, String deviceId, String providerType, String providerId, String label) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("sub", enrollment.getString("sub"));
    payload.put("enrollmentId", enrollment.getString("enrollmentId"));
    payload.put("nonce", enrollment.getString("nonce"));
    payload.put("exp", System.currentTimeMillis() / 1000 + 120);
    payload.put("cnf", Map.of("jwk", jwkMap(key)));
    payload.put("credentialId", credentialId);
    payload.put("deviceId", deviceId);
    payload.put("deviceType", "ios");
    payload.put("deviceLabel", label);
    payload.put("pushProviderType", providerType);
    if (providerId != null) payload.put("pushProviderId", providerId);
    return key.signJwt(ApnsSink.json(payload));
  }

  static Map<String, Object> jwkMap(DPoPProofs key) {
    return JsonPath.from(key.jwk()).getMap("$");
  }

  static String loginJwt(DPoPProofs key, String cid, String credentialId, String deviceId, String action, String userVerification) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("cid", cid);
    payload.put("credId", credentialId);
    payload.put("deviceId", deviceId);
    payload.put("action", action);
    payload.put("exp", System.currentTimeMillis() / 1000 + 120);
    if (userVerification != null) payload.put("userVerification", userVerification);
    return key.signJwt(ApnsSink.json(payload));
  }

  static List<Map<String, Object>> pushCredentials(String username) {
    return PasskeyIT.credentials(username).stream().filter(c -> "push-mfa".equals(c.get("type"))).toList();
  }

  static void deletePushCredentials(String username) {
    String token = adminToken();
    String userId = Admin.userId(username);
    for (Map<String, Object> c : pushCredentials(username)) {
      given().auth().oauth2(token).delete(adminRealmUrl() + "/users/" + userId + "/credentials/" + c.get("id")).then().statusCode(204);
    }
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> pushParams(Response r) {
    return (Map<String, Object>) descriptor(r, "push").get("params");
  }

  private static String formAction(String html) {
    Matcher m = FORM_ACTION.matcher(html);
    assertTrue(m.find(), "no form in page:\n" + html);
    return m.group(1).replace("&amp;", "&");
  }

  // ---------------------------------------------------------------------------------------------

  @Test
  @Order(1)
  void aliceEnrolsHerDeviceFromInsideTheApp() {
    given().get(realmUrl() + "/native-auth/metadata").then().statusCode(200)
        .body("push.enabled", org.hamcrest.Matchers.equalTo(true))
        .body("push.device_token", org.hamcrest.Matchers.equalTo("native"))
        .body("push.enroll_start_endpoint", org.hamcrest.Matchers.equalTo(realmUrl() + "/native-auth/push/enroll/start"))
        .body("push.device_api_base", org.hamcrest.Matchers.equalTo(realmUrl() + "/push-mfa"))
        .body("push.push_provider_types", org.hamcrest.Matchers.hasItems("apns", "none", "log"))
        .body("challenge_types_supported", org.hamcrest.Matchers.hasItems("push", "push_enrollment"));

    // 1. A DPoP-bound native login (spec/03 §8): the key becomes the device key.
    aliceKey = new DPoPProofs();
    Pkce pkce = Pkce.s256();
    Response r = startWithProof(aliceKey, CLIENT, pkce);
    r = answerWithProof(aliceKey, r, "username", "username", "alice");
    r = answerWithProof(aliceKey, r, "password", "password", "alice-password");
    r = answerWithProof(aliceKey, r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchangeWithProof(aliceKey, CLIENT, r.jsonPath().getString("authorization_code"), pkce);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("DPoP", tokens.jsonPath().getString("token_type"));
    aliceAccessToken = tokens.jsonPath().getString("access_token");
    aliceUserId = claims(aliceAccessToken).getString("sub");
    assertEquals(aliceKey.thumbprint(), claims(aliceAccessToken).getString("cnf.jkt"));

    // 2. /native-auth/push/enroll/start (spec/03 §7 b) with the native token.
    String startUrl = realmUrl() + "/native-auth/push/enroll/start";
    Response start = given().accept("application/json").header("Authorization", "DPoP " + aliceAccessToken)
        .header("DPoP", aliceKey.proof("POST", startUrl, aliceAccessToken)).post(startUrl).andReturn();
    assertEquals(200, start.statusCode(), start.asString());
    String enrollmentToken = start.jsonPath().getString("enrollment_token");
    assertEquals(realmUrl() + "/push-mfa", start.jsonPath().getString("device_api_base"));
    assertEquals(aliceUserId, start.jsonPath().getString("user_id"));
    assertTrue(start.jsonPath().getLong("expires_in") > 0);
    JsonPath enrollment = jwtPayload(enrollmentToken);
    assertEquals("push-enroll-challenge", enrollment.getString("typ"));
    assertEquals(aliceUserId, enrollment.getString("sub"));
    assertEquals("alice", enrollment.getString("username"));

    // 3. /push-mfa/enroll/complete with the device JWT (cnf.jwk = the DPoP key) under the native token.
    String completeUrl = deviceApi("enroll/complete");
    Response complete = device(aliceKey, "POST", completeUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + enrolmentJwt(aliceKey, enrollment, ALICE_CREDENTIAL_ID, ALICE_DEVICE_ID, "apns", ALICE_DEVICE_TOKEN, "Alice's test iPhone") + "\"}")
        .post(completeUrl).andReturn();
    assertEquals(200, complete.statusCode(), complete.asString());
    assertEquals("enrolled", complete.jsonPath().getString("status"));
    assertEquals(1, pushCredentials("alice").size());
    assertEquals("Alice's test iPhone", pushCredentials("alice").get(0).get("userLabel"));
  }

  @Test
  @Order(2)
  void scenarioA_aBrowserLoginIsApprovedOnTheEnrolledDevice() throws Exception {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    ApnsSink apns = KeycloakContainerSupport.apnsSink();
    apns.clear();
    RedirectToWebIT.Browser browser = new RedirectToWebIT.Browser();
    Pkce browserPkce = Pkce.s256();
    String authUrl = realmUrl() + "/protocol/openid-connect/auth?client_id=web-app&response_type=code&scope=openid&state=s1"
        + "&code_challenge=" + browserPkce.challenge() + "&code_challenge_method=S256&redirect_uri="
        + URLEncoder.encode("http://localhost:3000/cb", StandardCharsets.UTF_8);
    HttpResponse<String> page = browser.get(authUrl);
    for (int hops = 0; page.statusCode() == 302 && hops < 3; hops++) {
      String location = page.headers().firstValue("Location").orElseThrow();
      assertTrue(location.startsWith(realmUrl()), "bounced out of the realm: " + location);
      page = browser.get(location);
    }
    assertEquals(200, page.statusCode(), page.body());
    HttpResponse<String> wait = browser.post(formAction(page.body()), "username=alice&password=alice-password");
    assertEquals(200, wait.statusCode(), "the push-wait page: " + wait.body().substring(0, Math.min(500, wait.body().length())));
    assertTrue(wait.body().contains("challengeId"), wait.body());

    // The APNs sender posted the confirm token to the fake APNs with Apple's headers.
    ApnsSink.Delivery delivery = apns.latest(ALICE_DEVICE_TOKEN);
    assertEquals(ApnsSink.TOPIC, delivery.topic());
    assertEquals("alert", delivery.pushType());
    assertTrue(delivery.authorization().startsWith("bearer "), delivery.authorization());
    assertNotNull(delivery.confirmToken());
    assertEquals(delivery.cid(), delivery.collapseId());
    JsonPath confirm = jwtPayload(delivery.confirmToken());
    assertEquals(ALICE_CREDENTIAL_ID, confirm.getString("credId"));
    assertEquals(delivery.cid(), confirm.getString("cid"));
    assertEquals(1, delivery.body().path("aps").path("mutable-content").asInt());

    // The phone fetches the pending challenge with the native token (spec/03 §7.1) and approves it.
    String pendingUrl = deviceApi("login/pending");
    Response pending = device(aliceKey, "GET", pendingUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).queryParam("userId", aliceUserId).get(pendingUrl).andReturn();
    assertEquals(200, pending.statusCode(), pending.asString());
    List<Map<String, Object>> challenges = pending.jsonPath().getList("challenges");
    assertEquals(1, challenges.size(), pending.asString());
    assertEquals(delivery.cid(), challenges.get(0).get("cid"));
    assertEquals("web-app", challenges.get(0).get("clientId"));
    assertEquals("alice", challenges.get(0).get("username"));
    String respondUrl = deviceApi("login/challenges/" + delivery.cid() + "/respond");
    Response approved = device(aliceKey, "POST", respondUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + loginJwt(aliceKey, delivery.cid(), ALICE_CREDENTIAL_ID, ALICE_DEVICE_ID, "approve", null) + "\"}").post(respondUrl).andReturn();
    assertEquals(200, approved.statusCode(), approved.asString());
    assertEquals("approved", approved.jsonPath().getString("status"));

    // The browser's waiting form is submitted (what its SSE listener does) and the login completes.
    HttpResponse<String> done = browser.post(formAction(wait.body()), "challengeId=" + delivery.cid());
    assertEquals(302, done.statusCode(), done.body());
    String location = done.headers().firstValue("Location").orElseThrow();
    assertTrue(location.startsWith("http://localhost:3000/cb?") && location.contains("code=") && location.contains("state=s1"), location);
  }

  @Test
  @Order(3)
  void scenarioB_aNativeLoginOffersPushWithNumberMatch() {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    ApnsSink apns = KeycloakContainerSupport.apnsSink();
    apns.clear();
    Pkce pkce = Pkce.s256();
    Response r = NativeAuthIT.start(CLIENT, pkce);
    r = NativeAuthIT.answer(r, "username", "username", "alice");
    r = NativeAuthIT.answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp", "push");
    Map<String, Object> p = pushParams(r);
    assertEquals(false, p.get("sent"), "nothing is sent before the user picks the factor");
    assertEquals(List.of(Map.of("label", "Alice's test iPhone")), p.get("devices"));
    assertEquals(3, p.get("poll_interval"));
    assertEquals(0, apns.deliveries().size());

    r = NativeAuthIT.answer(r, "push", "action", "resend");
    assertChallenge(r, "totp", "push");
    p = pushParams(r);
    assertEquals(true, p.get("sent"));
    assertEquals("pending", p.get("status"));
    String cid = String.valueOf(p.get("cid"));
    assertNotNull(p.get("expires_at"));
    @SuppressWarnings("unchecked")
    Map<String, Object> uv = (Map<String, Object>) p.get("user_verification");
    assertEquals("number_match", uv.get("type"));
    String number = String.valueOf(uv.get("number"));
    ApnsSink.Delivery delivery = apns.latest(ALICE_DEVICE_TOKEN);
    assertEquals(cid, delivery.cid());

    Response poll = NativeAuthIT.answer(r, "push", "action", "poll");
    assertChallenge(poll, "totp", "push");
    assertEquals("pending", pushParams(poll).get("status"));
    assertNull(errorCode(poll, "push"));

    // The phone sees the three numbers, one of them is the native client's.
    String pendingUrl = deviceApi("login/pending");
    Response pending = device(aliceKey, "GET", pendingUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).queryParam("userId", aliceUserId).get(pendingUrl).andReturn();
    assertEquals(200, pending.statusCode(), pending.asString());
    List<String> numbers = pending.jsonPath().getList("challenges[0].userVerification.numbers");
    assertEquals(3, numbers.size(), pending.asString());
    assertTrue(numbers.contains(number), numbers + " must contain " + number);
    String wrong = numbers.stream().filter(n -> !n.equals(number)).findFirst().orElseThrow();
    String respondUrl = deviceApi("login/challenges/" + cid + "/respond");
    Response mismatch = device(aliceKey, "POST", respondUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + loginJwt(aliceKey, cid, ALICE_CREDENTIAL_ID, ALICE_DEVICE_ID, "approve", wrong) + "\"}").post(respondUrl).andReturn();
    assertEquals(403, mismatch.statusCode(), mismatch.asString());
    Response approved = device(aliceKey, "POST", respondUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + loginJwt(aliceKey, cid, ALICE_CREDENTIAL_ID, ALICE_DEVICE_ID, "approve", number) + "\"}").post(respondUrl).andReturn();
    assertEquals(200, approved.statusCode(), approved.asString());

    Response ok = NativeAuthIT.answer(poll, "push", "action", "poll");
    assertEquals(200, ok.statusCode(), ok.asString());
    Response tokens = exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("alice", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));
  }

  @Test
  @Order(4)
  void scenarioB_aDeniedPushIsAFailureAndTheAlternativeStillWorks() {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    Pkce pkce = Pkce.s256();
    Response r = NativeAuthIT.start(CLIENT, pkce);
    r = NativeAuthIT.answer(r, "username", "username", "alice");
    r = NativeAuthIT.answer(r, "password", "password", "alice-password");
    r = NativeAuthIT.answer(r, "push", "action", "resend");
    String cid = String.valueOf(pushParams(r).get("cid"));
    String respondUrl = deviceApi("login/challenges/" + cid + "/respond");
    Response denied = device(aliceKey, "POST", respondUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + loginJwt(aliceKey, cid, ALICE_CREDENTIAL_ID, ALICE_DEVICE_ID, "deny", null) + "\"}").post(respondUrl).andReturn();
    assertEquals(200, denied.statusCode(), denied.asString());
    assertEquals("denied", denied.jsonPath().getString("status"));

    pauseForQuickLoginWindow();
    Response poll = NativeAuthIT.answer(r, "push", "action", "poll");
    assertChallenge(poll, "totp", "push");
    assertEquals("denied", errorCode(poll, "push"));
    assertEquals(false, pushParams(poll).get("sent"));
    assertNotNull(pushParams(poll).get("resend_allowed_at"));

    Response tooSoon = NativeAuthIT.answer(poll, "push", "action", "resend");
    assertEquals("resend_too_soon", errorCode(tooSoon, "push"));

    // The other alternative is still available.
    Response ok = NativeAuthIT.answer(tooSoon, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, ok.statusCode(), ok.asString());
  }

  @Test
  @Order(5)
  void aliceMaintainsHerDevice_pushProviderRotateKeyAndLockout() {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    // 1. A new APNs device token (spec/03 §7 "Maintenance").
    String providerUrl = deviceApi("device/push-provider");
    Response updated = device(aliceKey, "PUT", providerUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"pushProviderId\":\"" + ALICE_DEVICE_TOKEN.replace('0', 'f') + "\",\"pushProviderType\":\"apns\"}").put(providerUrl).andReturn();
    assertEquals(200, updated.statusCode(), updated.asString());
    assertEquals("updated", updated.jsonPath().getString("status"));
    Response unchanged = device(aliceKey, "PUT", providerUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"pushProviderId\":\"" + ALICE_DEVICE_TOKEN.replace('0', 'f') + "\",\"pushProviderType\":\"apns\"}").put(providerUrl).andReturn();
    assertEquals("unchanged", unchanged.jsonPath().getString("status"), unchanged.asString());

    // 2. Key rotation (spec/14 D9): the proof is signed by the current key, the body carries the new
    // one. Afterwards the old token no longer matches the enrolled key: a new DPoP-bound login with
    // the new key is what re-binds the device token.
    DPoPProofs newKey = new DPoPProofs();
    String rotateUrl = deviceApi("device/rotate-key");
    String newJwk = newKey.jwk().replace("{", "{\"alg\":\"ES256\",");
    Response rotated = device(aliceKey, "PUT", rotateUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).contentType("application/json")
        .body("{\"publicKeyJwk\":" + newJwk + "}").put(rotateUrl).andReturn();
    assertEquals(200, rotated.statusCode(), rotated.asString());
    assertEquals("rotated", rotated.jsonPath().getString("status"));
    String pendingUrl = deviceApi("login/pending");
    Response oldKey = device(aliceKey, "GET", pendingUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).queryParam("userId", aliceUserId).get(pendingUrl).andReturn();
    assertTrue(oldKey.statusCode() == 401 || oldKey.statusCode() == 403, "old key refused: " + oldKey.statusCode() + " " + oldKey.asString());

    Pkce pkce = Pkce.s256();
    Response r = startWithProof(newKey, CLIENT, pkce);
    r = answerWithProof(newKey, r, "username", "username", "alice");
    r = answerWithProof(newKey, r, "password", "password", "alice-password");
    r = answerWithProof(newKey, r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchangeWithProof(newKey, CLIENT, r.jsonPath().getString("authorization_code"), pkce);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    String newToken = tokens.jsonPath().getString("access_token");
    Response pending = device(newKey, "GET", pendingUrl, newToken, aliceUserId, ALICE_DEVICE_ID).queryParam("userId", aliceUserId).get(pendingUrl).andReturn();
    assertEquals(200, pending.statusCode(), pending.asString());
    assertEquals(0, pending.jsonPath().getList("challenges").size());
    aliceKey = newKey;
    aliceAccessToken = newToken;

    // 3. The panic button disables the account (ba-itsys semantics); an admin re-enables it.
    String lockoutUrl = deviceApi("login/lockout");
    Response locked = device(aliceKey, "POST", lockoutUrl, aliceAccessToken, aliceUserId, ALICE_DEVICE_ID).post(lockoutUrl).andReturn();
    assertEquals(200, locked.statusCode(), locked.asString());
    assertEquals("locked_out", locked.jsonPath().getString("status"));
    assertEquals(false, Admin.user("alice").getBoolean("enabled"));
    Admin.updateUser("alice", "{\"enabled\":true}");
    assertEquals(true, Admin.user("alice").getBoolean("enabled"));
  }

  @Test
  @Order(6)
  void judyEnrolsMidFlowThroughTheNativeRequiredAction() {
    DPoPProofs judyKey = new DPoPProofs();
    Pkce pkce = Pkce.s256();
    Response r = startWithProof(judyKey, CLIENT, pkce);
    r = answerWithProof(judyKey, r, "username", "username", "judy");
    r = answerWithProof(judyKey, r, "password", "password", "judy-password");
    assertChallenge(r, "push_enrollment");
    Map<String, Object> d = descriptor(r, "push_enrollment");
    assertEquals("native-push-enroll", d.get("id"), "substitutes for ba-itsys' push-mfa-register");
    @SuppressWarnings("unchecked")
    Map<String, Object> p = (Map<String, Object>) d.get("params");
    assertEquals(realmUrl() + "/push-mfa", p.get("device_api_base"));
    JsonPath enrollment = jwtPayload(String.valueOf(p.get("enrollment_token")));
    assertEquals("judy", enrollment.getString("username"));
    assertEquals(enrollment.getString("sub"), p.get("user_id"));

    // A JWT signed with another key than the session's DPoP key is refused (spec/03 §4.15).
    DPoPProofs otherKey = new DPoPProofs();
    Response wrongKey = answerWithProof(judyKey, r, "push_enrollment", "token", enrolmentJwt(otherKey, enrollment, "cred-judy", "device-judy", "none", null, "Judy's phone"));
    assertChallenge(wrongKey, "push_enrollment");
    assertEquals("invalid_credential", errorCode(wrongKey, "push_enrollment"), wrongKey.asString());
    JsonPath again = jwtPayload(String.valueOf(((Map<?, ?>) descriptor(wrongKey, "push_enrollment").get("params")).get("enrollment_token")));
    assertEquals(enrollment.getString("enrollmentId"), again.getString("enrollmentId"), "the pending challenge is kept");

    Response ok = answerWithProof(judyKey, wrongKey, "push_enrollment", "token", enrolmentJwt(judyKey, again, "cred-judy", "device-judy", "none", null, "Judy's phone"));
    assertEquals(200, ok.statusCode(), ok.asString());
    assertEquals(200, exchangeWithProof(judyKey, CLIENT, ok.jsonPath().getString("authorization_code"), pkce).statusCode());
    assertEquals(1, pushCredentials("judy").size());
    assertEquals("Judy's phone", pushCredentials("judy").get(0).get("userLabel"));
    assertEquals(List.of(), Admin.user("judy").getList("requiredActions"), "push-mfa-register is gone");

    // Next login: judy has a push credential (provider none) and gets [push] as the second factor.
    Response next = NativeAuthIT.start(CLIENT, Pkce.s256());
    next = NativeAuthIT.answer(next, "username", "username", "judy");
    next = NativeAuthIT.answer(next, "password", "password", "judy-password");
    assertChallenge(next, "push");
    assertEquals(true, pushParams(next).get("sent"), "the single option is issued at once");
    assertNotEquals(null, pushParams(next).get("cid"));
  }
}
