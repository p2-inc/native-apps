package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.realmUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.ALICE_TOTP_SECRET;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.CLIENT;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.totp;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.answerWithProof;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.deletePushCredentials;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.device;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.deviceApi;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.enrolmentJwt;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.exchangeWithProof;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.jwtPayload;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.loginJwt;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.pushCredentials;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.pushParams;
import static io.phasetwo.keycloak.nativeauth.demo.PushMfaIT.startWithProof;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Push MFA to an Android device (spec/17 §6 A3; spec/03 §7) through ba-itsys' {@code fcm} sender
 * and a fake FCM ({@link FcmSink}):
 *
 * <ol>
 *   <li>alice enrols "her Android phone" from inside the app: {@code deviceType: android}, {@code
 *       pushProviderType: fcm}, {@code pushProviderId} = an FCM registration token.
 *   <li>A native login sends the push: the sender gets an access token from the service account's
 *       {@code token_uri} with a JWT-bearer assertion, then posts an HTTP v1 message with a {@code
 *       notification} and {@code data.token} = the confirm token; the phone approves.
 *   <li>The registration token changes ({@code onNewToken}); the next push goes to the new token.
 * </ol>
 */
@ExtendWith(TranscriptRecorder.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FcmPushIT {

  static final String REGISTRATION_TOKEN = "fcm-alice-1:APA91bFakeRegistrationTokenForTheIntegrationTest";
  static final String NEW_REGISTRATION_TOKEN = "fcm-alice-2:APA91bFakeRegistrationTokenAfterOnNewToken";
  static final String CREDENTIAL_ID = "cred-alice-android";
  static final String DEVICE_ID = "device-alice-android";

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
  }

  /** A native login of alice that ends at the [totp, push] choice, with the push sent. */
  static Response pushSent(Pkce pkce) {
    Response r = NativeAuthIT.start(CLIENT, pkce);
    r = NativeAuthIT.answer(r, "username", "username", "alice");
    r = NativeAuthIT.answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp", "push");
    r = NativeAuthIT.answer(r, "push", "action", "resend");
    assertEquals(true, pushParams(r).get("sent"), r.asString());
    return r;
  }

  @Test
  @Order(1)
  void aliceEnrolsHerAndroidPhone() {
    given().get(realmUrl() + "/native-auth/metadata").then().statusCode(200)
        .body("push.push_provider_types", org.hamcrest.Matchers.hasItems("fcm", "apns", "none"));

    aliceKey = new DPoPProofs();
    Pkce pkce = Pkce.s256();
    Response r = startWithProof(aliceKey, CLIENT, pkce);
    r = answerWithProof(aliceKey, r, "username", "username", "alice");
    r = answerWithProof(aliceKey, r, "password", "password", "alice-password");
    r = answerWithProof(aliceKey, r, "totp", "totp", totp(ALICE_TOTP_SECRET));
    assertEquals(200, r.statusCode(), r.asString());
    Response tokens = exchangeWithProof(aliceKey, CLIENT, r.jsonPath().getString("authorization_code"), pkce);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    aliceAccessToken = tokens.jsonPath().getString("access_token");
    aliceUserId = claims(aliceAccessToken).getString("sub");

    String startUrl = realmUrl() + "/native-auth/push/enroll/start";
    Response start = given().accept("application/json").header("Authorization", "DPoP " + aliceAccessToken)
        .header("DPoP", aliceKey.proof("POST", startUrl, aliceAccessToken)).post(startUrl).andReturn();
    assertEquals(200, start.statusCode(), start.asString());
    JsonPath enrollment = jwtPayload(start.jsonPath().getString("enrollment_token"));

    String completeUrl = deviceApi("enroll/complete");
    Response complete = device(aliceKey, "POST", completeUrl, aliceAccessToken, aliceUserId, DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + enrolmentJwt(aliceKey, enrollment, CREDENTIAL_ID, DEVICE_ID, "android", "fcm", REGISTRATION_TOKEN, "Alice's test Pixel") + "\"}")
        .post(completeUrl).andReturn();
    assertEquals(200, complete.statusCode(), complete.asString());
    assertEquals("enrolled", complete.jsonPath().getString("status"));
    List<Map<String, Object>> credentials = pushCredentials("alice");
    assertEquals(1, credentials.size());
    assertEquals("Alice's test Pixel", credentials.get(0).get("userLabel"));
  }

  @Test
  @Order(2)
  void aNativeLoginSendsAnFcmMessageAndThePhoneApproves() throws Exception {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    FcmSink fcm = KeycloakContainerSupport.fcmSink();
    fcm.clear();
    Pkce pkce = Pkce.s256();
    Response r = pushSent(pkce);
    String cid = String.valueOf(pushParams(r).get("cid"));
    String number = String.valueOf(((Map<?, ?>) pushParams(r).get("user_verification")).get("number"));

    // 1. The access token: a JWT-bearer grant at the service account's token_uri, signed (RS256)
    // with the service account's key, for the firebase.messaging scope.
    FcmSink.Delivery delivery = fcm.latest(REGISTRATION_TOKEN);
    FcmSink.TokenRequest tokenRequest = fcm.tokenRequests().get(fcm.tokenRequests().size() - 1);
    assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", tokenRequest.form().get("grant_type"));
    String[] assertion = tokenRequest.assertion().split("\\.");
    assertEquals("RS256", JsonPath.from(new String(Base64.getUrlDecoder().decode(assertion[0]), StandardCharsets.UTF_8)).getString("alg"));
    JsonPath grant = claims(tokenRequest.assertion());
    assertEquals(FcmSink.CLIENT_EMAIL, grant.getString("iss"));
    assertEquals(fcm.tokenUri(), grant.getString("aud"));
    assertEquals("https://www.googleapis.com/auth/firebase.messaging", grant.getString("scope"));
    Signature rs256 = Signature.getInstance("SHA256withRSA");
    rs256.initVerify(fcm.serviceAccountPublicKey());
    rs256.update((assertion[0] + "." + assertion[1]).getBytes(StandardCharsets.US_ASCII));
    assertTrue(rs256.verify(Base64.getUrlDecoder().decode(assertion[2])), "assertion signed with the service account key");

    // 2. The HTTP v1 message (spec/03 §7 "Receive push"): bearer token from step 1, a visible
    // notification, and data.token = the realm-signed confirm token carrying cid and credId.
    assertEquals("Bearer " + FcmSink.ACCESS_TOKEN, delivery.authorization());
    assertFalse(delivery.message().path("notification").path("title").asText("").isBlank(), delivery.body().toString());
    assertFalse(delivery.message().path("notification").path("body").asText("").isBlank(), delivery.body().toString());
    JsonPath confirm = jwtPayload(delivery.confirmToken());
    assertEquals(cid, confirm.getString("cid"));
    assertEquals(CREDENTIAL_ID, confirm.getString("credId"));

    // 3. The phone resolves cid from the token, reads the numbers and approves.
    String pendingUrl = deviceApi("login/pending");
    Response pending = device(aliceKey, "GET", pendingUrl, aliceAccessToken, aliceUserId, DEVICE_ID).queryParam("userId", aliceUserId).get(pendingUrl).andReturn();
    assertEquals(200, pending.statusCode(), pending.asString());
    List<String> numbers = pending.jsonPath().getList("challenges[0].userVerification.numbers");
    assertTrue(numbers.contains(number), numbers + " must contain " + number);
    String respondUrl = deviceApi("login/challenges/" + confirm.getString("cid") + "/respond");
    Response approved = device(aliceKey, "POST", respondUrl, aliceAccessToken, aliceUserId, DEVICE_ID).contentType("application/json")
        .body("{\"token\":\"" + loginJwt(aliceKey, confirm.getString("cid"), confirm.getString("credId"), DEVICE_ID, "approve", number) + "\"}").post(respondUrl).andReturn();
    assertEquals(200, approved.statusCode(), approved.asString());

    Response ok = NativeAuthIT.answer(r, "push", "action", "poll");
    assertEquals(200, ok.statusCode(), ok.asString());
    assertEquals(200, exchange(CLIENT, ok.jsonPath().getString("authorization_code"), pkce, null).statusCode());
  }

  @Test
  @Order(3)
  void aRefreshedRegistrationTokenReceivesTheNextPush() {
    assertNotNull(aliceAccessToken, "order: enrolment first");
    // FirebaseMessagingService.onNewToken -> PUT /push-mfa/device/push-provider (spec/03 §7 "Maintenance").
    String providerUrl = deviceApi("device/push-provider");
    Response updated = device(aliceKey, "PUT", providerUrl, aliceAccessToken, aliceUserId, DEVICE_ID).contentType("application/json")
        .body("{\"pushProviderId\":\"" + NEW_REGISTRATION_TOKEN + "\",\"pushProviderType\":\"fcm\"}").put(providerUrl).andReturn();
    assertEquals(200, updated.statusCode(), updated.asString());
    assertEquals("updated", updated.jsonPath().getString("status"));

    FcmSink fcm = KeycloakContainerSupport.fcmSink();
    fcm.clear();
    NativeAuthIT.pauseForQuickLoginWindow();
    Response r = pushSent(Pkce.s256());
    FcmSink.Delivery delivery = fcm.latest(NEW_REGISTRATION_TOKEN);
    assertEquals(String.valueOf(pushParams(r).get("cid")), jwtPayload(delivery.confirmToken()).getString("cid"));
    assertTrue(fcm.deliveries().stream().noneMatch(d -> REGISTRATION_TOKEN.equals(d.registrationToken())), "nothing to the old token");
  }
}
