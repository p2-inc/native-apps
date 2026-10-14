package io.phasetwo.keycloak.nativeauth.demo;

import static io.phasetwo.keycloak.nativeauth.demo.KeycloakContainerSupport.baseUrl;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.answer;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.assertChallenge;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.claims;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.descriptor;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.errorCode;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.exchange;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.pauseForQuickLoginWindow;
import static io.phasetwo.keycloak.nativeauth.demo.NativeAuthIT.start;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * The {@code otp} challenge over email (spec/03 §4.6, spec/13 D4) on the {@code native-otp} flow
 * (client {@code demo-ios-otp}): username → password → [totp | otp]. Codes are read back from
 * mailpit. The flow's config: 6 digits, ttl 300 s, resend cooldown 10 s, 3 attempts.
 */
@ExtendWith(TranscriptRecorder.class)
class OtpIT {

  static final String CLIENT_OTP = "demo-ios-otp";

  @BeforeAll
  static void startContainer() {
    baseUrl();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> otpParams(Response r) {
    return (Map<String, Object>) descriptor(r, "otp").get("params");
  }

  @Test
  void bobGetsAnEmailCodeAsTheOnlySecondFactor() {
    Mailpit.clear();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_OTP, pkce);
    r = answer(r, "username", "username", "bob");
    r = answer(r, "password", "password", "bob-password");
    assertChallenge(r, "otp");
    Map<String, Object> p = otpParams(r);
    assertEquals(true, descriptor(r, "otp").get("required"));
    assertEquals("email", p.get("channel"));
    assertEquals("b***@example.com", p.get("destination_masked"));
    assertEquals(6, p.get("digits"));
    assertEquals(300, p.get("ttl"));
    assertEquals(true, p.get("sent"), "the single option is sent unasked");
    assertNotNull(p.get("resend_allowed_at"));
    assertEquals(1, Mailpit.count());
    String code = Mailpit.latestCode("bob@example.com");

    Response tooSoon = answer(r, "otp", "action", "resend");
    assertChallenge(tooSoon, "otp");
    assertEquals("resend_too_soon", errorCode(tooSoon, "otp"));
    assertEquals(true, otpParams(tooSoon).get("sent"), "the outstanding code is still valid");
    assertEquals(1, Mailpit.count());

    pauseForQuickLoginWindow();
    Response wrong = answer(tooSoon, "otp", "otp", "000000".equals(code) ? "111111" : "000000");
    assertChallenge(wrong, "otp");
    assertEquals("invalid_credential", errorCode(wrong, "otp"));

    Response ok = answer(wrong, "otp", "otp", code);
    assertEquals(200, ok.statusCode(), ok.asString());
    Response tokens = exchange(CLIENT_OTP, ok.jsonPath().getString("authorization_code"), pkce, null);
    assertEquals(200, tokens.statusCode(), tokens.asString());
    assertEquals("bob", claims(tokens.jsonPath().getString("access_token")).getString("preferred_username"));
  }

  @Test
  void aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest() {
    Mailpit.clear();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_OTP, pkce);
    r = answer(r, "username", "username", "alice");
    r = answer(r, "password", "password", "alice-password");
    assertChallenge(r, "totp", "otp");
    assertEquals(false, descriptor(r, "otp").get("required"));
    assertEquals(false, otpParams(r).get("sent"), "nothing is sent before the user picks the factor");
    assertNull(otpParams(r).get("resend_allowed_at"));
    assertEquals(0, Mailpit.count());

    r = answer(r, "otp", "action", "resend");
    assertChallenge(r, "totp", "otp");
    assertNull(errorCode(r, "otp"));
    assertEquals(true, otpParams(r).get("sent"));
    assertNotNull(otpParams(r).get("resend_allowed_at"));
    assertEquals(1, Mailpit.count());

    r = answer(r, "otp", "otp", Mailpit.latestCode("alice@example.com"));
    assertEquals(200, r.statusCode(), r.asString());
  }

  @Test
  void tooManyWrongCodesInvalidateTheCodeUntilItIsResent() throws Exception {
    Mailpit.clear();
    Pkce pkce = Pkce.s256();
    Response r = start(CLIENT_OTP, pkce);
    r = answer(r, "username", "username", "bob");
    r = answer(r, "password", "password", "bob-password");
    assertChallenge(r, "otp");
    String first = Mailpit.latestCode("bob@example.com");
    String wrongCode = "000000".equals(first) ? "111111" : "000000";

    pauseForQuickLoginWindow();
    r = answer(r, "otp", "otp", wrongCode);
    assertEquals("invalid_credential", errorCode(r, "otp"));
    pauseForQuickLoginWindow();
    r = answer(r, "otp", "otp", wrongCode);
    assertEquals("invalid_credential", errorCode(r, "otp"));
    pauseForQuickLoginWindow();
    r = answer(r, "otp", "otp", wrongCode);
    assertEquals("expired_code", errorCode(r, "otp"), "third wrong attempt exhausts the code");
    assertEquals(false, otpParams(r).get("sent"));
    assertEquals(1, Mailpit.count(), "no code is sent unasked after exhaustion");

    // Even the right code is refused now.
    Response stale = answer(r, "otp", "otp", first);
    assertEquals("expired_code", errorCode(stale, "otp"));

    // Resend after the cooldown delivers a new code that works.
    Thread.sleep(10_500);
    r = answer(stale, "otp", "action", "resend");
    assertNull(errorCode(r, "otp"), r.asString());
    assertEquals(true, otpParams(r).get("sent"));
    assertEquals(2, Mailpit.count());
    String second = Mailpit.latestCode("bob@example.com");
    assertNotEquals(first, second);
    r = answer(r, "otp", "otp", second);
    assertEquals(200, r.statusCode(), r.asString());
    assertTrue(r.jsonPath().getString("authorization_code") != null);
  }
}
