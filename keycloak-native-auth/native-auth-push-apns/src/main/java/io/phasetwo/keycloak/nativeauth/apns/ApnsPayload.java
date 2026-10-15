package io.phasetwo.keycloak.nativeauth.apns;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * The notification body (spec/04 §6, spec/05 §5): a visible, time-sensitive alert whose texts are
 * localisation keys the app resolves ({@code PUSH_MFA_TITLE}, {@code PUSH_MFA_BODY} with the client
 * id as argument), {@code mutable-content} so a notification service extension can enrich it from
 * {@code /push-mfa/login/pending}, and the ba-itsys fields ({@code confirmToken}, {@code cid},
 * {@code credId}, {@code typ}, {@code ver}) as custom keys. No user identity is included.
 */
final class ApnsPayload {

  static final String CATEGORY = "PUSH_MFA_APPROVAL";
  static final String TITLE_KEY = "PUSH_MFA_TITLE";
  static final String BODY_KEY = "PUSH_MFA_BODY";

  private ApnsPayload() {}

  static String build(String confirmToken, String challengeId, String deviceCredentialId, String clientId, int type, int version) {
    Map<String, Object> alert = new LinkedHashMap<>();
    alert.put("title-loc-key", TITLE_KEY);
    alert.put("loc-key", BODY_KEY);
    alert.put("loc-args", List.of(clientId == null ? "" : clientId));
    Map<String, Object> aps = new LinkedHashMap<>();
    aps.put("alert", alert);
    aps.put("sound", "default");
    aps.put("category", CATEGORY);
    aps.put("interruption-level", "time-sensitive");
    aps.put("mutable-content", 1);
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("aps", aps);
    payload.put("confirmToken", confirmToken);
    payload.put("cid", challengeId);
    payload.put("credId", deviceCredentialId);
    payload.put("typ", type);
    payload.put("ver", version);
    try {
      return JsonSerialization.writeValueAsString(payload);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
