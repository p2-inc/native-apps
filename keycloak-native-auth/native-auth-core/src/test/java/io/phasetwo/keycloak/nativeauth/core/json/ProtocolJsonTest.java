package io.phasetwo.keycloak.nativeauth.core.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeContext;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeResponse;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProtocolJsonTest {

  @Test
  void challengeResponseUsesSnakeCaseAndOmitsNulls() throws Exception {
    ChallengeResponse r =
        new ChallengeResponse()
            .setAuthSession("S1")
            .setExpiresIn(540L)
            .setChallenges(
                List.of(
                    new ChallengeDescriptor(ChallengeType.TOTP)
                        .setId("E4")
                        .setLabel("Authenticator app code")
                        .setRequired(true)
                        .setError("invalid_credential", "Invalid code")
                        .param("digits", 6)
                        .param("period", 30)))
            .setContext(new ChallengeContext().setUsername("alice").setDisplayName("Alice Example"));

    JsonNode json = NativeAuthJson.mapper().readTree(NativeAuthJson.write(r));
    assertEquals("insufficient_authorization", json.get("error").asText());
    assertEquals("Authentication required", json.get("error_description").asText());
    assertEquals("S1", json.get("auth_session").asText());
    assertEquals("1", json.get("protocol_version").asText());
    assertEquals(540, json.get("expires_in").asInt());
    JsonNode c = json.get("challenges").get(0);
    assertEquals("totp", c.get("type").asText());
    assertEquals("E4", c.get("id").asText());
    assertTrue(c.get("required").asBoolean());
    assertEquals("invalid_credential", c.get("error").get("code").asText());
    assertFalse(c.has("retry"));
    assertEquals(6, c.get("params").get("digits").asInt());
    assertEquals("Alice Example", json.get("context").get("display_name").asText());
    assertFalse(json.get("context").has("client_name"));
  }

  @Test
  void metadataFieldNames() throws Exception {
    Metadata m = new Metadata();
    m.setAuthorizationChallengeEndpoint("https://idp/realms/demo/native-auth/challenge");
    m.setCodeExchange(new Metadata.CodeExchange(false, null));
    m.setChallengeTypesSupported(List.of(ChallengeType.USERNAME, ChallengeType.RECOVERY_CODE));
    JsonNode json = NativeAuthJson.mapper().readTree(NativeAuthJson.write(m));
    assertEquals("draft-ietf-oauth-first-party-apps-04", json.get("fipa_draft").asText());
    assertEquals("recovery_code", json.get("challenge_types_supported").get(1).asText());
    assertFalse(json.get("code_exchange").get("redirect_uri_required").asBoolean());
    assertFalse(json.get("code_exchange").has("redirect_uri"));
    assertFalse(json.get("client_attestation").get("required").asBoolean());
  }

  @Test
  void challengeTypeParsesWireValues() {
    assertEquals(ChallengeType.RECOVERY_CODE, ChallengeType.fromWire("recovery_code"));
    assertEquals(null, ChallengeType.fromWire("x-vendor-foo"));
  }
}
