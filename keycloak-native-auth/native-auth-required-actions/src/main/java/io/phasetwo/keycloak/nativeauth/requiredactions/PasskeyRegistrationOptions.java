package io.phasetwo.keycloak.nativeauth.requiredactions;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;

/**
 * Builds the {@code passkey_registration} params of spec/03 §4.4 (a snake_case mirror of {@code
 * PublicKeyCredentialCreationOptions}) from the realm's WebAuthn <b>Passwordless</b> policy, the same
 * way Keycloak's {@code WebAuthnRegister.requiredActionChallenge} fills its FreeMarker form. Used by
 * both {@code native-passkey-register} (mid-flow) and the authenticated {@code /passkey/register/*}
 * endpoints (spec/03 §6), so it takes no flow or required-action context.
 */
public final class PasskeyRegistrationOptions {

  private static final int DEFAULT_TIMEOUT_MS = 60_000;

  private PasskeyRegistrationOptions() {}

  public static WebAuthnPolicy policy(RealmModel realm) {
    return realm.getWebAuthnPolicyPasswordless();
  }

  public static String rpId(WebAuthnPolicy policy, URI baseUri) {
    String rpId = policy.getRpId();
    return rpId == null || rpId.isEmpty() ? baseUri.getHost() : rpId;
  }

  public static String newChallenge() {
    return Base64Url.encode(new DefaultChallenge().getValue());
  }

  /** The user handle Keycloak expects back in discoverable assertions: base64url(userId as UTF-8). */
  public static String userHandle(UserModel user) {
    return Base64Url.encode(user.getId().getBytes(StandardCharsets.UTF_8));
  }

  public static Map<String, Object> build(RealmModel realm, UserModel user, URI baseUri, String challenge) {
    WebAuthnPolicy policy = policy(realm);
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("challenge", challenge);

    Map<String, Object> rp = new LinkedHashMap<>();
    rp.put("id", rpId(policy, baseUri));
    String rpName = policy.getRpEntityName();
    rp.put("name", rpName == null || rpName.isBlank() ? realm.getName() : rpName);
    params.put("rp", rp);

    Map<String, Object> userEntity = new LinkedHashMap<>();
    userEntity.put("id", userHandle(user));
    userEntity.put("name", user.getUsername());
    userEntity.put("display_name", displayName(user));
    params.put("user", userEntity);

    List<Map<String, Object>> credParams = new ArrayList<>();
    List<String> algorithms = policy.getSignatureAlgorithm();
    if (algorithms == null || algorithms.isEmpty()) {
      algorithms = List.of(Constants.DEFAULT_WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS.split(","));
    }
    for (String alg : algorithms) {
      Long cose = coseAlgorithm(alg);
      if (cose == null) continue;
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("type", "public-key");
      entry.put("alg", cose);
      credParams.add(entry);
    }
    params.put("pub_key_cred_params", credParams);

    Map<String, Object> selection = new LinkedHashMap<>();
    String attachment = policy.getAuthenticatorAttachment();
    if (specified(attachment)) selection.put("authenticator_attachment", attachment);
    String residentKey = WebAuthnCompat.residentKey(policy);
    if (specified(residentKey)) selection.put("resident_key", residentKey);
    if (Constants.WEBAUTHN_POLICY_OPTION_YES.equals(policy.getRequireResidentKey())) {
      selection.put("require_resident_key", true);
    }
    String uv = policy.getUserVerificationRequirement();
    selection.put("user_verification", specified(uv) ? uv : Constants.WEBAUTHN_POLICY_OPTION_PREFERED);
    params.put("authenticator_selection", selection);

    String attestation = policy.getAttestationConveyancePreference();
    params.put("attestation", specified(attestation) ? attestation : "none");

    List<Map<String, Object>> exclude = new ArrayList<>();
    if (policy.isAvoidSameAuthenticatorRegister()) {
      user.credentialManager()
          .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
          .map(WebAuthnCredentialModel::createFromCredentialModel)
          .forEach(
              c -> {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", "public-key");
                entry.put("id", Base64Url.encodeBase64ToBase64Url(c.getWebAuthnCredentialData().getCredentialId()));
                exclude.add(entry);
              });
    }
    params.put("exclude_credentials", exclude);
    params.put("timeout", policy.getCreateTimeout() > 0 ? policy.getCreateTimeout() * 1000 : DEFAULT_TIMEOUT_MS);
    return params;
  }

  private static boolean specified(String value) {
    return value != null && !value.isBlank() && !Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED.equals(value);
  }

  private static String displayName(UserModel user) {
    String name =
        ((user.getFirstName() == null ? "" : user.getFirstName()) + " " + (user.getLastName() == null ? "" : user.getLastName()))
            .trim();
    return name.isEmpty() ? user.getUsername() : name;
  }

  /** Same mapping as Keycloak's {@code WebAuthnRegister.convertSignatureAlgorithms}. */
  static Long coseAlgorithm(String algorithm) {
    return switch (algorithm) {
      case Algorithm.ES256 -> COSEAlgorithmIdentifier.ES256.getValue();
      case Algorithm.RS256 -> COSEAlgorithmIdentifier.RS256.getValue();
      case Algorithm.ES384 -> COSEAlgorithmIdentifier.ES384.getValue();
      case Algorithm.RS384 -> COSEAlgorithmIdentifier.RS384.getValue();
      case Algorithm.ES512 -> COSEAlgorithmIdentifier.ES512.getValue();
      case Algorithm.RS512 -> COSEAlgorithmIdentifier.RS512.getValue();
      case Algorithm.Ed25519 -> COSEAlgorithmIdentifier.EdDSA.getValue();
      case "RS1" -> COSEAlgorithmIdentifier.RS1.getValue();
      default -> null;
    };
  }
}
