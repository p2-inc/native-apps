package io.phasetwo.keycloak.nativeauth.requiredactions;

import com.webauthn4j.anchor.KeyStoreTrustAnchorRepository;
import com.webauthn4j.anchor.TrustAnchorRepository;
import io.phasetwo.keycloak.nativeauth.core.compat.KeycloakCompat;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.Optional;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;

/**
 * WebAuthn members that differ between the supported Keycloak versions (see {@link KeycloakCompat}),
 * resolved once.
 *
 * <ul>
 *   <li>{@code WebAuthnPolicy.getResidentKey()} ({@code required|preferred|discouraged}) exists from
 *       26.8; before, only the {@code Yes|No} {@code getRequireResidentKey()}.
 *   <li>{@code KeycloakTrustAnchorRepository} (26.8) anchors attestation chains in the server
 *       truststore; before, Keycloak's own {@code WebAuthnRegisterFactory} wraps the same truststore
 *       in webauthn4j's {@link KeyStoreTrustAnchorRepository}, and so do we.
 * </ul>
 */
final class WebAuthnCompat {

  private WebAuthnCompat() {}

  private static final Optional<Method> RESIDENT_KEY = KeycloakCompat.method(WebAuthnPolicy.class, "getResidentKey");
  private static final Optional<Constructor<?>> KEYCLOAK_TRUST_ANCHORS =
      KeycloakCompat.type("org.keycloak.authentication.requiredactions.KeycloakTrustAnchorRepository")
          .flatMap(t -> KeycloakCompat.constructor(t, 1));

  /** The policy's resident-key requirement in WebAuthn terms, or {@code null} when unspecified. */
  static String residentKey(WebAuthnPolicy policy) {
    if (RESIDENT_KEY.isPresent()) {
      return (String) KeycloakCompat.invoke(RESIDENT_KEY.get(), policy);
    }
    String require = policy.getRequireResidentKey();
    if (Constants.WEBAUTHN_POLICY_OPTION_YES.equals(require)) return "required";
    if (Constants.WEBAUTHN_POLICY_OPTION_NO.equals(require)) return "discouraged";
    return null;
  }

  /** Trust anchors for attestation chains; only called when the server has a truststore. */
  static TrustAnchorRepository trustAnchors(KeycloakSession session, KeyStore truststore) {
    if (KEYCLOAK_TRUST_ANCHORS.isPresent()) {
      return (TrustAnchorRepository) KeycloakCompat.create(KEYCLOAK_TRUST_ANCHORS.get(), session);
    }
    return new KeyStoreTrustAnchorRepository(truststore);
  }
}
