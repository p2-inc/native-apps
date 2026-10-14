package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;

/**
 * Verifies an optional {@code DPoP} header on the challenge endpoint (spec/03 §8, spec/13 D3) with
 * Keycloak's own validator (RFC 9449 §4.3: {@code typ}, {@code alg}, {@code jwk}, {@code htm},
 * {@code htu}, {@code iat} window, {@code jti} replay). Fifth class allowed to use Keycloak-internal
 * APIs (spec/08 R2): {@code DPoPUtil} lives in {@code keycloak-services}.
 */
final class DPoPProofChecker {

  private static final Logger log = Logger.getLogger(DPoPProofChecker.class);
  static final String HEADER = "DPoP";

  private DPoPProofChecker() {}

  /**
   * @return the proof key's RFC 7638 thumbprint, or {@code null} when the request carries no proof
   *     (or the {@code dpop} feature is disabled)
   * @throws NativeAuthException {@code invalid_dpop_proof} when a proof is present but does not verify
   */
  static String thumbprint(KeycloakSession session) {
    if (!Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
      return null;
    }
    HttpRequest request = session.getContext().getHttpRequest();
    String header = request.getHttpHeaders().getHeaderString(HEADER);
    if (header == null || header.isBlank()) {
      return null;
    }
    try {
      DPoP proof =
          new DPoPUtil.Validator(session).request(request).uriInfo(session.getContext().getUri()).validate();
      return proof.getThumbprint();
    } catch (VerificationException e) {
      log.debugf("DPoP proof rejected on the challenge endpoint: %s", e.getMessage());
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_DPOP_PROOF, "DPoP proof invalid: " + e.getMessage());
    }
  }

  /** Algorithms the validator accepts, for {@code dpop_signing_alg_values_supported}. */
  static List<String> supportedAlgorithms(KeycloakSession session) {
    if (!Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
      return List.of();
    }
    return DPoPUtil.getDPoPSupportedAlgorithms(session);
  }
}
