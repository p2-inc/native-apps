package io.phasetwo.keycloak.nativeauth.push;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeCreatedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.EnrollmentCompletedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventService;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import de.arbeitsagentur.keycloak.push.util.PushMfaInputValidator;
import de.arbeitsagentur.keycloak.push.util.PushMfaKeyUtil;
import de.arbeitsagentur.keycloak.push.util.PushSignatureVerifier;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Programmatic push-MFA enrolment on top of ba-itsys' public classes (spec/03 §4.15, §7 (b);
 * spec/14 D9): creates enrolment challenges the way {@code PushMfaRegisterRequiredAction} does and
 * completes them from a device-signed JWT the way {@code PushMfaResource#completeEnrollment} does —
 * the one piece worth offering upstream as a small API (08 Q5).
 */
public final class PushEnrolment {

  private static final Logger log = Logger.getLogger(PushEnrolment.class);
  private static final SecureRandom RANDOM = new SecureRandom();

  /** A verification failure the caller turns into a descriptor error (spec/03 §4.15). */
  public static final class EnrolmentException extends Exception {
    private final boolean expired;

    public EnrolmentException(String message, boolean expired) {
      super(message);
      this.expired = expired;
    }

    public boolean isExpired() {
      return expired;
    }
  }

  public record Started(PushChallenge challenge, String enrollmentToken, long expiresIn) {}

  private PushEnrolment() {}

  /** {@code /realms/{realm}/push-mfa}, the ba-itsys device API root (spec/03 §7). */
  public static String deviceApiBase(RealmModel realm, URI baseUri) {
    return UriBuilder.fromUri(baseUri).path("realms").path(realm.getName()).path("push-mfa").build().toString();
  }

  /** Lifetime of enrolment challenges: the {@code push-mfa-register} action's config, else ba-itsys' default. */
  public static Duration enrolmentTtl(RealmModel realm) {
    RequiredActionConfigModel config = realm.getRequiredActionConfigByAlias(PushMfaConstants.REQUIRED_ACTION_ID);
    String value = config == null ? null : config.getConfigValue(PushMfaConstants.ENROLLMENT_CHALLENGE_TTL_CONFIG);
    try {
      long seconds = value == null || value.isBlank() ? 0 : Long.parseLong(value.trim());
      return seconds > 0 ? Duration.ofSeconds(seconds) : PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
    } catch (NumberFormatException e) {
      return PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
    }
  }

  /** A new pending enrolment challenge plus the realm-signed enrolment token for it. */
  public static Started start(KeycloakSession session, RealmModel realm, UserModel user, URI baseUri) {
    PushChallengeStore store = new PushChallengeStore(session);
    byte[] nonce = new byte[PushMfaConstants.NONCE_BYTES_SIZE];
    RANDOM.nextBytes(nonce);
    Duration ttl = enrolmentTtl(realm);
    PushChallenge challenge =
        store.create(realm.getId(), user.getId(), nonce, PushChallenge.Type.ENROLLMENT, ttl, null, null, KeycloakModelUtils.generateId(), null);
    PushMfaEventService.fire(
        session,
        new ChallengeCreatedEvent(
            challenge.getRealmId(), challenge.getUserId(), challenge.getId(), challenge.getType(), challenge.getKeycloakCredentialId(),
            challenge.getClientId(), challenge.getUserVerificationMode(), challenge.getExpiresAt(), Instant.now()));
    String token = PushEnrollmentTokenBuilder.build(session, realm, user, challenge, baseUri);
    log.debugf("Created push enrolment challenge %s for user %s", challenge.getId(), user.getUsername());
    return new Started(challenge, token, Math.max(1, Duration.between(Instant.now(), challenge.getExpiresAt()).getSeconds()));
  }

  /** The pending enrolment challenge {@code challengeId}, if it still is one. */
  public static Optional<PushChallenge> pending(KeycloakSession session, String challengeId) {
    if (challengeId == null) return Optional.empty();
    return new PushChallengeStore(session).get(challengeId).filter(c -> c.getType() == PushChallenge.Type.ENROLLMENT && c.getStatus() == PushChallengeStatus.PENDING);
  }

  /**
   * Verifies a device-signed enrolment JWT exactly as {@code POST /push-mfa/enroll/complete} does
   * (subject, challenge, nonce, expiry, {@code cnf.jwk}, signature, field limits) and stores the
   * push credential. {@code requiredJkt}, when given, additionally demands that the enrolled key is
   * the session's DPoP key (spec/03 §4.15, §7.1).
   */
  public static PushCredentialData complete(
      KeycloakSession session, RealmModel realm, UserModel user, PushChallenge challenge, String deviceToken, String requiredJkt, String clientId)
      throws EnrolmentException {
    JWSInput jws;
    JsonNode payload;
    try {
      jws = new JWSInput(deviceToken);
      payload = JsonSerialization.mapper.readTree(jws.getContent());
    } catch (Exception e) {
      throw new EnrolmentException("Enrolment token is not a JWS", false);
    }
    try {
      PushMfaKeyUtil.requireSupportedAlgorithm(jws.getHeader().getAlgorithm(), "enrollment token");
      if (!Objects.equals(text(payload, "sub"), user.getId())) {
        throw new EnrolmentException("Enrolment token subject mismatch", false);
      }
      if (!Objects.equals(text(payload, "enrollmentId"), challenge.getId())) {
        throw new EnrolmentException("Enrolment token names another challenge", false);
      }
      if (challenge.getStatus() != PushChallengeStatus.PENDING || Instant.now().isAfter(challenge.getExpiresAt())) {
        throw new EnrolmentException("Enrolment challenge expired", true);
      }
      long exp = payload.path("exp").asLong(0);
      if (exp <= 0 || Instant.now().getEpochSecond() > exp) {
        throw new EnrolmentException("Enrolment token expired", false);
      }
      if (!Objects.equals(text(payload, "nonce"), PushChallengeStore.encodeNonce(challenge.getNonce()))) {
        throw new EnrolmentException("Nonce mismatch", false);
      }
      JsonNode jwkNode = payload.path("cnf").path("jwk");
      if (!jwkNode.isObject()) {
        throw new EnrolmentException("Enrolment token is missing cnf.jwk", false);
      }
      PushMfaInputValidator.ensurePublicJwk(jwkNode, "cnf.jwk");
      String jwkJson = jwkNode.toString();
      KeyWrapper deviceKey = PushMfaKeyUtil.keyWrapperFromNode(jwkNode);
      PushMfaKeyUtil.ensureKeyMatchesAlgorithm(deviceKey, jws.getHeader().getAlgorithm().name());
      if (requiredJkt != null && !requiredJkt.equals(PushMfaKeyUtil.computeJwkThumbprint(jwkJson))) {
        throw new EnrolmentException("cnf.jwk must be the DPoP key this session is bound to", false);
      }
      if (!PushSignatureVerifier.verify(jws, deviceKey)) {
        throw new EnrolmentException("Invalid enrolment token signature", false);
      }
      String deviceType = PushMfaInputValidator.requireBoundedText(text(payload, "deviceType"), 64, "deviceType");
      String credentialId = PushMfaInputValidator.requireBoundedText(text(payload, "credentialId"), 128, "credentialId");
      String deviceId = PushMfaInputValidator.requireBoundedText(text(payload, "deviceId"), 128, "deviceId");
      String pushProviderType = PushMfaInputValidator.optionalBoundedText(text(payload, "pushProviderType"), 64, "pushProviderType");
      if (pushProviderType == null || pushProviderType.isBlank()) pushProviderType = "none";
      String pushProviderId = PushMfaInputValidator.optionalBoundedText(text(payload, "pushProviderId"), 2048, "pushProviderId");
      if (!"none".equals(pushProviderType) && (pushProviderId == null || pushProviderId.isBlank())) {
        throw new EnrolmentException("pushProviderId required unless pushProviderType=none", false);
      }
      String label = text(payload, "deviceLabel");
      if (label == null || label.isBlank()) label = PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME;
      label = PushMfaInputValidator.requireBoundedText(label, 128, "deviceLabel");

      PushChallengeStore store = new PushChallengeStore(session);
      PushChallengeStore.ResolveResult resolved = store.tryResolve(challenge.getId(), PushChallengeStatus.APPROVED);
      if (!resolved.applied()) {
        throw new EnrolmentException("Enrolment challenge already resolved", true);
      }
      PushCredentialData data = new PushCredentialData(jwkJson, Instant.now().toEpochMilli(), deviceType, pushProviderId, pushProviderType, credentialId, deviceId);
      PushCredentialService.createCredential(user, label, data);
      PushMfaEventService.fire(
          session,
          new EnrollmentCompletedEvent(realm.getId(), user.getId(), challenge.getId(), credentialId, clientId, deviceId, deviceType, Instant.now()));
      log.debugf("Push credential %s enrolled for user %s (provider %s)", credentialId, user.getUsername(), pushProviderType);
      return data;
    } catch (WebApplicationException e) {
      // ba-itsys' validators throw JAX-RS exceptions with user-safe messages.
      throw new EnrolmentException(e.getMessage() == null ? "Invalid enrolment token" : e.getMessage(), false);
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    return value == null || value.isNull() ? null : value.asText(null);
  }
}
