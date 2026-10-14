package io.phasetwo.keycloak.nativeauth.requiredactions;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.truststore.TruststoreProvider;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.keycloak.authentication.requiredactions.KeycloakTrustAnchorRepository;

/**
 * Verifies a WebAuthn attestation against the realm's Passwordless policy and stores the resulting
 * {@code webauthn-passwordless} credential. This is the validation portion of Keycloak's {@code
 * WebAuthnRegister.processAction} (same webauthn4j verifier set, self-attestation rule, trust anchors
 * from the realm truststore, AAGUID policy) without its form handling and FreeMarker error pages.
 */
public final class PasskeyRegistrationVerifier {

  private static final Logger log = Logger.getLogger(PasskeyRegistrationVerifier.class);

  /** The stored credential and the id/label the client gets back. */
  public record Registered(CredentialModel credential, String credentialIdBase64Url, String label, String aaguid) {}

  private PasskeyRegistrationVerifier() {}

  /**
   * @param challenge the base64url challenge issued with the options (already consumed single-use by
   *     the caller)
   * @param transports client-reported transports, may be empty
   * @param label user-visible credential label, may be null
   */
  public static Registered verifyAndStore(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      URI baseUri,
      String challenge,
      byte[] attestationObject,
      byte[] clientDataJson,
      Set<String> transports,
      String label)
      throws PasskeyRegistrationException {
    WebAuthnPolicy policy = PasskeyRegistrationOptions.policy(realm);
    String rpId = PasskeyRegistrationOptions.rpId(policy, baseUri);
    Set<Origin> origins = policy.getExtraOrigins().stream().map(Origin::new).collect(Collectors.toSet());
    origins.add(new Origin(UriUtils.getOrigin(baseUri)));
    ServerProperty server = new ServerProperty(origins, rpId, new DefaultChallenge(challenge));
    boolean uvRequired = Constants.WEBAUTHN_POLICY_OPTION_REQUIRED.equals(policy.getUserVerificationRequirement());

    RegistrationRequest request =
        transports == null || transports.isEmpty()
            ? new RegistrationRequest(attestationObject, clientDataJson)
            : new RegistrationRequest(attestationObject, clientDataJson, new HashSet<>(transports));
    RegistrationParameters parameters =
        new RegistrationParameters(server, expectedCredentialParameters(policy), uvRequired);

    WebAuthnRegistrationManager manager = registrationManager(session, policy);
    RegistrationData data;
    try {
      data = manager.parse(request);
      manager.verify(data, parameters);
      verifyAcceptableAaguids(data, policy);
    } catch (WebAuthnException e) {
      log.debugf("Passkey attestation rejected for user %s: %s", user.getUsername(), e.getMessage());
      throw new PasskeyRegistrationException("Attestation could not be verified", e);
    } catch (RuntimeException e) {
      log.debugf(e, "Passkey attestation could not be parsed for user %s", user.getUsername());
      throw new PasskeyRegistrationException("Attestation could not be parsed", e);
    }

    AttestedCredentialData attested = attestedCredentialData(data);
    WebAuthnCredentialModelInput input = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    input.setAttestedCredentialData(attested);
    input.setCount(data.getAttestationObject().getAuthenticatorData().getSignCount());
    input.setAttestationStatementFormat(data.getAttestationObject().getFormat());
    input.setTransports(data.getTransports());

    WebAuthnCredentialProvider provider =
        (WebAuthnCredentialProvider)
            session.getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
    WebAuthnCredentialModel model = provider.getCredentialModelFromCredentialInput(input, label);
    CredentialModel created;
    try {
      created = provider.createCredential(realm, user, model);
    } catch (ModelDuplicateException e) {
      throw new PasskeyRegistrationException("This passkey is already registered", e);
    }
    String credentialId = org.keycloak.common.util.Base64Url.encode(attested.getCredentialId());
    String aaguid = model.getWebAuthnCredentialData().getAaguid();
    log.debugf(
        "Registered passkey for user %s (credential %s, aaguid %s, format %s)",
        user.getUsername(), created == null ? "?" : created.getId(), aaguid, data.getAttestationObject().getFormat());
    return new Registered(created, credentialId, label, aaguid);
  }

  /** Mirrors {@code WebAuthnRegister.createWebAuthnRegistrationManager} and {@code WebAuthnRegisterFactory.buildTrustVerifier}. */
  static WebAuthnRegistrationManager registrationManager(KeycloakSession session, WebAuthnPolicy policy) {
    List<AttestationStatementVerifier> verifiers = new ArrayList<>(6);
    String preference = policy.getAttestationConveyancePreference();
    if (preference == null
        || Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED.equals(preference)
        || AttestationConveyancePreference.NONE.getValue().equals(preference)) {
      verifiers.add(new NoneAttestationStatementVerifier());
    }
    verifiers.add(new PackedAttestationStatementVerifier());
    verifiers.add(new TPMAttestationStatementVerifier());
    verifiers.add(new AndroidKeyAttestationStatementVerifier());
    verifiers.add(new AndroidSafetyNetAttestationStatementVerifier());
    verifiers.add(new FIDOU2FAttestationStatementVerifier());

    DefaultSelfAttestationTrustworthinessVerifier selfAttestation = new DefaultSelfAttestationTrustworthinessVerifier();
    List<String> acceptableAaguids = policy.getAcceptableAaguids();
    selfAttestation.setSelfAttestationAllowed(acceptableAaguids == null || acceptableAaguids.isEmpty());

    TruststoreProvider truststore = session.getProvider(TruststoreProvider.class);
    CertPathTrustworthinessVerifier certPath =
        truststore == null || truststore.getTruststore() == null
            ? new NullCertPathTrustworthinessVerifier()
            : new DefaultCertPathTrustworthinessVerifier(new KeycloakTrustAnchorRepository(session));

    return new WebAuthnRegistrationManager(verifiers, certPath, selfAttestation, Collections.emptyList(), new ObjectConverter());
  }

  private static List<PublicKeyCredentialParameters> expectedCredentialParameters(WebAuthnPolicy policy) {
    List<String> algorithms = policy.getSignatureAlgorithm();
    if (algorithms == null || algorithms.isEmpty()) {
      algorithms = Arrays.asList(Constants.DEFAULT_WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS.split(","));
    }
    List<PublicKeyCredentialParameters> result = new ArrayList<>();
    for (String alg : algorithms) {
      Long cose = PasskeyRegistrationOptions.coseAlgorithm(alg);
      if (cose != null) {
        result.add(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(cose)));
      }
    }
    return result;
  }

  /** Same rule as {@code WebAuthnRegister.PolicyVerifier.verifyAcceptableAaguids}. */
  private static void verifyAcceptableAaguids(RegistrationData data, WebAuthnPolicy policy) {
    List<String> acceptable = policy.getAcceptableAaguids();
    if (acceptable == null || acceptable.isEmpty()) return;
    if (NoneAttestationStatement.FORMAT.equals(data.getAttestationObject().getFormat())) {
      throw new WebAuthnException("Acceptable AAGUIDs require an attestation format other than 'none'");
    }
    String aaguid = attestedCredentialData(data).getAaguid().toString();
    if (acceptable.stream().noneMatch(aaguid::equals)) {
      throw new WebAuthnException("Authenticator model not acceptable (AAGUID " + aaguid + ")");
    }
  }

  private static AttestedCredentialData attestedCredentialData(RegistrationData data) {
    return Optional.ofNullable(data.getAttestationObject())
        .map(AttestationObject::getAuthenticatorData)
        .map(AuthenticatorData::getAttestedCredentialData)
        .orElseThrow(() -> new WebAuthnException("Cannot obtain attested credential data from the response"));
  }
}
