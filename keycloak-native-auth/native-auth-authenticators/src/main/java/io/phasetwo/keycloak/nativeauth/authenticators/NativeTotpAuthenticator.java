package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

/**
 * {@code native-totp} (spec/04 §3.2). Validation is delegated to Keycloak's
 * {@link OTPCredentialProvider} (look-around window, code reuse protection) exactly as
 * {@code OTPFormAuthenticator} does.
 */
public class NativeTotpAuthenticator extends NativeAuthenticatorBase
    implements CredentialValidator<OTPCredentialProvider> {

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.TOTP;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user.credentialManager().isConfiguredFor(getCredentialProvider(session).getType());
  }

  @Override
  public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
    return (OTPCredentialProvider)
        session.getProvider(CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);
  }

  @Override
  public ChallengeDescriptor describe(
      AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    OTPPolicy policy = context.getRealm().getOTPPolicy();
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.TOTP)
            .setLabel("Authenticator app code")
            .param("digits", policy.getDigits())
            .param("period", policy.getPeriod())
            .param("algorithm", policy.getAlgorithm());
    UserModel user = context.getUser();
    if (user != null) {
      List<String> labels = new ArrayList<>();
      List<Map<String, String>> credentials = new ArrayList<>();
      user.credentialManager()
          .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
          .forEach(
              c -> {
                String label = c.getUserLabel() == null ? "" : c.getUserLabel();
                labels.add(label);
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("id", c.getId());
                entry.put("label", label);
                credentials.add(entry);
              });
      d.param("credential_labels", labels);
      // Lets the client pick 'credential_id' when the user has several OTP credentials (spec/03 §4.5).
      d.param("credentials", credentials);
    }
    return d;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String totp = param(context, Protocol.TOTP);
    if (totp == null || totp.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Code is required");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    String credentialId = param(context, Protocol.CREDENTIAL_ID);
    if (credentialId == null || credentialId.isEmpty()) {
      CredentialModel defaultCredential =
          getCredentialProvider(context.getSession())
              .getDefaultCredential(context.getSession(), context.getRealm(), user);
      credentialId = defaultCredential == null ? "" : defaultCredential.getId();
    }
    context.getEvent().detail(Details.SELECTED_CREDENTIAL_ID, credentialId);

    boolean valid =
        user.credentialManager()
            .isValid(new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, totp));
    if (valid) {
      context.success(OTPCredentialModel.TYPE);
      return;
    }
    context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
    failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid code");
  }
}
