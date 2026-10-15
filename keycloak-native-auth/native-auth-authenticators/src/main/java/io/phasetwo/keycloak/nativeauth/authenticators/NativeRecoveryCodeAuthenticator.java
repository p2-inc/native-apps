package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.io.IOException;
import java.util.Locale;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProvider;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.RecoveryAuthnCodesCredentialModel;
import org.keycloak.models.credential.dto.RecoveryAuthnCodesCredentialData;
import org.keycloak.models.utils.RecoveryAuthnCodesUtils;
import org.keycloak.util.JsonSerialization;

/**
 * {@code native-recovery-code} (spec/03 §4.8): one of the user's single-use recovery codes
 * (Keycloak's {@code recovery-authn-codes} credential). Validation and consumption are delegated to
 * {@link RecoveryAuthnCodesCredentialProvider} exactly as {@code RecoveryAuthnCodesFormAuthenticator}
 * does; when the last code is used the user gets {@code CONFIGURE_RECOVERY_AUTHN_CODES}, which the
 * native flow hands to the browser ({@code redirect_to_web}) like Keycloak's form does with its page.
 */
public class NativeRecoveryCodeAuthenticator extends NativeAuthenticatorBase
    implements CredentialValidator<RecoveryAuthnCodesCredentialProvider> {

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.RECOVERY_CODE;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public RecoveryAuthnCodesCredentialProvider getCredentialProvider(KeycloakSession session) {
    return (RecoveryAuthnCodesCredentialProvider)
        session.getProvider(CredentialProvider.class, RecoveryAuthnCodesCredentialProviderFactory.PROVIDER_ID);
  }

  /** Offered only while the user has unused codes (spec/03 §4.8 eligibility). */
  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return credential(user).map(c -> !c.allCodesUsed()).orElse(false);
  }

  private static Optional<RecoveryAuthnCodesCredentialModel> credential(UserModel user) {
    return RecoveryAuthnCodesUtils.getCredential(user).map(RecoveryAuthnCodesCredentialModel::createFromCredentialModel);
  }

  @Override
  public ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    ChallengeDescriptor d = new ChallengeDescriptor(ChallengeType.RECOVERY_CODE).setLabel("Recovery code");
    UserModel user = context.getUser();
    if (user != null) {
      // 26.8.1's model has no accessor for the credential data; read the stored JSON (remaining/total).
      credential(user).ifPresent(c -> d.param("remaining", remaining(c)));
    }
    d.param("warning_threshold", context.getRealm().getPasswordPolicy().getRecoveryCodesWarningThreshold());
    return d;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String code = param(context, Protocol.RECOVERY_CODE);
    if (code == null || code.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Recovery code is required");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    // Same normalisation as Keycloak's form: separators dropped; codes are upper-case alphanumerics.
    String normalised = code.replace("-", "").replace(" ", "").toUpperCase(Locale.ROOT);
    boolean valid = user.credentialManager().isValid(UserCredentialModel.buildFromBackupAuthnCode(normalised));
    if (!valid) {
      context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
      failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid recovery code");
      return;
    }
    context.getEvent().detail(Details.CREDENTIAL_TYPE, RecoveryAuthnCodesCredentialModel.TYPE);
    Optional<RecoveryAuthnCodesCredentialModel> remaining = credential(user);
    if (remaining.isEmpty() || remaining.get().allCodesUsed()) {
      // Like RecoveryAuthnCodesFormAuthenticator: new codes are needed before the next login.
      user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES);
    }
    context.success(RecoveryAuthnCodesCredentialModel.TYPE);
  }

  static Integer remaining(CredentialModel credential) {
    try {
      return JsonSerialization.readValue(credential.getCredentialData(), RecoveryAuthnCodesCredentialData.class).getRemainingCodes();
    } catch (IOException | RuntimeException e) {
      return null;
    }
  }
}
