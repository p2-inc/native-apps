package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code native-password} (spec/04 §3.2). Validation is delegated to Keycloak's
 * {@link PasswordCredentialProvider} via {@code user.credentialManager().isValid(...)}, exactly as
 * {@code PasswordForm} does; brute-force accounting happens through the processor.
 */
public class NativePasswordAuthenticator extends NativeAuthenticatorBase
    implements CredentialValidator<PasswordCredentialProvider> {

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSWORD;
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
  public PasswordCredentialProvider getCredentialProvider(KeycloakSession session) {
    return (PasswordCredentialProvider)
        session.getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
  }

  @Override
  public ChallengeDescriptor describe(
      AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    return new ChallengeDescriptor(ChallengeType.PASSWORD)
        .setLabel("Password")
        .param("username_known", context.getUser() != null);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String password = form(context).getFirst(Protocol.PASSWORD);
    if (password == null || password.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Password is required");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    if (user.credentialManager().isValid(UserCredentialModel.password(password))) {
      context.getAuthenticationSession().setAuthNote(AuthenticationManager.PASSWORD_VALIDATED, "true");
      context.success(PasswordCredentialModel.TYPE);
      return;
    }
    context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
    failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid password");
  }
}
