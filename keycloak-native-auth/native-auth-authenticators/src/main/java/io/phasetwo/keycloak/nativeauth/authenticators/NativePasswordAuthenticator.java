package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
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
    if (user == null && NativeRequestContext.isPhantom(context.getAuthenticationSession())) {
      phantomAnswer(context, password);
      return;
    }
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

  /**
   * spec/03 §4.1: the username step found no usable user. Every answer costs a hash and fails like
   * a wrong password, with the same {@code retry.remaining} countdown a real user would see, and
   * after the realm's failure factor the flow ends with the same "temporarily locked" refusal.
   * {@code failureChallenge} lets the processor record a failure for a real-but-disabled account.
   */
  private void phantomAnswer(AuthenticationFlowContext context, String password) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    AuthenticatorUtils.dummyHash(context);
    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
    if (password == null || password.isEmpty()) {
      challenge(context, List.of(phantomDescriptor(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Password is required", null)), false, null);
      return;
    }
    int attempts = 1;
    try {
      attempts = Integer.parseInt(authSession.getAuthNote(NativeRequestContext.AUTH_NOTE_PHANTOM_ATTEMPTS)) + 1;
    } catch (RuntimeException ignored) {
      // first attempt
    }
    authSession.setAuthNote(NativeRequestContext.AUTH_NOTE_PHANTOM_ATTEMPTS, String.valueOf(attempts));
    RealmModel realm = context.getRealm();
    if (realm.isBruteForceProtected() && realm.getFailureFactor() > 0) {
      int remaining = Math.max(0, realm.getFailureFactor() - attempts);
      if (remaining == 0) {
        context.failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
        return;
      }
      challenge(context, List.of(phantomDescriptor(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid password", new ChallengeDescriptor.Retry(remaining))), true, AuthenticationFlowError.INVALID_CREDENTIALS);
      return;
    }
    challenge(context, List.of(phantomDescriptor(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid password", null)), true, AuthenticationFlowError.INVALID_CREDENTIALS);
  }

  private ChallengeDescriptor phantomDescriptor(AuthenticationFlowContext context, String code, String message, ChallengeDescriptor.Retry retry) {
    return describe(context, context.getExecution())
        .setId(context.getExecution().getId())
        .setRequired(true)
        .setError(code, message)
        .setRetry(retry)
        .param("username_known", true);
  }
}
