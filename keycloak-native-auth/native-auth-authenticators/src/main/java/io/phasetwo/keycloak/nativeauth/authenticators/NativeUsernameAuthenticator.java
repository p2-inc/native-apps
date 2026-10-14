package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

/**
 * {@code native-username} (spec/04 §3.2): identifies the user by username or e-mail and sets it on
 * the context. Mirrors the user lookup of Keycloak's {@code UsernameForm}.
 */
public class NativeUsernameAuthenticator extends NativeAuthenticatorBase {

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.USERNAME;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (NativeRequestContext.isNative(context) && context.getUser() != null) {
      // Step-up / re-authentication inside an existing user session (spec/03 §5): the endpoint
      // identified the user from the post-login auth_session, so there is nothing to ask here.
      context.getEvent().detail(Details.USERNAME, context.getUser().getUsername());
      context.success();
      return;
    }
    super.authenticate(context);
  }

  @Override
  public ChallengeDescriptor describe(
      AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    return new ChallengeDescriptor(ChallengeType.USERNAME)
        .setLabel("Username")
        .param("allow_email", context.getRealm().isLoginWithEmailAllowed())
        .param(
            "hint",
            nonEmpty(
                context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM)));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    String username = param(context, Protocol.USERNAME);
    if (username == null || username.isEmpty() || AuthenticatorUtils.isUsernameTooLong(username)) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Username is required");
      return;
    }
    context.getEvent().detail(Details.USERNAME, username);
    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

    UserModel user;
    try {
      user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
    } catch (ModelDuplicateException e) {
      context.getEvent().error(Errors.USERNAME_IN_USE);
      failAndRechallenge(context, Protocol.DESC_ERR_INVALID_USER, "Ambiguous username");
      return;
    }

    if (user == null) {
      // Same cost as a real password check so timing does not leak existence (as UsernameForm does).
      AuthenticatorUtils.dummyHash(context);
      context.getEvent().error(Errors.USER_NOT_FOUND);
      if (revealUserNotFound(context)) {
        failAndRechallenge(context, Protocol.DESC_ERR_INVALID_USER, MSG_INVALID_USER);
      } else {
        // Generic error; see spec/09 for the enumeration-resistance limitation of Phase 0.
        failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid username or password");
      }
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    context.setUser(user);
    context.success();
  }

  private static boolean revealUserNotFound(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    return config != null
        && config.getConfig() != null
        && Boolean.parseBoolean(
            config.getConfig().get(NativeUsernameAuthenticatorFactory.CONFIG_REVEAL_USER_NOT_FOUND));
  }

  @Override
  protected boolean checkUserEnabled(AuthenticationFlowContext context, UserModel user) {
    // A disabled/locked account must look like an unknown one at the username step
    // (spec/03 §4.1 "MUST NOT reveal whether the user exists"), so re-challenge instead of failing.
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().user(user).error(bruteForceError);
      failAndRechallengeGeneric(context);
      return false;
    }
    if (!user.isEnabled()) {
      context.getEvent().user(user).error(Errors.USER_DISABLED);
      failAndRechallengeGeneric(context);
      return false;
    }
    return true;
  }

  private void failAndRechallengeGeneric(AuthenticationFlowContext context) {
    challenge(
        context,
        buildChallengeSet(
            context,
            new ChallengeDescriptor.ChallengeError(
                Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid username or password")),
        true,
        AuthenticationFlowError.INVALID_USER);
  }
}
