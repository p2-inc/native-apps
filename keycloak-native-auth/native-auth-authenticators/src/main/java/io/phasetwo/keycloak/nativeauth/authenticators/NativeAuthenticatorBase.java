package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.spi.ChallengeEnvelope;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticator;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Base class of the native authenticators (spec/04 §3.1).
 *
 * <p>How a multi-entry {@code challenges[]} set is produced (spec/08 Q2, answer (a)): Keycloak's
 * {@code DefaultAuthenticationFlow} hands every authenticator the list of currently eligible
 * ALTERNATIVE executions through {@link AuthenticationFlowContext#getAuthenticationSelections()}
 * (the same list that feeds the browser "Try another way" screen). Instead of a chooser page, this
 * base class asks each eligible sibling that is itself a {@link NativeAuthenticator} to
 * {@link NativeAuthenticator#describe describe} itself, and puts all descriptors into the
 * per-request {@link ChallengeEnvelope}. The endpoint later routes the client's answer to whichever
 * execution id the client picked. No change to the flow engine is needed.
 */
public abstract class NativeAuthenticatorBase implements NativeAuthenticator {

  protected final Logger log = Logger.getLogger(getClass());

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (!NativeRequestContext.isNative(context)) {
      // Placed in a browser flow by mistake: do nothing and let the flow move on (spec/04 §3.1).
      log.warnf(
          "Native authenticator '%s' used outside a native authentication session; marking attempted",
          context.getExecution().getAuthenticator());
      context.attempted();
      return;
    }
    challenge(context, buildChallengeSet(context, null), false, null);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}

  // ---------------------------------------------------------------------------------------------
  // Challenge set construction

  /** The current execution's descriptor (with {@code error}) followed by eligible native siblings. */
  protected List<ChallengeDescriptor> buildChallengeSet(
      AuthenticationFlowContext context, ChallengeDescriptor.ChallengeError errorForCurrent) {
    List<ChallengeDescriptor> set = new ArrayList<>();
    Map<String, NativeAuthenticator> authenticators = new HashMap<>();
    Map<String, AuthenticationExecutionModel> executions = new HashMap<>();
    AuthenticationExecutionModel current = context.getExecution();
    set.add(describe(context, current).setId(current.getId()).setError(errorForCurrent));
    authenticators.put(current.getId(), this);
    executions.put(current.getId(), current);

    List<AuthenticationSelectionOption> selections = context.getAuthenticationSelections();
    if (selections != null) {
      for (AuthenticationSelectionOption option : selections) {
        AuthenticationExecutionModel sibling = option.getAuthenticationExecution();
        if (sibling == null
            || sibling.getId().equals(current.getId())
            || sibling.isAuthenticatorFlow()
            || isProcessed(context.getAuthenticationSession(), sibling)) {
          continue;
        }
        NativeAuthenticator siblingAuthenticator = nativeAuthenticator(context.getSession(), sibling);
        if (siblingAuthenticator == null) {
          log.debugf(
              "Skipping non-native alternative '%s' in native challenge set", sibling.getAuthenticator());
          continue;
        }
        UserModel user = context.getUser();
        // Credential-based siblings are offered only when the identified user has the credential;
        // before a user is known only user-less authenticators (e.g. discoverable passkey) qualify.
        boolean eligible =
            user == null
                ? !siblingAuthenticator.requiresUser()
                : siblingAuthenticator.configuredFor(context.getSession(), context.getRealm(), user);
        if (!eligible) {
          continue;
        }
        set.add(siblingAuthenticator.describe(context, sibling).setId(sibling.getId()));
        authenticators.put(sibling.getId(), siblingAuthenticator);
        executions.put(sibling.getId(), sibling);
      }
    }
    // Order follows the operator's flow layout (depth-first execution order), not the engine's
    // pick, which follows the user's credential priority and would list a newly registered passkey
    // after the password (spec/11 D3).
    Map<String, Integer> order = flowOrder(context.getRealm(), context.getTopLevelFlow());
    set.sort(Comparator.comparingInt(d -> order.getOrDefault(d.getId(), Integer.MAX_VALUE)));
    boolean single = set.size() == 1;
    for (ChallengeDescriptor d : set) {
      d.setRequired(single);
    }
    // Side effects that depend on the set's shape (an OTP is only sent unasked when it is the single
    // option, spec/03 §4.6) happen now that `required` is known.
    for (ChallengeDescriptor d : set) {
      NativeAuthenticator a = authenticators.get(d.getId());
      if (a != null) {
        a.prepare(context, executions.get(d.getId()), d, single);
      }
    }
    return set;
  }

  /** Execution id → position in a depth-first walk of the top-level flow (executions sorted by priority). */
  static Map<String, Integer> flowOrder(RealmModel realm, AuthenticationFlowModel topLevelFlow) {
    Map<String, Integer> order = new HashMap<>();
    if (topLevelFlow != null) collectFlowOrder(realm, topLevelFlow.getId(), order);
    return order;
  }

  private static void collectFlowOrder(RealmModel realm, String flowId, Map<String, Integer> order) {
    realm
        .getAuthenticationExecutionsStream(flowId)
        .forEachOrdered(
            e -> {
              order.put(e.getId(), order.size());
              if (e.isAuthenticatorFlow() && e.getFlowId() != null) {
                collectFlowOrder(realm, e.getFlowId(), order);
              }
            });
  }

  /** Hands the set to the endpoint and stops the flow (CHALLENGE or FAILURE_CHALLENGE). */
  protected void challenge(
      AuthenticationFlowContext context,
      List<ChallengeDescriptor> descriptors,
      boolean failure,
      AuthenticationFlowError error) {
    NativeRequestContext.envelope(context.getSession()).replaceAll(descriptors);
    NativeRequestContext.setPending(context.getAuthenticationSession(), descriptors);
    if (failure) {
      // FAILURE_CHALLENGE makes the processor record a brute-force failure for the user.
      context.failureChallenge(error, NativeRequestContext.markerResponse());
    } else {
      context.challenge(NativeRequestContext.markerResponse());
    }
  }

  /** Re-issue the set with {@code error} on this challenge and count it as a failed attempt. */
  protected void failAndRechallenge(AuthenticationFlowContext context, String code, String message) {
    failAndRechallenge(context, code, message, retryAfterThisFailure(context));
  }

  /**
   * Like {@link #failAndRechallenge(AuthenticationFlowContext, String, String)} with an explicit
   * {@code retry} for this challenge, for factors with an attempt limit of their own (a PIN,
   * spec/03 §4.17); {@code null} leaves {@code retry} out.
   */
  protected void failAndRechallenge(
      AuthenticationFlowContext context, String code, String message, ChallengeDescriptor.Retry retry) {
    List<ChallengeDescriptor> set = buildChallengeSet(context, new ChallengeDescriptor.ChallengeError(code, message));
    if (retry != null) {
      String current = context.getExecution().getId();
      set.stream().filter(d -> current.equals(d.getId())).findFirst().ifPresent(d -> d.setRetry(retry));
    }
    challenge(context, set, true, AuthenticationFlowError.INVALID_CREDENTIALS);
  }

  /**
   * {@code retry.remaining} (spec/03 §3.3): attempts left before the realm's brute-force protection
   * locks the account, counting the failure being reported now (the processor records it after this
   * method returns). {@code null} when the realm has no brute-force protection.
   */
  protected ChallengeDescriptor.Retry retryAfterThisFailure(AuthenticationFlowContext context) {
    RealmModel realm = context.getRealm();
    if (!realm.isBruteForceProtected() || realm.getFailureFactor() <= 0) {
      return null;
    }
    UserModel user = context.getUser();
    if (user == null) {
      return null;
    }
    UserLoginFailureModel failures = context.getSession().loginFailures().getUserLoginFailure(realm, user.getId());
    int recorded = failures == null ? 0 : failures.getNumFailures();
    return new ChallengeDescriptor.Retry(Math.max(0, realm.getFailureFactor() - (recorded + 1)));
  }

  /** Re-issue the set with {@code error} on this challenge without counting a failed attempt. */
  protected void rechallenge(AuthenticationFlowContext context, String code, String message) {
    challenge(
        context,
        buildChallengeSet(context, new ChallengeDescriptor.ChallengeError(code, message)),
        false,
        null);
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers for subclasses

  protected MultivaluedMap<String, String> form(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
    return form == null ? new MultivaluedHashMap<>() : form;
  }

  protected String param(AuthenticationFlowContext context, String name) {
    String value = form(context).getFirst(name);
    return value == null ? null : value.trim();
  }

  /**
   * Terminal checks shared by every factor (spec/07 §2): brute-force lockout and disabled accounts
   * fail the flow ({@code access_denied}) instead of re-challenging.
   *
   * @return true if the user may continue
   */
  protected boolean checkUserEnabled(AuthenticationFlowContext context, UserModel user) {
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().user(user).error(bruteForceError);
      context.failure(
          Errors.USER_TEMPORARILY_DISABLED.equals(bruteForceError)
              ? AuthenticationFlowError.USER_TEMPORARILY_DISABLED
              : AuthenticationFlowError.USER_DISABLED);
      return false;
    }
    if (!user.isEnabled()) {
      context.getEvent().user(user).error(Errors.USER_DISABLED);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return false;
    }
    return true;
  }

  protected static boolean isProcessed(
      AuthenticationSessionModel authSession, AuthenticationExecutionModel execution) {
    if (execution.isDisabled()) return true;
    AuthenticationSessionModel.ExecutionStatus status =
        authSession.getExecutionStatus().get(execution.getId());
    if (status == null) return false;
    return status == AuthenticationSessionModel.ExecutionStatus.SUCCESS
        || status == AuthenticationSessionModel.ExecutionStatus.SKIPPED
        || status == AuthenticationSessionModel.ExecutionStatus.ATTEMPTED
        || status == AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED;
  }

  /** @return the execution's authenticator if it is native, else {@code null}. */
  public static NativeAuthenticator nativeAuthenticator(
      KeycloakSession session, AuthenticationExecutionModel execution) {
    AuthenticatorFactory factory =
        (AuthenticatorFactory)
            session
                .getKeycloakSessionFactory()
                .getProviderFactory(Authenticator.class, execution.getAuthenticator());
    if (!(factory instanceof NativeAuthenticatorFactory)) return null;
    Authenticator authenticator = factory.create(session);
    return authenticator instanceof NativeAuthenticator na ? na : null;
  }

  protected static String nonEmpty(String s) {
    return s == null || s.isEmpty() ? null : s;
  }

  /** Message keys are intentionally plain English for Phase 0; i18n is a later concern. */
  protected static final String MSG_INVALID_CREDENTIAL = "Invalid credential";

  protected static final String MSG_INVALID_USER = "Invalid username";
}
