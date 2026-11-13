package io.phasetwo.keycloak.nativeauth.pin;

import io.phasetwo.keycloak.nativeauth.authenticators.NativeAuthenticatorBase;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.PinVerification;
import io.phasetwo.keycloak.pin.credential.PinCredentialProvider;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code native-pin} (spec/03 §4.17, spec/20 D7): the PIN factor of the native profile. Every PIN
 * check goes through keycloak-pin's {@link PinCredentialProvider} with this execution's {@code
 * max-attempts}, so browser and native logins share one credential, one attempt counter and one
 * lock. Wrong and locked attempts emit {@code INVALID_USER_CREDENTIALS} with {@code
 * credential_type=phasetwo-pin} (plus {@code reason=pin_locked} when locked), like keycloak-pin's
 * browser authenticator, and count as brute-force failures.
 */
public class NativePinAuthenticator extends NativeAuthenticatorBase
    implements CredentialValidator<PinCredentialProvider> {

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PIN;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return getCredentialProvider(session).hasPin(realm, user);
  }

  @Override
  public PinCredentialProvider getCredentialProvider(KeycloakSession session) {
    return PinCredentialProvider.get(session);
  }

  @Override
  public ChallengeDescriptor describe(
      AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    PinCredentialProvider pins = getCredentialProvider(context.getSession());
    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();
    // The stored PIN's own length (a later change of the realm setting does not break it); the
    // realm's length for a legacy credential whose length is unknown.
    int length =
        user == null
            ? pins.getRequiredLength(realm)
            : pins.getStoredLength(realm, user).orElseGet(() -> pins.getRequiredLength(realm));
    return new ChallengeDescriptor(ChallengeType.PIN).setLabel("PIN").param("length", length);
  }

  /** A PIN that is already locked is announced on the first descriptor, not after one more try. */
  @Override
  public void prepare(
      AuthenticationFlowContext context,
      AuthenticationExecutionModel execution,
      ChallengeDescriptor descriptor,
      boolean required) {
    UserModel user = context.getUser();
    if (descriptor.getError() != null || user == null) return;
    if (getCredentialProvider(context.getSession()).isLocked(context.getRealm(), user)) {
      descriptor
          .setError(new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_CREDENTIAL_LOCKED, MSG_LOCKED))
          .setRetry(new ChallengeDescriptor.Retry(0));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String pin = param(context, Protocol.PIN);
    if (pin == null || pin.isEmpty()) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "PIN is required");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }
    RealmModel realm = context.getRealm();
    int maxAttempts = PinConfig.maxAttempts(context.getAuthenticatorConfig());
    PinVerification result = getCredentialProvider(context.getSession()).verify(realm, user, pin, maxAttempts);
    switch (result.outcome()) {
      case VALID -> context.success(PinConstants.CREDENTIAL_TYPE);
      case INVALID -> {
        context
            .getEvent()
            .user(user)
            .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
            .error(Errors.INVALID_USER_CREDENTIALS);
        // retry.remaining is the PIN's own budget, present only when the execution has one
        // (spec/03 §4.17).
        ChallengeDescriptor.Retry retry =
            result.isUnlimited() ? null : new ChallengeDescriptor.Retry(result.remainingAttempts());
        failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid PIN", retry);
      }
      case LOCKED -> {
        context
            .getEvent()
            .user(user)
            .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
            .detail(Details.REASON, PinConstants.EVENT_REASON_LOCKED)
            .error(Errors.INVALID_USER_CREDENTIALS);
        failAndRechallenge(
            context, Protocol.DESC_ERR_CREDENTIAL_LOCKED, MSG_LOCKED, new ChallengeDescriptor.Retry(0));
      }
      // The PIN was removed between the challenge and the answer: let the flow move on.
      case NOT_CONFIGURED -> context.attempted();
    }
  }

  static final String MSG_LOCKED =
      "The PIN is locked after too many wrong attempts; reset it to sign in with a PIN";
}
