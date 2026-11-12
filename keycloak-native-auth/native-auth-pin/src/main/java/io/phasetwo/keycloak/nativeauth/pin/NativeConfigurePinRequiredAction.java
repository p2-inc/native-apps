package io.phasetwo.keycloak.nativeauth.pin;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.requiredactions.NativeRequiredActionBase;
import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.PinSetResult;
import io.phasetwo.keycloak.pin.credential.PinCredentialProvider;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;

/**
 * {@code native-configure-pin} (spec/03 §4.18, spec/20 D7): the JSON variant of keycloak-pin's
 * {@code phasetwo-configure-pin}, for which it substitutes (spec/03 §4.11). The PIN is stored
 * through {@link PinCredentialProvider#setPin}, so format, weak-PIN and confirmation rules are
 * keycloak-pin's and a new PIN replaces the old one with its counter and lock cleared.
 */
public class NativeConfigurePinRequiredAction extends NativeRequiredActionBase {

  public NativeConfigurePinRequiredAction(KeycloakSession session) {
    super(session);
  }

  @Override
  protected String providerId() {
    return NativeConfigurePinRequiredActionFactory.PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PIN_SETUP;
  }

  @Override
  protected void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    int length = PinCredentialProvider.get(session).getRequiredLength(context.getRealm());
    emit(
        context,
        new ChallengeDescriptor(ChallengeType.PIN_SETUP)
            .setLabel("Choose a PIN")
            .setError(error)
            .param("length", length));
  }

  @Override
  public void processAction(RequiredActionContext context) {
    EventBuilder event =
        context
            .getEvent()
            .clone()
            .event(EventType.UPDATE_CREDENTIAL)
            .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE);
    String pin = form(context).getFirst(Protocol.PIN);
    String confirm = form(context).getFirst(Protocol.PIN_CONFIRM);
    if (isBlank(pin)) {
      challenge(context, error(Protocol.DESC_ERR_MISSING_CREDENTIAL, "A PIN is required"));
      return;
    }
    PinCredentialProvider pins = PinCredentialProvider.get(session);
    PinSetResult result = pins.setPin(context.getRealm(), context.getUser(), pin, confirm);
    switch (result) {
      case OK -> {
        event.success();
        context.success();
      }
      case INVALID_FORMAT ->
          challenge(
              context,
              error(
                  Protocol.DESC_ERR_INVALID_FORMAT,
                  "The PIN must be exactly " + pins.getRequiredLength(context.getRealm()) + " digits"));
      case WEAK ->
          challenge(
              context,
              error(Protocol.DESC_ERR_WEAK_PIN, "The PIN is too easy to guess; avoid repeated digits and simple runs"));
      case MISMATCH -> challenge(context, error(Protocol.DESC_ERR_PIN_MISMATCH, "PINs do not match"));
    }
  }

  private static ChallengeDescriptor.ChallengeError error(String code, String message) {
    return new ChallengeDescriptor.ChallengeError(code, message);
  }
}
