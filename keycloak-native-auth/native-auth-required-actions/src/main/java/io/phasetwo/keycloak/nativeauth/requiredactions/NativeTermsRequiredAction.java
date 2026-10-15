package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.util.List;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.TermsAndConditions;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;

/**
 * {@code native-terms} (spec/03 §4.14): substitutes for Keycloak's {@code TERMS_AND_CONDITIONS}.
 * The descriptor carries the text and/or URL from the action's configuration (fallback: realm
 * attributes, which a realm export can carry); accepting sets the same {@code terms_and_conditions}
 * user attribute Keycloak's own action sets, declining ends the login.
 */
public class NativeTermsRequiredAction extends NativeRequiredActionBase {

  public NativeTermsRequiredAction(KeycloakSession session) {
    super(session);
  }

  @Override
  String providerId() {
    return NativeTermsRequiredActionFactory.PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.TERMS;
  }

  @Override
  void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error) {
    RealmModel realm = context.getRealm();
    RequiredActionConfigModel config = context.getConfig();
    String text = configured(config, NativeTermsRequiredActionFactory.CONFIG_TEXT, realm.getAttribute(Protocol.ATTR_TERMS_TEXT));
    String url = configured(config, NativeTermsRequiredActionFactory.CONFIG_URL, realm.getAttribute(Protocol.ATTR_TERMS_URL));
    String version = configured(config, NativeTermsRequiredActionFactory.CONFIG_VERSION, realm.getAttribute(Protocol.ATTR_TERMS_VERSION));
    if (text == null && url == null) {
      text = "Please accept the terms and conditions to continue.";
    }
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.TERMS)
            .setLabel("Terms and conditions")
            .setError(error)
            .param("text", text)
            .param("url", url)
            .param("version", version);
    emit(context, d);
  }

  private static String configured(RequiredActionConfigModel config, String key, String fallback) {
    String value = config == null ? null : config.getConfigValue(key);
    if (value == null || value.isBlank()) value = fallback;
    return value == null || value.isBlank() ? null : value.trim();
  }

  @Override
  public void processAction(RequiredActionContext context) {
    String accepted = param(context, Protocol.ACCEPTED);
    if ("false".equalsIgnoreCase(accepted)) {
      context.getUser().removeAttribute(TermsAndConditions.USER_ATTRIBUTE);
      context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION_ERROR).detail(Details.CUSTOM_REQUIRED_ACTION, providerId()).error(Errors.REJECTED_BY_USER);
      context.failure("declined");
      return;
    }
    if (!"true".equalsIgnoreCase(accepted)) {
      challenge(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_MISSING_CREDENTIAL, "accepted=true or accepted=false is required"));
      return;
    }
    context.getUser().setAttribute(TermsAndConditions.USER_ATTRIBUTE, List.of(Integer.toString(Time.currentTime())));
    context.success();
  }
}
