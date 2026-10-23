package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class NativePasskeyAuthenticatorFactory extends AbstractNativeAuthenticatorFactory {

  public static final String PROVIDER_ID = "native-passkey";

  private static final NativePasskeyAuthenticator SINGLETON = new NativePasskeyAuthenticator();

  /**
   * Execution config: when {@code true} and the identified user has no passkey, the login continues
   * with the other alternative (password) and {@code native-passkey-register} is added to the
   * authentication session, so the passkey is enrolled in-band right after (spec/04 §4, spec/14 D4).
   * Only meaningful for an ALTERNATIVE execution; a REQUIRED one still fails with
   * {@code access_denied} because nothing could authenticate the user first.
   */
  public static final String CONFIG_ENROL_ON_FIRST_LOGIN = "enrol-on-first-login";

  /**
   * Execution config: with {@link #CONFIG_ENROL_ON_FIRST_LOGIN}, the scheduled registration is an
   * offer the user may decline ("Not now", {@code action=skip}); the next login offers it again
   * (spec/03 §4.4, §4.11).
   */
  public static final String CONFIG_ENROL_OPTIONAL = "enrol-optional";

  private static final List<ProviderConfigProperty> CONFIG;

  static {
    ProviderConfigProperty p = new ProviderConfigProperty();
    p.setName(CONFIG_ENROL_ON_FIRST_LOGIN);
    p.setLabel("Enrol on first login");
    p.setHelpText("Add the native-passkey-register required action to a native login of a user who has no passkey yet (the realm must have that action enabled). Only for an ALTERNATIVE execution next to another factor.");
    p.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    p.setDefaultValue("false");
    ProviderConfigProperty optional = new ProviderConfigProperty();
    optional.setName(CONFIG_ENROL_OPTIONAL);
    optional.setLabel("Enrolment optional");
    optional.setHelpText("With 'Enrol on first login': the user may decline the passkey enrolment for this login ('Not now'); it is offered again at the next login.");
    optional.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    optional.setDefaultValue("false");
    CONFIG = List.of(p, optional);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSKEY;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Native: Passkey";
  }

  @Override
  public String getHelpText() {
    return "Validates the 'passkey' challenge of the native authentication profile (WebAuthn assertion) against the realm's Passwordless policy and the user's passkeys; supports discoverable (username-less) login.";
  }

  @Override
  public String getReferenceCategory() {
    return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG;
  }
}
