package io.phasetwo.keycloak.nativeauth.registration;

import io.phasetwo.keycloak.nativeauth.authenticators.NativeAuthenticatorBase;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.requiredactions.NativeUpdatePasswordRequiredAction;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.UserProfileAttributeMetadata;
import org.keycloak.representations.idm.UserProfileMetadata;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.UserProfileUtil;
import org.keycloak.userprofile.ValidationException;

/**
 * {@code native-registration} (spec/22 phase 3): the {@code registration} challenge. Its params
 * describe the realm's declarative user profile for registration (the attributes Keycloak's own
 * registration page shows, with labels, required flags, input types, options and validators) and the
 * password policy; the answer carries one form field per attribute plus {@code password} and {@code
 * password_confirm}. Validation is Keycloak's: the user profile's validators (duplicate username or
 * email included) and the password policy. Refused fields come back as {@code invalid_profile} with
 * {@code params.field_errors}. On success the user is created with the password and the flow goes
 * on, so required actions such as email verification run natively before the code is issued.
 */
public class NativeRegistrationAuthenticator extends NativeAuthenticatorBase {

  /** Form fields that are never user-profile attributes. */
  private static final Set<String> PROTOCOL_FIELDS =
      Set.of(
          Protocol.AUTH_SESSION,
          Protocol.CHALLENGE_TYPE,
          Protocol.CHALLENGE_ID,
          Protocol.CLIENT_ID,
          Protocol.ACTION,
          Protocol.PASSWORD,
          Protocol.PASSWORD_CONFIRM);

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.REGISTRATION;
  }

  @Override
  public ChallengeDescriptor describe(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    KeycloakSession session = context.getSession();
    RealmModel realm = context.getRealm();
    Messages messages = Messages.of(session, realm);
    UserProfile profile = session.getProvider(UserProfileProvider.class).create(UserProfileContext.REGISTRATION, new MultivaluedHashMap<>());
    return new ChallengeDescriptor(ChallengeType.REGISTRATION)
        .setLabel("Create an account")
        .param("attributes", attributes(session, profile, messages))
        .param("password_policy", NativeUpdatePasswordRequiredAction.policyHints(realm))
        .param("email_as_username", realm.isRegistrationEmailAsUsername());
  }

  /** The registration attributes in display order, as the client renders them. */
  static List<Map<String, Object>> attributes(KeycloakSession session, UserProfile profile, Messages messages) {
    UserProfileMetadata metadata = UserProfileUtil.createUserProfileMetadata(session, profile);
    List<Map<String, Object>> list = new ArrayList<>();
    if (metadata == null || metadata.getAttributes() == null) return list;
    for (UserProfileAttributeMetadata a : metadata.getAttributes()) {
      if (a.isReadOnly()) continue;
      Map<String, Object> attribute = new LinkedHashMap<>();
      attribute.put("name", a.getName());
      attribute.put("display_name", messages.label(a.getDisplayName(), a.getName()));
      attribute.put("required", a.isRequired());
      if (a.isMultivalued()) attribute.put("multivalued", true);
      if (a.getGroup() != null) attribute.put("group", a.getGroup());
      if (a.getDefaultValue() != null) attribute.put("default_value", a.getDefaultValue());
      Map<String, Object> annotations = a.getAnnotations();
      if (annotations != null && annotations.get("inputType") != null) {
        attribute.put("input_type", String.valueOf(annotations.get("inputType")));
      }
      Map<String, Map<String, Object>> validators = a.getValidators();
      if (validators != null && !validators.isEmpty()) {
        attribute.put("validators", validators);
        Map<String, Object> options = validators.get("options");
        if (options != null && options.get("options") != null) attribute.put("options", options.get("options"));
      }
      if (annotations != null && !annotations.isEmpty()) attribute.put("annotations", annotations);
      list.add(attribute);
    }
    return list;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    KeycloakSession session = context.getSession();
    RealmModel realm = context.getRealm();
    Messages messages = Messages.of(session, realm);
    MultivaluedMap<String, String> form = form(context);
    MultivaluedMap<String, String> attributes = new MultivaluedHashMap<>();
    form.forEach(
        (name, values) -> {
          if (!PROTOCOL_FIELDS.contains(name) && !name.startsWith(Protocol.EXTENSION_PARAM_PREFIX)) {
            attributes.put(name, values);
          }
        });
    String password = form.getFirst(Protocol.PASSWORD);
    String confirm = form.getFirst(Protocol.PASSWORD_CONFIRM);

    UserProfile profile = session.getProvider(UserProfileProvider.class).create(UserProfileContext.REGISTRATION, attributes);
    Map<String, List<String>> errors = new LinkedHashMap<>();
    try {
      profile.validate();
    } catch (ValidationException e) {
      for (ValidationException.Error error : e.getErrors()) {
        List<String> list = errors.computeIfAbsent(error.getAttribute(), k -> new ArrayList<>());
        String message = error.getFormattedMessage((key, params) -> messages.format(key, params));
        // Keycloak reports a duplicate username from two validators: show it once.
        if (!list.contains(message)) list.add(message);
      }
    }
    if (password == null || password.isEmpty()) {
      errors.computeIfAbsent(Protocol.PASSWORD, k -> new ArrayList<>()).add(messages.format("missingPasswordMessage"));
    } else if (!password.equals(confirm)) {
      errors.computeIfAbsent(Protocol.PASSWORD_CONFIRM, k -> new ArrayList<>()).add(messages.format("notMatchPasswordMessage"));
    } else {
      String username = realm.isRegistrationEmailAsUsername() ? attributes.getFirst(UserModel.EMAIL) : attributes.getFirst(UserModel.USERNAME);
      PolicyError policy = session.getProvider(PasswordPolicyManagerProvider.class).validate(username, password);
      if (policy != null) {
        errors.computeIfAbsent(Protocol.PASSWORD, k -> new ArrayList<>()).add(messages.format(policy.getMessage(), policy.getParameters()));
      }
    }
    if (!errors.isEmpty()) {
      context.getEvent().detail(Details.REGISTER_METHOD, "native").error(Errors.INVALID_REGISTRATION);
      List<ChallengeDescriptor> set =
          buildChallengeSet(context, new ChallengeDescriptor.ChallengeError(Protocol.DESC_ERR_INVALID_PROFILE, "Some fields need attention"));
      String current = context.getExecution().getId();
      set.stream().filter(d -> current.equals(d.getId())).findFirst().ifPresent(d -> d.param("field_errors", errors));
      challenge(context, set, false, null);
      return;
    }

    UserModel user = profile.create();
    user.setEnabled(true);
    user.credentialManager().updateCredential(UserCredentialModel.password(password, false));
    context.setUser(user);
    context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, user.getUsername());
    context
        .getEvent()
        .user(user)
        .detail(Details.USERNAME, user.getUsername())
        .detail(Details.REGISTER_METHOD, "native");
    if (user.getEmail() != null) context.getEvent().detail(Details.EMAIL, user.getEmail());
    log.debugf("native-registration: created user %s", user.getUsername());
    context.success();
  }
}
