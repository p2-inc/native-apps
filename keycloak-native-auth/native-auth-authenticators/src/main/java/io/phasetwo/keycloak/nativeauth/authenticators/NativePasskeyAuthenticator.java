package io.phasetwo.keycloak.nativeauth.authenticators;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.credential.dto.WebAuthnCredentialData;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;

/**
 * {@code native-passkey} (spec/03 §4.3, spec/04 §3.2): a WebAuthn assertion against the realm's
 * <b>Passwordless</b> policy and the user's {@code webauthn-passwordless} credentials. Validation is
 * exactly the portion of Keycloak's {@code WebAuthnPasswordlessAuthenticator.action()} that follows
 * form handling: build a {@code ServerProperty} from origin + RP ID + stored challenge, wrap the four
 * assertion fields in a {@code WebAuthnCredentialModelInput} and let the credential provider
 * (webauthn4j) verify signature, RP ID hash, origin (incl. the policy's extra origins), UV flag and
 * counter.
 *
 * <p>Discoverable login: {@link #requiresUser()} is {@code false}; when no user has been identified
 * yet the descriptor has empty {@code allow_credentials} and {@code discoverable=true}, and {@code
 * user_handle} selects the user. When a user is already known and has no passkey the execution is
 * marked {@code attempted} so the engine moves to the next alternative (spec/11 D2).
 *
 * <p>Per-execution challenge: generated once per request (session attribute) and stored in an auth
 * note keyed by execution id, so {@code describe()} is idempotent within a request even though it is
 * also called for sibling alternatives (spec/09 Q2), and the note is consumed single-use in {@link
 * #action}.
 */
public class NativePasskeyAuthenticator extends NativeAuthenticatorBase
    implements CredentialValidator<WebAuthnPasswordlessCredentialProvider> {

  static final String AUTH_NOTE_CHALLENGE_PREFIX = "native-auth.passkey.challenge.";
  private static final int DEFAULT_TIMEOUT_MS = 60_000;

  @Override
  public ChallengeType challengeType() {
    return ChallengeType.PASSKEY;
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
  }

  @Override
  public WebAuthnPasswordlessCredentialProvider getCredentialProvider(KeycloakSession session) {
    return (WebAuthnPasswordlessCredentialProvider)
        session.getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (NativeRequestContext.isNative(context)
        && user != null
        && !configuredFor(context.getSession(), context.getRealm(), user)) {
      // Known user without a passkey: nothing to offer here, let the next alternative challenge.
      context.attempted();
      return;
    }
    super.authenticate(context);
  }

  // ---------------------------------------------------------------------------------------------
  // describe

  @Override
  public ChallengeDescriptor describe(
      AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    WebAuthnPolicy policy = policy(context);
    String challenge = challengeFor(context, execution);
    ChallengeDescriptor d =
        new ChallengeDescriptor(ChallengeType.PASSKEY)
            .setLabel("Sign in with a passkey")
            .param("challenge", challenge)
            .param("rp_id", rpId(context, policy))
            .param("timeout", timeoutMillis(policy))
            .param("user_verification", userVerification(policy));
    List<Map<String, Object>> allow = new ArrayList<>();
    UserModel user = context.getUser();
    if (user != null) {
      user.credentialManager()
          .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
          .map(WebAuthnCredentialModel::createFromCredentialModel)
          .forEach(
              c -> {
                WebAuthnCredentialData data = c.getWebAuthnCredentialData();
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", "public-key");
                entry.put("id", Base64Url.encodeBase64ToBase64Url(data.getCredentialId()));
                if (data.getTransports() != null && !data.getTransports().isEmpty()) {
                  entry.put("transports", new ArrayList<>(data.getTransports()));
                }
                allow.add(entry);
              });
    }
    d.param("allow_credentials", allow);
    d.param("discoverable", allow.isEmpty());
    return d;
  }

  /** One fresh challenge per request and execution; the same value is reused by sibling describe() calls. */
  private static String challengeFor(AuthenticationFlowContext context, AuthenticationExecutionModel execution) {
    String key = AUTH_NOTE_CHALLENGE_PREFIX + execution.getId();
    String challenge = context.getSession().getAttribute(key, String.class);
    if (challenge == null) {
      challenge = Base64Url.encode(new DefaultChallenge().getValue());
      context.getSession().setAttribute(key, challenge);
      context.getAuthenticationSession().setAuthNote(key, challenge);
    }
    return challenge;
  }

  // ---------------------------------------------------------------------------------------------
  // action

  @Override
  public void action(AuthenticationFlowContext context) {
    context.getEvent().detail(Details.CREDENTIAL_TYPE, WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    String credentialIdParam = param(context, Protocol.CREDENTIAL_ID);
    String clientDataParam = param(context, Protocol.CLIENT_DATA_JSON);
    String authenticatorDataParam = param(context, Protocol.AUTHENTICATOR_DATA);
    String signatureParam = param(context, Protocol.SIGNATURE);
    String userHandleParam = param(context, Protocol.USER_HANDLE);
    if (isBlank(credentialIdParam) || isBlank(clientDataParam) || isBlank(authenticatorDataParam) || isBlank(signatureParam)) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "credential_id, client_data_json, authenticator_data and signature are required");
      return;
    }
    byte[] credentialId;
    byte[] clientDataJson;
    byte[] authenticatorData;
    byte[] signature;
    byte[] userHandle;
    try {
      credentialId = Base64Url.decode(credentialIdParam);
      clientDataJson = Base64Url.decode(clientDataParam);
      authenticatorData = Base64Url.decode(authenticatorDataParam);
      signature = Base64Url.decode(signatureParam);
      userHandle = isBlank(userHandleParam) ? null : Base64Url.decode(userHandleParam);
    } catch (RuntimeException e) {
      rechallenge(context, Protocol.DESC_ERR_MISSING_CREDENTIAL, "Assertion fields must be base64url");
      return;
    }

    // Resolve the user: the one identified earlier, or the one named by the discoverable credential.
    UserModel user = context.getUser();
    if (userHandle != null) {
      String userId = new String(userHandle, StandardCharsets.UTF_8);
      if (user != null && !user.getId().equals(userId)) {
        context.getEvent()
            .detail(WebAuthnConstants.FIRST_AUTHENTICATED_USER_ID, user.getId())
            .detail(WebAuthnConstants.AUTHENTICATED_USER_ID, userId)
            .error(Errors.DIFFERENT_USER_AUTHENTICATED);
        context.failure(AuthenticationFlowError.USER_CONFLICT);
        return;
      }
      if (user == null) {
        user = context.getSession().users().getUserById(context.getRealm(), userId);
      }
    }
    if (user == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Unknown passkey");
      return;
    }
    if (!checkUserEnabled(context, user)) {
      return;
    }

    // Single-use challenge stored by describe() for this execution.
    String noteKey = AUTH_NOTE_CHALLENGE_PREFIX + context.getExecution().getId();
    String challengeNote = context.getAuthenticationSession().getAuthNote(noteKey);
    context.getAuthenticationSession().removeAuthNote(noteKey);
    context.getSession().removeAttribute(noteKey);
    if (challengeNote == null) {
      context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
      failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Challenge expired or already used");
      return;
    }

    WebAuthnPolicy policy = policy(context);
    Origin origin = new Origin(UriUtils.getOrigin(context.getUriInfo().getBaseUri()));
    Challenge challenge = new DefaultChallenge(challengeNote);
    ServerProperty server = new ServerProperty(origin, rpId(context, policy), challenge);
    boolean uvRequired = Constants.WEBAUTHN_POLICY_OPTION_REQUIRED.equals(policy.getUserVerificationRequirement());

    WebAuthnCredentialModelInput input = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    input.setAuthenticationRequest(new AuthenticationRequest(credentialId, authenticatorData, clientDataJson, signature));
    input.setAuthenticationParameters(
        new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(server, uvRequired));

    boolean valid;
    try {
      valid = user.credentialManager().isValid(input);
    } catch (WebAuthnException e) {
      log.debugf("Passkey assertion rejected for user %s: %s", user.getUsername(), e.getMessage());
      valid = false;
    }
    String encodedCredentialId = Base64Url.encode(credentialId);
    if (!valid) {
      context.getEvent()
          .user(user)
          .detail(WebAuthnConstants.PUBKEY_CRED_ID_ATTR, encodedCredentialId)
          .error(Errors.INVALID_USER_CREDENTIALS);
      failAndRechallenge(context, Protocol.DESC_ERR_INVALID_CREDENTIAL, "Invalid passkey assertion");
      return;
    }
    context.setUser(user);
    context.getEvent()
        .detail(WebAuthnConstants.USER_VERIFICATION_CHECKED, Boolean.toString(uvRequired))
        .detail(WebAuthnConstants.PUBKEY_CRED_ID_ATTR, encodedCredentialId);
    context.success(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
  }

  // ---------------------------------------------------------------------------------------------
  // helpers

  static WebAuthnPolicy policy(AuthenticationFlowContext context) {
    return context.getRealm().getWebAuthnPolicyPasswordless();
  }

  static String rpId(AuthenticationFlowContext context, WebAuthnPolicy policy) {
    String rpId = policy.getRpId();
    return rpId == null || rpId.isEmpty() ? context.getUriInfo().getBaseUri().getHost() : rpId;
  }

  static int timeoutMillis(WebAuthnPolicy policy) {
    return policy.getCreateTimeout() > 0 ? policy.getCreateTimeout() * 1000 : DEFAULT_TIMEOUT_MS;
  }

  static String userVerification(WebAuthnPolicy policy) {
    String uv = policy.getUserVerificationRequirement();
    return uv == null || Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED.equals(uv)
        ? Constants.WEBAUTHN_POLICY_OPTION_PREFERED
        : uv;
  }

  private static boolean isBlank(String s) {
    return s == null || s.isEmpty();
  }
}
