package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.json.NativeAuthJson;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.session.AuthSessionCodec;
import io.phasetwo.keycloak.nativeauth.requiredactions.PasskeyRegistrationException;
import io.phasetwo.keycloak.nativeauth.requiredactions.PasskeyRegistrationOptions;
import io.phasetwo.keycloak.nativeauth.requiredactions.PasskeyRegistrationVerifier;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * The authenticated passkey registration endpoints (spec/03 §6, spec/04 §2.4). Fourth class allowed
 * to use Keycloak-internal APIs (spec/08 R2, spec/11): bearer-token authentication through {@code
 * AppAuthManager.BearerTokenAuthenticator} (also validates DPoP-bound tokens) and the user session
 * behind it for the freshness rule of spec/07 §5.
 *
 * <p>{@code registration_id} → challenge is a {@code SingleUseObjectProvider} entry (lifetime: the
 * realm's user-action timeout), consumed atomically by {@code /finish}.
 */
final class PasskeyRegistrationDriver {

  private static final Logger log = Logger.getLogger(PasskeyRegistrationDriver.class);
  static final String SINGLE_USE_PREFIX = "native-auth.passkey-registration-id:";
  private static final String NOTE_CHALLENGE = "challenge";
  private static final String NOTE_USER = "user";

  /** JSON body of {@code POST /passkey/register/finish}. */
  public static final class FinishRequest {
    public String registrationId;
    public String credentialId;
    public String clientDataJson;
    public String attestationObject;
    /** Comma-separated string or JSON array; both are accepted. */
    public Object transports;
    public String label;
  }

  private final KeycloakSession session;
  private final RealmModel realm;

  PasskeyRegistrationDriver(KeycloakSession session) {
    this.session = session;
    this.realm = session.getContext().getRealm();
  }

  Response options() {
    Authenticated auth = authenticate();
    String challenge = PasskeyRegistrationOptions.newChallenge();
    String registrationId = SecretGenerator.getInstance().randomString(32);
    Map<String, String> notes = new LinkedHashMap<>();
    notes.put(NOTE_CHALLENGE, challenge);
    notes.put(NOTE_USER, auth.user().getId());
    session.singleUseObjects().put(SINGLE_USE_PREFIX + registrationId, realm.getAccessCodeLifespanUserAction(), notes);

    Map<String, Object> body = new LinkedHashMap<>();
    body.put(Protocol.REGISTRATION_ID, registrationId);
    body.putAll(PasskeyRegistrationOptions.build(realm, auth.user(), baseUri(), challenge));
    log.debugf("Issued passkey registration options for user %s (registration %s)", auth.user().getUsername(), AuthSessionCodec.hashPrefix(registrationId));
    return Responses.json(Response.Status.OK, body);
  }

  Response finish(String json) {
    Authenticated auth = authenticate();
    FinishRequest req;
    try {
      req = json == null || json.isBlank() ? new FinishRequest() : NativeAuthJson.read(json, FinishRequest.class);
    } catch (IOException e) {
      throw new NativeAuthException(Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "Body must be JSON");
    }
    if (isBlank(req.registrationId) || isBlank(req.credentialId) || isBlank(req.clientDataJson) || isBlank(req.attestationObject)) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST,
          "registration_id, credential_id, client_data_json and attestation_object are required");
    }
    byte[] clientDataJson;
    byte[] attestationObject;
    try {
      clientDataJson = Base64Url.decode(req.clientDataJson);
      attestationObject = Base64Url.decode(req.attestationObject);
    } catch (RuntimeException e) {
      throw new NativeAuthException(Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "Registration fields must be base64url");
    }
    Map<String, String> notes = session.singleUseObjects().remove(SINGLE_USE_PREFIX + req.registrationId);
    if (notes == null || !auth.user().getId().equals(notes.get(NOTE_USER))) {
      throw new NativeAuthException(
          Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, "registration_id is unknown, expired or already used");
    }

    EventBuilder event =
        new EventBuilder(realm, session, session.getContext().getConnection())
            .event(EventType.UPDATE_CREDENTIAL)
            .client(auth.client() == null ? null : auth.client().getClientId())
            .user(auth.user())
            .session(auth.userSession())
            .detail(Details.CREDENTIAL_TYPE, WebAuthnCredentialModel.TYPE_PASSWORDLESS)
            .detail("native_protocol", Protocol.VERSION);
    try {
      PasskeyRegistrationVerifier.Registered registered =
          PasskeyRegistrationVerifier.verifyAndStore(
              session, realm, auth.user(), baseUri(), notes.get(NOTE_CHALLENGE),
              attestationObject, clientDataJson, transports(req.transports), req.label);
      if (registered.credential() != null) {
        event.detail(Details.CREDENTIAL_ID, registered.credential().getId());
      }
      event.success();
      Map<String, Object> body = new LinkedHashMap<>();
      body.put(Protocol.CREDENTIAL_ID, registered.credentialIdBase64Url());
      body.put(Protocol.LABEL, req.label);
      return Responses.json(Response.Status.CREATED, body);
    } catch (PasskeyRegistrationException e) {
      event.error(Errors.INVALID_REGISTRATION);
      throw new NativeAuthException(Response.Status.BAD_REQUEST, Protocol.ERR_INVALID_REQUEST, e.getMessage());
    }
  }

  // ---------------------------------------------------------------------------------------------

  private record Authenticated(UserModel user, UserSessionModel userSession, org.keycloak.models.ClientModel client) {}

  /** Bearer/DPoP access token → user + user session; enforces the spec/07 §5 freshness rule. */
  private Authenticated authenticate() {
    AuthenticationManager.AuthResult auth;
    try {
      auth = new AppAuthManager.BearerTokenAuthenticator(session).setRealm(realm).authenticate();
    } catch (RuntimeException e) {
      log.debugf(e, "Bearer token rejected on passkey registration endpoint");
      auth = null;
    }
    if (auth == null || auth.getUser() == null) {
      throw unauthorized("Bearer token missing, invalid or expired");
    }
    if (!auth.getUser().isEnabled()) {
      throw unauthorized("User is disabled");
    }
    UserSessionModel userSession = auth.getSession();
    if (userSession == null) {
      throw unauthorized("Token has no user session");
    }
    int maxAge = NativeAuthConfig.passkeyRegistrationMaxAge(realm);
    if (maxAge > 0) {
      int authTime = authTime(userSession);
      int age = Time.currentTime() - authTime;
      if (age > maxAge) {
        log.debugf("Passkey registration refused for user %s: authentication is %d s old (max %d)", auth.getUser().getUsername(), age, maxAge);
        // FiPA's answer for an insufficiently fresh authentication, with a post-login auth_session and
        // the limit so the client can step up with max_age and retry (spec/03 §5, §6; spec/13 D1).
        String jkt =
            auth.getToken().getConfirmation() == null ? null : auth.getToken().getConfirmation().getKeyThumbprint();
        String clientId = auth.getClient() == null ? auth.getToken().getIssuedFor() : auth.getClient().getClientId();
        throw NativeAuthException.withBody(
            Response.Status.FORBIDDEN,
            new io.phasetwo.keycloak.nativeauth.core.model.ErrorResponse(
                    Protocol.ERR_INSUFFICIENT_AUTHORIZATION,
                    "Authentication is older than " + maxAge + " s; re-authenticate (step up with max_age) before registering a passkey")
                .setAuthSession(PostLoginAuthSession.mint(session, realm, userSession.getId(), clientId, jkt))
                .setMaxAge((long) maxAge));
      }
    }
    return new Authenticated(auth.getUser(), userSession, auth.getClient());
  }

  /** When the user actually authenticated (not when the token was minted or refreshed). */
  private static int authTime(UserSessionModel userSession) {
    String note = userSession.getNote(AuthenticationManager.AUTH_TIME);
    if (note != null) {
      try {
        return Integer.parseInt(note);
      } catch (NumberFormatException ignored) {
        // fall through
      }
    }
    return userSession.getStarted();
  }

  private NativeAuthException unauthorized(String description) {
    return new NativeAuthException(Response.Status.UNAUTHORIZED, Protocol.ERR_INVALID_TOKEN, description) {
      @Override
      Response toResponse() {
        return Response.fromResponse(super.toResponse())
            .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"" + realm.getName() + "\", error=\"invalid_token\"")
            .build();
      }
    };
  }

  private URI baseUri() {
    return session.getContext().getUri().getBaseUri();
  }

  @SuppressWarnings("unchecked")
  private static Set<String> transports(Object value) {
    if (value == null) return Set.of();
    if (value instanceof List<?> list) {
      return list.stream().map(String::valueOf).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(LinkedHashSet::new));
    }
    return Arrays.stream(String.valueOf(value).split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }
}
