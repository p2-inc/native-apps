package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import io.phasetwo.keycloak.nativeauth.requiredactions.PasskeyRegistrationOptions;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;

/**
 * JAX-RS resource behind {@code /realms/{realm}/native-auth}: {@code GET /metadata}, {@code POST
 * /challenge} and the bearer-authenticated {@code POST /passkey/register/options|finish} (spec/03 §1,
 * §6). Push enrolment is added in Phase 3.
 */
public class NativeAuthResource {

  private final KeycloakSession session;

  public NativeAuthResource(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path("metadata")
  @Produces(MediaType.APPLICATION_JSON)
  public Response metadata() {
    RealmModel realm = session.getContext().getRealm();
    URI baseUri = session.getContext().getUri().getBaseUri();

    Metadata m = new Metadata();
    m.setAuthorizationChallengeEndpoint(
        UriBuilder.fromUri(baseUri)
            .path("realms/{realm}/" + Protocol.RESOURCE_ID + "/challenge")
            .build(realm.getName())
            .toString());
    m.setTokenEndpoint(
        OIDCLoginProtocolService.tokenUrl(UriBuilder.fromUri(baseUri)).build(realm.getName()).toString());
    m.setAuthorizationEndpoint(
        OIDCLoginProtocolService.authUrl(UriBuilder.fromUri(baseUri)).build(realm.getName()).toString());
    m.setCodeExchange(NativeAuthConfig.codeExchangeMetadata(realm));
    m.setPasskey(
        new Metadata.Passkey(
            PasskeyRegistrationOptions.rpId(PasskeyRegistrationOptions.policy(realm), baseUri),
            realmPath(baseUri, realm, "passkey/register/options"),
            realmPath(baseUri, realm, "passkey/register/finish")));
    m.setChallengeTypesSupported(installedChallengeTypes());
    // The challenge endpoint verifies proofs and binds auth_session/code to the key (spec/03 §8, 13 D3).
    m.setDpopSigningAlgValuesSupported(DPoPProofChecker.supportedAlgorithms(session));
    return Responses.json(Response.Status.OK, m);
  }

  @POST
  @Path("challenge")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response challenge() {
    // Read the form through Keycloak's HttpRequest so the authenticators see the same parameters.
    MultivaluedMap<String, String> form = session.getContext().getHttpRequest().getDecodedFormParameters();
    if (form == null) form = new MultivaluedHashMap<>();
    return new ChallengeFlowDriver(session).handle(form);
  }

  /** Passkey registration for an already authenticated user (spec/03 §6 step 1). */
  @POST
  @Path("passkey/register/options")
  @Produces(MediaType.APPLICATION_JSON)
  public Response passkeyRegisterOptions() {
    return guarded(() -> new PasskeyRegistrationDriver(session).options());
  }

  /** Passkey registration for an already authenticated user (spec/03 §6 step 3). */
  @POST
  @Path("passkey/register/finish")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response passkeyRegisterFinish(String body) {
    return guarded(() -> new PasskeyRegistrationDriver(session).finish(body));
  }

  private static Response guarded(java.util.function.Supplier<Response> action) {
    try {
      return action.get();
    } catch (NativeAuthException e) {
      return e.toResponse();
    } catch (RuntimeException e) {
      org.jboss.logging.Logger.getLogger(NativeAuthResource.class).error("Unexpected error in native-auth endpoint", e);
      return Responses.error(Response.Status.INTERNAL_SERVER_ERROR, Protocol.ERR_SERVER_ERROR, "Unexpected server error");
    }
  }

  private static String realmPath(URI baseUri, RealmModel realm, String suffix) {
    return UriBuilder.fromUri(baseUri)
        .path("realms/{realm}/" + Protocol.RESOURCE_ID + "/" + suffix)
        .build(realm.getName())
        .toString();
  }

  /** Challenge types of the installed native authenticators and native required actions, sorted. */
  private List<ChallengeType> installedChallengeTypes() {
    List<ChallengeType> types = new ArrayList<>();
    Stream.concat(
            session.getKeycloakSessionFactory().getProviderFactoriesStream(Authenticator.class)
                .filter(f -> f instanceof NativeAuthenticatorFactory)
                .map(f -> ((NativeAuthenticatorFactory) f).challengeType()),
            session.getKeycloakSessionFactory().getProviderFactoriesStream(RequiredActionProvider.class)
                .filter(f -> f instanceof NativeRequiredActionFactory)
                .map(f -> ((NativeRequiredActionFactory) f).challengeType()))
        .distinct()
        .sorted()
        .forEach(types::add);
    return types;
  }
}
