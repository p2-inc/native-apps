package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
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
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;

/**
 * JAX-RS resource behind {@code /realms/{realm}/native-auth}. Phase 0 serves {@code GET /metadata} and
 * {@code POST /challenge} (spec/03 §1). Passkey registration and push enrolment endpoints are added in
 * later phases.
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
    m.setCodeExchange(NativeAuthConfig.codeExchangeMetadata(realm));
    m.setChallengeTypesSupported(installedChallengeTypes());
    // DPoP binding of auth_session/code is a Phase 4 item; advertise nothing until it is enforced.
    m.setDpopSigningAlgValuesSupported(List.of());
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

  private List<ChallengeType> installedChallengeTypes() {
    List<ChallengeType> types = new ArrayList<>();
    session
        .getKeycloakSessionFactory()
        .getProviderFactoriesStream(Authenticator.class)
        .filter(f -> f instanceof NativeAuthenticatorFactory)
        .map(f -> ((NativeAuthenticatorFactory) f).challengeType())
        .distinct()
        .sorted()
        .forEach(types::add);
    return types;
  }
}
