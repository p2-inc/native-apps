package io.phasetwo.keycloak.nativeauth.push;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.push.NativePushEnrolmentProvider;
import io.phasetwo.keycloak.nativeauth.core.push.NativePushEnrolmentProviderFactory;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** The {@code native-auth-push-enrolment} provider: metadata block and in-app enrolment start (spec/03 §7 b). */
public class NativePushEnrolmentProviderImpl implements NativePushEnrolmentProvider {

  private final KeycloakSession session;

  public NativePushEnrolmentProviderImpl(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Metadata.Push metadata(RealmModel realm, URI baseUri) {
    Metadata.Push push = new Metadata.Push();
    push.setEnabled(true);
    push.setEnrollStartEndpoint(
        UriBuilder.fromUri(baseUri).path("realms/{realm}/" + Protocol.RESOURCE_ID + "/push/enroll/start").build(realm.getName()).toString());
    push.setDeviceApiBase(PushEnrolment.deviceApiBase(realm, baseUri));
    push.setDeviceToken("native");
    List<String> providers =
        session.getKeycloakSessionFactory().getProviderFactoriesStream(PushNotificationSender.class).map(f -> f.getId()).sorted().toList();
    push.setPushProviderTypes(providers);
    return push;
  }

  @Override
  public Map<String, Object> start(RealmModel realm, UserModel user, ClientModel client, URI baseUri) {
    PushEnrolment.Started started = PushEnrolment.start(session, realm, user, baseUri);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("enrollment_token", started.enrollmentToken());
    body.put("expires_in", started.expiresIn());
    body.put("device_api_base", PushEnrolment.deviceApiBase(realm, baseUri));
    body.put("user_id", user.getId());
    return body;
  }

  public static class Factory implements NativePushEnrolmentProviderFactory {
    public static final String ID = "default";

    @Override
    public NativePushEnrolmentProvider create(KeycloakSession session) {
      return new NativePushEnrolmentProviderImpl(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
      return ID;
    }
  }
}
