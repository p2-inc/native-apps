package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Registers {@code /realms/{realm}/native-auth} (spec/08 Q3). */
public class NativeAuthResourceProviderFactory implements RealmResourceProviderFactory {

  @Override
  public String getId() {
    return Protocol.RESOURCE_ID;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new NativeAuthResourceProvider(session);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
