package io.phasetwo.keycloak.nativeauth.endpoint;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class NativeAuthResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public NativeAuthResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return new NativeAuthResource(session);
  }

  @Override
  public void close() {}
}
