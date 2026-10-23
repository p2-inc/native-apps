package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeAuthenticatorFactory;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredActionFactory;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Registers {@code /realms/{realm}/native-auth} (spec/08 Q3). */
public class NativeAuthResourceProviderFactory implements RealmResourceProviderFactory {

  private static final Logger log = Logger.getLogger(NativeAuthResourceProviderFactory.class);
  static final int MAX_PROVIDER_ID_LENGTH = 36;

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

  /**
   * Keycloak stores authenticator and required-action provider ids in {@code varchar(36)} columns,
   * so a longer id of an extension native provider only fails later, with a 500 when an operator
   * adds it to a flow. Warn at startup instead.
   */
  @Override
  public void postInit(KeycloakSessionFactory factory) {
    Stream.concat(
            factory.getProviderFactoriesStream(Authenticator.class).filter(f -> f instanceof NativeAuthenticatorFactory),
            factory.getProviderFactoriesStream(RequiredActionProvider.class).filter(f -> f instanceof NativeRequiredActionFactory))
        .map(ProviderFactory::getId)
        .filter(id -> id.length() > MAX_PROVIDER_ID_LENGTH)
        .forEach(id -> log.warnf("Native provider id '%s' is %d characters; Keycloak stores provider ids in varchar(%d), so adding it to a flow will fail", id, id.length(), MAX_PROVIDER_ID_LENGTH));
  }

  @Override
  public void close() {}
}
