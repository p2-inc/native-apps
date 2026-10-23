package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.compat.KeycloakCompat;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.protocol.oidc.utils.OAuth2Code;

/**
 * {@code keycloak-services} members that differ between the supported Keycloak versions (see {@link
 * KeycloakCompat}), resolved once.
 *
 * <ul>
 *   <li>{@code OAuth2Code}: 9 arguments on 26.4, 10 ({@code + resource}) on 26.6, 11 ({@code +
 *       clientId}) on 26.8.
 *   <li>PAR single-use key: the bare key on 26.4, {@code "par:" + key} on 26.6, {@code
 *       buildCacheKey(realmId, key)} = {@code "par:<realm>:" + key} on 26.8.
 *   <li>{@code ParEndpoint.PAR_CLIENT_ID} (the issuing client, checked by the authorization
 *       endpoint) exists from 26.8; older versions must not receive it, it would become a request
 *       parameter.
 * </ul>
 */
final class ServicesCompat {

  private ServicesCompat() {}

  private static final Constructor<?> OAUTH2_CODE = oauth2CodeConstructor();
  private static final int OAUTH2_CODE_ARGS = OAUTH2_CODE.getParameterCount();
  private static final Optional<Method> PAR_BUILD_CACHE_KEY =
      KeycloakCompat.method(ParEndpoint.class, "buildCacheKey", String.class, String.class);
  private static final Optional<String> PAR_CACHE_KEY_PREFIX = KeycloakCompat.constant(ParEndpoint.class, "CACHE_KEY_PREFIX");
  private static final Optional<String> PAR_CLIENT_ID = KeycloakCompat.constant(ParEndpoint.class, "PAR_CLIENT_ID");

  private static Constructor<?> oauth2CodeConstructor() {
    for (int args : new int[] {11, 10, 9}) {
      Optional<Constructor<?>> c = KeycloakCompat.constructor(OAuth2Code.class, args);
      if (c.isPresent()) return c.get();
    }
    throw new IllegalStateException("No supported OAuth2Code constructor in this Keycloak version");
  }

  static OAuth2Code newOAuth2Code(
      String id,
      String clientId,
      int expiration,
      String nonce,
      String scope,
      String resource,
      String redirectUriParam,
      String codeChallenge,
      String codeChallengeMethod,
      String dpopJkt,
      String userSessionId) {
    Object code =
        switch (OAUTH2_CODE_ARGS) {
          case 11 -> KeycloakCompat.create(OAUTH2_CODE, id, clientId, expiration, nonce, scope, resource, redirectUriParam, codeChallenge, codeChallengeMethod, dpopJkt, userSessionId);
          case 10 -> KeycloakCompat.create(OAUTH2_CODE, id, expiration, nonce, scope, resource, redirectUriParam, codeChallenge, codeChallengeMethod, dpopJkt, userSessionId);
          default -> KeycloakCompat.create(OAUTH2_CODE, id, expiration, nonce, scope, redirectUriParam, codeChallenge, codeChallengeMethod, dpopJkt, userSessionId);
        };
    return (OAuth2Code) code;
  }

  /** The single-use-store key under which the authorization endpoint looks up {@code key}. */
  static String parCacheKey(String realmId, String key) {
    if (PAR_BUILD_CACHE_KEY.isPresent()) {
      return (String) KeycloakCompat.invoke(PAR_BUILD_CACHE_KEY.get(), null, realmId, key);
    }
    return PAR_CACHE_KEY_PREFIX.map(prefix -> prefix + key).orElse(key);
  }

  /** Adds the issuing client where the Keycloak version checks it. */
  static void putParClientId(Map<String, String> params, String clientId) {
    PAR_CLIENT_ID.ifPresent(name -> params.put(name, clientId));
  }
}
