package io.phasetwo.keycloak.nativeauth.endpoint;

import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import io.phasetwo.keycloak.nativeauth.core.model.Protocol;
import java.util.Locale;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

/** Realm / client attributes that configure the endpoint (spec/04 §2.1, §2.2, §7). */
public final class NativeAuthConfig {

  private NativeAuthConfig() {}

  /**
   * How the authorization code's stored {@code redirect_uri} is handled (spec/08 Q1).
   *
   * <ul>
   *   <li>{@link #NONE} (default): store {@code null}; the token request MUST omit {@code
   *       redirect_uri}. Verified against Keycloak 26.8 (spec/09).
   *   <li>{@link #SENTINEL}: store {@link Protocol#SENTINEL_REDIRECT_URI}; the client MUST send it.
   *   <li>{@link #CLIENT_FIXED}: store the client's configured native redirect URI; the client MUST
   *       send it.
   * </ul>
   */
  public enum CodeRedirectUriMode {
    NONE,
    SENTINEL,
    CLIENT_FIXED;

    public static CodeRedirectUriMode parse(String value) {
      if (value == null || value.isBlank()) return NONE;
      return switch (value.trim().toLowerCase(Locale.ROOT).replace('_', '-')) {
        case "none" -> NONE;
        case "sentinel" -> SENTINEL;
        case "client-fixed" -> CLIENT_FIXED;
        default -> throw new IllegalArgumentException(
            "Unknown " + Protocol.ATTR_CODE_REDIRECT_URI_MODE + ": " + value);
      };
    }
  }

  public static boolean isNativeEnabled(ClientModel client) {
    return client != null && Boolean.parseBoolean(client.getAttribute(Protocol.CLIENT_ATTR_ENABLED));
  }

  /** Flow alias: client attribute override, then realm attribute, then {@code native}. */
  public static String flowAlias(RealmModel realm, ClientModel client) {
    String alias = client == null ? null : client.getAttribute(Protocol.ATTR_FLOW_ALIAS);
    if (alias == null || alias.isBlank()) alias = realm.getAttribute(Protocol.ATTR_FLOW_ALIAS);
    if (alias == null || alias.isBlank()) alias = Protocol.DEFAULT_FLOW_ALIAS;
    return alias;
  }

  public static AuthenticationFlowModel flow(RealmModel realm, ClientModel client) {
    return realm.getFlowByAlias(flowAlias(realm, client));
  }

  public static CodeRedirectUriMode codeRedirectUriMode(RealmModel realm) {
    return CodeRedirectUriMode.parse(realm.getAttribute(Protocol.ATTR_CODE_REDIRECT_URI_MODE));
  }

  /** The {@code redirect_uri} value to store with the code, or {@code null} for mode NONE. */
  public static String codeRedirectUri(RealmModel realm, ClientModel client) {
    return switch (codeRedirectUriMode(realm)) {
      case NONE -> null;
      case SENTINEL -> Protocol.SENTINEL_REDIRECT_URI;
      case CLIENT_FIXED -> fixedRedirectUri(realm, client);
    };
  }

  private static String fixedRedirectUri(RealmModel realm, ClientModel client) {
    String uri = client == null ? null : client.getAttribute(Protocol.ATTR_CODE_REDIRECT_URI);
    if (uri == null || uri.isBlank()) uri = realm.getAttribute(Protocol.ATTR_CODE_REDIRECT_URI);
    if ((uri == null || uri.isBlank()) && client != null && !client.getRedirectUris().isEmpty()) {
      uri = client.getRedirectUris().iterator().next();
    }
    if (uri == null || uri.isBlank()) {
      throw new IllegalStateException(
          Protocol.ATTR_CODE_REDIRECT_URI_MODE
              + "=client-fixed requires "
              + Protocol.ATTR_CODE_REDIRECT_URI
              + " on the client or realm, or a registered redirect URI");
    }
    return uri;
  }

  /** Realm-level description for metadata (client-specific values cannot be shown there). */
  public static Metadata.CodeExchange codeExchangeMetadata(RealmModel realm) {
    return switch (codeRedirectUriMode(realm)) {
      case NONE -> new Metadata.CodeExchange(false, null);
      case SENTINEL -> new Metadata.CodeExchange(true, Protocol.SENTINEL_REDIRECT_URI);
      case CLIENT_FIXED -> new Metadata.CodeExchange(true, realm.getAttribute(Protocol.ATTR_CODE_REDIRECT_URI));
    };
  }
}
