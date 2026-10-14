package io.phasetwo.keycloak.nativeauth.core.session;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Plaintext of the {@code auth_session} JWE (spec/02 D5, spec/03 §5): {@code {root_session_id, tab_id,
 * client_id, iat, jkt?}}. The value is opaque to clients; only the server decrypts it.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthSessionClaims {

  public static final String TYPE = "native-auth-session";

  private String typ = TYPE;
  private int ver = 1;
  private String rootSessionId;
  private String tabId;
  private String clientId;
  private long iat;
  /** DPoP key thumbprint (spec/03 §8). Null until DPoP binding is implemented (Phase 4). */
  private String jkt;

  public String getTyp() {
    return typ;
  }

  public void setTyp(String typ) {
    this.typ = typ;
  }

  public int getVer() {
    return ver;
  }

  public void setVer(int ver) {
    this.ver = ver;
  }

  public String getRootSessionId() {
    return rootSessionId;
  }

  public AuthSessionClaims setRootSessionId(String rootSessionId) {
    this.rootSessionId = rootSessionId;
    return this;
  }

  public String getTabId() {
    return tabId;
  }

  public AuthSessionClaims setTabId(String tabId) {
    this.tabId = tabId;
    return this;
  }

  public String getClientId() {
    return clientId;
  }

  public AuthSessionClaims setClientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public long getIat() {
    return iat;
  }

  public AuthSessionClaims setIat(long iat) {
    this.iat = iat;
    return this;
  }

  public String getJkt() {
    return jkt;
  }

  public AuthSessionClaims setJkt(String jkt) {
    this.jkt = jkt;
    return this;
  }
}
