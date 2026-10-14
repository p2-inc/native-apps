package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The {@code 200 OK} success body (spec/03 §3.1). */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationCodeResponse {
  private String authorizationCode;
  private String authSession;

  public AuthorizationCodeResponse() {}

  public AuthorizationCodeResponse(String authorizationCode, String authSession) {
    this.authorizationCode = authorizationCode;
    this.authSession = authSession;
  }

  public String getAuthorizationCode() {
    return authorizationCode;
  }

  public void setAuthorizationCode(String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  public String getAuthSession() {
    return authSession;
  }

  public void setAuthSession(String authSession) {
    this.authSession = authSession;
  }
}
