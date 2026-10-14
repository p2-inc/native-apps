package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/** The {@code redirect_to_web} answer (spec/03 §3.4): a PAR {@code request_uri} for the browser. */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"error", "error_description", "request_uri", "expires_in", "redirect_uri", "state", "reason", "protocol_version"})
public class RedirectToWebResponse extends ErrorResponse {
  private String requestUri;
  private Long expiresIn;
  private String redirectUri;
  private String state;
  private String reason;

  public RedirectToWebResponse() {
    setError(Protocol.ERR_REDIRECT_TO_WEB);
  }

  public String getRequestUri() {
    return requestUri;
  }

  public RedirectToWebResponse setRequestUri(String requestUri) {
    this.requestUri = requestUri;
    return this;
  }

  public Long getExpiresIn() {
    return expiresIn;
  }

  public RedirectToWebResponse setExpiresIn(Long expiresIn) {
    this.expiresIn = expiresIn;
    return this;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public RedirectToWebResponse setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
    return this;
  }

  public String getState() {
    return state;
  }

  public RedirectToWebResponse setState(String state) {
    this.state = state;
    return this;
  }

  public String getReason() {
    return reason;
  }

  public RedirectToWebResponse setReason(String reason) {
    this.reason = reason;
    return this;
  }
}
