package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/** Error body for everything that is not a challenge (spec/03 §3.5). */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"error", "error_description", "auth_session", "max_age", "protocol_version"})
public class ErrorResponse {
  private String error;
  private String errorDescription;
  private String authSession;
  /** spec/03 §6: the freshness limit a step-up must satisfy ({@code insufficient_authorization}). */
  private Long maxAge;
  private String protocolVersion = Protocol.VERSION;

  public ErrorResponse() {}

  public ErrorResponse(String error, String errorDescription) {
    this.error = error;
    this.errorDescription = errorDescription;
  }

  public String getError() {
    return error;
  }

  public ErrorResponse setError(String error) {
    this.error = error;
    return this;
  }

  public String getErrorDescription() {
    return errorDescription;
  }

  public ErrorResponse setErrorDescription(String errorDescription) {
    this.errorDescription = errorDescription;
    return this;
  }

  public String getAuthSession() {
    return authSession;
  }

  public ErrorResponse setAuthSession(String authSession) {
    this.authSession = authSession;
    return this;
  }

  public Long getMaxAge() {
    return maxAge;
  }

  public ErrorResponse setMaxAge(Long maxAge) {
    this.maxAge = maxAge;
    return this;
  }

  public String getProtocolVersion() {
    return protocolVersion;
  }

  public ErrorResponse setProtocolVersion(String protocolVersion) {
    this.protocolVersion = protocolVersion;
    return this;
  }
}
