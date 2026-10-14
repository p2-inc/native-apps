package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;

/** The {@code 403 insufficient_authorization} body (spec/03 §3.2). */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
  "error",
  "error_description",
  "auth_session",
  "protocol_version",
  "expires_in",
  "challenges",
  "context"
})
public class ChallengeResponse {
  private String error = Protocol.ERR_INSUFFICIENT_AUTHORIZATION;
  private String errorDescription = "Authentication required";
  private String authSession;
  private String protocolVersion = Protocol.VERSION;
  private Long expiresIn;
  private List<ChallengeDescriptor> challenges = new ArrayList<>();
  private ChallengeContext context;

  public String getError() {
    return error;
  }

  public ChallengeResponse setError(String error) {
    this.error = error;
    return this;
  }

  public String getErrorDescription() {
    return errorDescription;
  }

  public ChallengeResponse setErrorDescription(String errorDescription) {
    this.errorDescription = errorDescription;
    return this;
  }

  public String getAuthSession() {
    return authSession;
  }

  public ChallengeResponse setAuthSession(String authSession) {
    this.authSession = authSession;
    return this;
  }

  public String getProtocolVersion() {
    return protocolVersion;
  }

  public ChallengeResponse setProtocolVersion(String protocolVersion) {
    this.protocolVersion = protocolVersion;
    return this;
  }

  public Long getExpiresIn() {
    return expiresIn;
  }

  public ChallengeResponse setExpiresIn(Long expiresIn) {
    this.expiresIn = expiresIn;
    return this;
  }

  public List<ChallengeDescriptor> getChallenges() {
    return challenges;
  }

  public ChallengeResponse setChallenges(List<ChallengeDescriptor> challenges) {
    this.challenges = challenges;
    return this;
  }

  public ChallengeContext getContext() {
    return context;
  }

  public ChallengeResponse setContext(ChallengeContext context) {
    this.context = context;
    return this;
  }
}
