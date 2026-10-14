package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Informational {@code context} of a challenge response (spec/03 §3.2). Never carries secrets. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChallengeContext {
  private String username;
  private String displayName;
  private String clientName;
  private String acrRequested;
  private Boolean stepUp;

  public String getUsername() {
    return username;
  }

  public ChallengeContext setUsername(String username) {
    this.username = username;
    return this;
  }

  public String getDisplayName() {
    return displayName;
  }

  public ChallengeContext setDisplayName(String displayName) {
    this.displayName = displayName;
    return this;
  }

  public String getClientName() {
    return clientName;
  }

  public ChallengeContext setClientName(String clientName) {
    this.clientName = clientName;
    return this;
  }

  public String getAcrRequested() {
    return acrRequested;
  }

  public ChallengeContext setAcrRequested(String acrRequested) {
    this.acrRequested = acrRequested;
    return this;
  }

  public Boolean getStepUp() {
    return stepUp;
  }

  public ChallengeContext setStepUp(Boolean stepUp) {
    this.stepUp = stepUp;
    return this;
  }
}
