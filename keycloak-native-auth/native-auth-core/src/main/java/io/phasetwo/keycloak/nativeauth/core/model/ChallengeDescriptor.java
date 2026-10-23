package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.LinkedHashMap;
import java.util.Map;

/** A challenge descriptor (spec/03 §3.3). Serialised with snake_case field names. */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"type", "id", "label", "required", "skippable", "retry", "error", "params"})
public class ChallengeDescriptor {

  private ChallengeType type;
  private String id;
  private String label;
  private Boolean required;
  /** {@code true} on a required-action descriptor the user may decline with {@code action=skip} (spec/03 §4.11). */
  private Boolean skippable;
  private Retry retry;
  private ChallengeError error;
  private Map<String, Object> params = new LinkedHashMap<>();

  public ChallengeDescriptor() {}

  public ChallengeDescriptor(ChallengeType type) {
    this.type = type;
  }

  public ChallengeType getType() {
    return type;
  }

  public ChallengeDescriptor setType(ChallengeType type) {
    this.type = type;
    return this;
  }

  public String getId() {
    return id;
  }

  public ChallengeDescriptor setId(String id) {
    this.id = id;
    return this;
  }

  public String getLabel() {
    return label;
  }

  public ChallengeDescriptor setLabel(String label) {
    this.label = label;
    return this;
  }

  public Boolean getRequired() {
    return required;
  }

  public ChallengeDescriptor setRequired(Boolean required) {
    this.required = required;
    return this;
  }

  public Boolean getSkippable() {
    return skippable;
  }

  public ChallengeDescriptor setSkippable(Boolean skippable) {
    this.skippable = skippable;
    return this;
  }

  public Retry getRetry() {
    return retry;
  }

  public ChallengeDescriptor setRetry(Retry retry) {
    this.retry = retry;
    return this;
  }

  public ChallengeError getError() {
    return error;
  }

  public ChallengeDescriptor setError(ChallengeError error) {
    this.error = error;
    return this;
  }

  public ChallengeDescriptor setError(String code, String message) {
    this.error = new ChallengeError(code, message);
    return this;
  }

  public Map<String, Object> getParams() {
    return params;
  }

  public ChallengeDescriptor setParams(Map<String, Object> params) {
    this.params = params;
    return this;
  }

  public ChallengeDescriptor param(String name, Object value) {
    if (value != null) params.put(name, value);
    return this;
  }

  /** {@code retry} object of a descriptor. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class Retry {
    private Integer remaining;

    public Retry() {}

    public Retry(Integer remaining) {
      this.remaining = remaining;
    }

    public Integer getRemaining() {
      return remaining;
    }

    public void setRemaining(Integer remaining) {
      this.remaining = remaining;
    }
  }

  /** {@code error} object of a descriptor: the previous attempt at this challenge failed. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class ChallengeError {
    private String code;
    private String message;

    public ChallengeError() {}

    public ChallengeError(String code, String message) {
      this.code = code;
      this.message = message;
    }

    public String getCode() {
      return code;
    }

    public void setCode(String code) {
      this.code = code;
    }

    public String getMessage() {
      return message;
    }

    public void setMessage(String message) {
      this.message = message;
    }
  }
}
