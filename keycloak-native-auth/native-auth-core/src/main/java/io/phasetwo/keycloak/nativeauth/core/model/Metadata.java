package io.phasetwo.keycloak.nativeauth.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;

/** {@code GET /native-auth/metadata} body (spec/03 §1.1). */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
  "protocol_version",
  "fipa_draft",
  "authorization_challenge_endpoint",
  "token_endpoint",
  "authorization_endpoint",
  "code_exchange",
  "passkey",
  "push",
  "challenge_types_supported",
  "dpop_signing_alg_values_supported",
  "client_attestation"
})
public class Metadata {
  private String protocolVersion = Protocol.VERSION;
  private String fipaDraft = Protocol.FIPA_DRAFT;
  private String authorizationChallengeEndpoint;
  private String tokenEndpoint;
  /** The realm's OIDC authorization endpoint, needed for {@code redirect_to_web} (spec/03 §3.4). */
  private String authorizationEndpoint;
  private CodeExchange codeExchange;
  private Passkey passkey;
  private List<ChallengeType> challengeTypesSupported = new ArrayList<>();
  private List<String> dpopSigningAlgValuesSupported = new ArrayList<>();
  private ClientAttestation clientAttestation = new ClientAttestation();

  public String getProtocolVersion() {
    return protocolVersion;
  }

  public void setProtocolVersion(String protocolVersion) {
    this.protocolVersion = protocolVersion;
  }

  public String getFipaDraft() {
    return fipaDraft;
  }

  public void setFipaDraft(String fipaDraft) {
    this.fipaDraft = fipaDraft;
  }

  public String getAuthorizationChallengeEndpoint() {
    return authorizationChallengeEndpoint;
  }

  public void setAuthorizationChallengeEndpoint(String authorizationChallengeEndpoint) {
    this.authorizationChallengeEndpoint = authorizationChallengeEndpoint;
  }

  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  public void setTokenEndpoint(String tokenEndpoint) {
    this.tokenEndpoint = tokenEndpoint;
  }

  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }

  public void setAuthorizationEndpoint(String authorizationEndpoint) {
    this.authorizationEndpoint = authorizationEndpoint;
  }

  public CodeExchange getCodeExchange() {
    return codeExchange;
  }

  public void setCodeExchange(CodeExchange codeExchange) {
    this.codeExchange = codeExchange;
  }

  public Passkey getPasskey() {
    return passkey;
  }

  public void setPasskey(Passkey passkey) {
    this.passkey = passkey;
  }

  public List<ChallengeType> getChallengeTypesSupported() {
    return challengeTypesSupported;
  }

  public void setChallengeTypesSupported(List<ChallengeType> challengeTypesSupported) {
    this.challengeTypesSupported = challengeTypesSupported;
  }

  public List<String> getDpopSigningAlgValuesSupported() {
    return dpopSigningAlgValuesSupported;
  }

  public void setDpopSigningAlgValuesSupported(List<String> dpopSigningAlgValuesSupported) {
    this.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported;
  }

  public ClientAttestation getClientAttestation() {
    return clientAttestation;
  }

  public void setClientAttestation(ClientAttestation clientAttestation) {
    this.clientAttestation = clientAttestation;
  }

  /**
   * Answers spec/03 §3.1's "the metadata document will state whether redirect_uri must be sent"
   * (spec/08 Q1). {@code redirect_uri_required=false} means the token request MUST omit
   * {@code redirect_uri}; otherwise it MUST send exactly {@code redirect_uri}.
   */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class CodeExchange {
    private boolean redirectUriRequired;
    private String redirectUri;

    public CodeExchange() {}

    public CodeExchange(boolean redirectUriRequired, String redirectUri) {
      this.redirectUriRequired = redirectUriRequired;
      this.redirectUri = redirectUri;
    }

    public boolean isRedirectUriRequired() {
      return redirectUriRequired;
    }

    public void setRedirectUriRequired(boolean redirectUriRequired) {
      this.redirectUriRequired = redirectUriRequired;
    }

    public String getRedirectUri() {
      return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
      this.redirectUri = redirectUri;
    }
  }

  /** The {@code passkey} block (spec/03 §1.1): RP ID and the authenticated registration endpoints (§6). */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  @JsonPropertyOrder({"rp_id", "register_options_endpoint", "register_finish_endpoint"})
  public static class Passkey {
    private String rpId;
    private String registerOptionsEndpoint;
    private String registerFinishEndpoint;

    public Passkey() {}

    public Passkey(String rpId, String registerOptionsEndpoint, String registerFinishEndpoint) {
      this.rpId = rpId;
      this.registerOptionsEndpoint = registerOptionsEndpoint;
      this.registerFinishEndpoint = registerFinishEndpoint;
    }

    public String getRpId() {
      return rpId;
    }

    public void setRpId(String rpId) {
      this.rpId = rpId;
    }

    public String getRegisterOptionsEndpoint() {
      return registerOptionsEndpoint;
    }

    public void setRegisterOptionsEndpoint(String registerOptionsEndpoint) {
      this.registerOptionsEndpoint = registerOptionsEndpoint;
    }

    public String getRegisterFinishEndpoint() {
      return registerFinishEndpoint;
    }

    public void setRegisterFinishEndpoint(String registerFinishEndpoint) {
      this.registerFinishEndpoint = registerFinishEndpoint;
    }
  }

  /** Reserved for Phase 4 (spec/03 §9). */
  public static class ClientAttestation {
    private boolean required = false;
    private List<String> methods = new ArrayList<>();

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

    public List<String> getMethods() {
      return methods;
    }

    public void setMethods(List<String> methods) {
      this.methods = methods;
    }
  }
}
