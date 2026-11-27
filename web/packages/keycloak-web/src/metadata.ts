import { NativeAuthError, NativeAuthErrorCode } from './errors';
import { asObject, bool, str, strings, type JsonObject } from './json';
import { responseJson, type Transport } from './transport';

/** `GET /realms/{realm}/native-auth/metadata` (spec/03 §1.1). Unknown fields are ignored. */
export interface NativeAuthMetadata {
  protocolVersion: string;
  fipaDraft?: string;
  authorizationChallengeEndpoint: string;
  tokenEndpoint: string;
  /** The realm's OIDC authorization endpoint, used by the browser fallback. */
  authorizationEndpoint?: string;
  codeExchange: { redirectUriRequired: boolean; redirectUri?: string };
  passkey?: {
    rpId: string;
    registerOptionsEndpoint?: string;
    registerFinishEndpoint?: string;
  };
  challengeTypesSupported: string[];
  /** `native_flow` values the realm allows (spec/22 phase 3); `['login']` from older servers. */
  flowsSupported: string[];
  dpopSigningAlgValuesSupported: string[];
  push?: { enabled: boolean; enrollStartEndpoint?: string; deviceApiBase?: string };
  raw: JsonObject;
}

export function parseMetadata(json: unknown): NativeAuthMetadata {
  const o = asObject(json);
  const protocolVersion = str(o?.protocol_version);
  const challenge = str(o?.authorization_challenge_endpoint);
  const token = str(o?.token_endpoint);
  if (o === undefined || protocolVersion === undefined || challenge === undefined || token === undefined) {
    throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, 'Metadata document is malformed', {
      statusCode: 200,
      details: o,
    });
  }
  const code = asObject(o.code_exchange);
  const passkey = asObject(o.passkey);
  const push = asObject(o.push);
  const rpId = str(passkey?.rp_id);
  return {
    protocolVersion,
    fipaDraft: str(o.fipa_draft),
    authorizationChallengeEndpoint: challenge,
    tokenEndpoint: token,
    authorizationEndpoint: str(o.authorization_endpoint),
    codeExchange: {
      redirectUriRequired: bool(code?.redirect_uri_required) ?? false,
      redirectUri: str(code?.redirect_uri),
    },
    passkey:
      rpId === undefined
        ? undefined
        : {
            rpId,
            registerOptionsEndpoint: str(passkey?.register_options_endpoint),
            registerFinishEndpoint: str(passkey?.register_finish_endpoint),
          },
    challengeTypesSupported: strings(o.challenge_types_supported),
    flowsSupported: strings(o.flows_supported).length > 0 ? strings(o.flows_supported) : ['login'],
    dpopSigningAlgValuesSupported: strings(o.dpop_signing_alg_values_supported),
    push:
      push === undefined
        ? undefined
        : {
            enabled: bool(push.enabled) ?? true,
            enrollStartEndpoint: str(push.enroll_start_endpoint),
            deviceApiBase: str(push.device_api_base),
          },
    raw: o,
  };
}

/** Fetches and caches the metadata document; concurrent callers share one fetch. */
export class MetadataClient {
  private cached: { value: NativeAuthMetadata; at: number } | undefined;
  private inFlight: Promise<NativeAuthMetadata> | undefined;

  constructor(
    readonly issuer: string,
    private readonly transport: Transport,
    private readonly ttlMs = 5 * 60_000
  ) {}

  async metadata(forceRefresh = false): Promise<NativeAuthMetadata> {
    const cached = this.cached;
    if (!forceRefresh && cached !== undefined && Date.now() - cached.at < this.ttlMs) {
      return cached.value;
    }
    if (this.inFlight === undefined) {
      this.inFlight = this.fetch().finally(() => {
        this.inFlight = undefined;
      });
    }
    return this.inFlight;
  }

  private async fetch(): Promise<NativeAuthMetadata> {
    const url = `${this.issuer}/native-auth/metadata`;
    const response = await this.transport.send({
      method: 'GET',
      url,
      headers: { Accept: 'application/json' },
    });
    if (response.status !== 200) {
      throw new NativeAuthError(
        NativeAuthErrorCode.metadataUnavailable,
        `GET ${url} answered HTTP ${response.status}`,
        { statusCode: response.status, details: responseJson(response) }
      );
    }
    const value = parseMetadata(responseJson(response));
    this.cached = { value, at: Date.now() };
    return value;
  }
}
