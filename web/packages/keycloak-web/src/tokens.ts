import { DPoPSigner } from './dpop';
import { decodeJwtPayload } from './encoding';
import { NativeAuthError, NativeAuthErrorCode } from './errors';
import { asObject, num, str } from './json';
import type { MetadataClient } from './metadata';
import {
  FORM_CONTENT_TYPE,
  encodeForm,
  responseJson,
  type HttpResponse,
  type Transport,
} from './transport';

/** Tokens from the realm's token endpoint plus the post-login `auth_session` (spec/05 §6). */
export interface Credentials {
  accessToken: string;
  /** `Bearer`, or `DPoP` when the server bound the token to the SDK's key. */
  tokenType: string;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
  /** Epoch milliseconds. */
  expiresAt: number;
  /** Epoch milliseconds; `Infinity` for an offline token (`refresh_expires_in: 0`). */
  refreshExpiresAt?: number;
  issuedAt: number;
  /** Post-login value (spec/03 §3.1), kept for step-up (spec/03 §5). */
  authSession?: string;
}

/** Scheme for the `Authorization` header of resource requests. */
export function authorizationScheme(credentials: Credentials): 'DPoP' | 'Bearer' {
  return credentials.tokenType.toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer';
}

export function isDPoPBound(credentials: Credentials): boolean {
  return authorizationScheme(credentials) === 'DPoP';
}

export function isExpired(
  credentials: Credentials,
  leewayMs = 0,
  now = Date.now()
): boolean {
  return now + leewayMs >= credentials.expiresAt;
}

/** Unverified claims of the ID token, for display only. */
export function idTokenClaims(credentials: Credentials): Record<string, unknown> | undefined {
  return decodeJwtPayload(credentials.idToken);
}

/** Unverified claims of the access token, for display only. */
export function accessTokenClaims(credentials: Credentials): Record<string, unknown> | undefined {
  return decodeJwtPayload(credentials.accessToken);
}

/**
 * The standard Keycloak token endpoints: exchange, refresh, revoke, logout. DPoP proofs are attached
 * when the SDK has a key; whether the server binds is read from `token_type`.
 */
export class Tokens {
  constructor(
    private readonly clientId: string,
    private readonly issuer: string,
    private readonly metadata: MetadataClient,
    private readonly transport: Transport,
    private readonly dpop: DPoPSigner | undefined
  ) {}

  /**
   * `grant_type=authorization_code` without `redirect_uri` unless metadata says otherwise (spec/03
   * §3.1). A code issued by the browser fallback sends the `redirect_uri` it was issued for.
   */
  async exchange(
    code: string,
    codeVerifier: string,
    options: { authSession?: string; redirectUri?: string } = {}
  ): Promise<Credentials> {
    const document = await this.metadata.metadata();
    const fields: [string, string][] = [
      ['grant_type', 'authorization_code'],
      ['client_id', this.clientId],
      ['code', code],
      ['code_verifier', codeVerifier],
    ];
    if (options.redirectUri !== undefined) {
      fields.push(['redirect_uri', options.redirectUri]);
    } else if (document.codeExchange.redirectUriRequired) {
      const required = document.codeExchange.redirectUri;
      if (required === undefined) {
        throw new NativeAuthError(
          NativeAuthErrorCode.invalidResponse,
          'Metadata requires redirect_uri but names none'
        );
      }
      fields.push(['redirect_uri', required]);
    }
    return parseTokenResponse(
      await this.post(document.tokenEndpoint, fields),
      options.authSession
    );
  }

  /** `grant_type=refresh_token`; keeps the stored `auth_session`. */
  async refresh(credentials: Credentials): Promise<Credentials> {
    if (credentials.refreshToken === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.invalidGrant, 'No refresh token');
    }
    const document = await this.metadata.metadata();
    const response = await this.post(document.tokenEndpoint, [
      ['grant_type', 'refresh_token'],
      ['client_id', this.clientId],
      ['refresh_token', credentials.refreshToken],
    ]);
    const refreshed = parseTokenResponse(response, credentials.authSession);
    // Keycloak may omit an unchanged ID token on refresh.
    return refreshed.idToken === undefined && credentials.idToken !== undefined
      ? { ...refreshed, idToken: credentials.idToken }
      : refreshed;
  }

  /** RFC 7009 revocation. */
  async revoke(token: string, tokenTypeHint = 'refresh_token'): Promise<void> {
    const response = await this.post(
      this.oidcEndpoint('revoke'),
      [
        ['client_id', this.clientId],
        ['token', token],
        ['token_type_hint', tokenTypeHint],
      ]
    );
    if (response.status < 200 || response.status > 299)
      throw NativeAuthError.fromResponse(response);
  }

  /**
   * Ends the user session with the refresh token (`/protocol/openid-connect/logout`). A DPoP-bound
   * refresh token needs a proof here too (`invalid_grant: DPoP proof is missing` otherwise), so it is
   * always sent when the SDK has a key.
   */
  async logout(refreshToken: string): Promise<void> {
    const response = await this.post(
      this.oidcEndpoint('logout'),
      [
        ['client_id', this.clientId],
        ['refresh_token', refreshToken],
      ]
    );
    if (response.status < 200 || response.status > 299)
      throw NativeAuthError.fromResponse(response);
  }

  oidcEndpoint(name: string): string {
    return `${this.issuer}/protocol/openid-connect/${name}`;
  }

  private async post(
    url: string,
    fields: [string, string][],
    withProof = true
  ): Promise<HttpResponse> {
    let response = await this.transport.send(await this.request(url, fields, withProof));
    const nonce =
      withProof && this.dpop !== undefined ? DPoPSigner.nonceChallenge(response) : undefined;
    if (nonce !== undefined) {
      this.dpop!.setNonce(nonce, url);
      response = await this.transport.send(await this.request(url, fields, true));
    }
    return response;
  }

  private async request(url: string, fields: [string, string][], withProof: boolean) {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': FORM_CONTENT_TYPE,
    };
    if (withProof && this.dpop !== undefined) headers.DPoP = await this.dpop.proof('POST', url);
    return { method: 'POST', url, headers, body: encodeForm(fields) };
  }
}

export function parseTokenResponse(
  response: HttpResponse,
  authSession: string | undefined,
  now = Date.now()
): Credentials {
  const json = asObject(responseJson(response));
  if (response.status !== 200 || json === undefined) {
    throw NativeAuthError.fromResponse(response, NativeAuthErrorCode.invalidGrant);
  }
  const accessToken = str(json.access_token);
  if (accessToken === undefined) {
    throw new NativeAuthError(
      NativeAuthErrorCode.invalidResponse,
      'Token response without access_token',
      { statusCode: 200, details: json }
    );
  }
  const expiresIn = num(json.expires_in) ?? 300;
  const refreshExpiresIn = num(json.refresh_expires_in);
  return {
    accessToken,
    tokenType: str(json.token_type) ?? 'Bearer',
    refreshToken: str(json.refresh_token),
    idToken: str(json.id_token),
    scope: str(json.scope),
    expiresAt: now + expiresIn * 1000,
    refreshExpiresAt:
      refreshExpiresIn === undefined
        ? undefined
        : refreshExpiresIn > 0
          ? now + refreshExpiresIn * 1000
          : Infinity,
    issuedAt: now,
    authSession,
  };
}
