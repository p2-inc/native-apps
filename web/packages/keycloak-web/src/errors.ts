import { parseJson, str, num, asObject, int, type JsonValue } from './json';
import { header, type HttpResponse } from './transport';

/** The SDKs' error codes (spec/05 §2.3); server codes pass through, so the list is not closed. */
export const NativeAuthErrorCode = {
  // spec/03 §3.5 (challenge endpoint)
  invalidRequest: 'invalid_request',
  invalidSession: 'invalid_session',
  invalidDPoPProof: 'invalid_dpop_proof',
  invalidClient: 'invalid_client',
  accessDenied: 'access_denied',
  slowDown: 'slow_down',
  clientAttestationRequired: 'client_attestation_required',
  serverError: 'server_error',
  redirectToWeb: 'redirect_to_web',
  // spec/03 §6 and the token endpoint
  invalidToken: 'invalid_token',
  insufficientAuthorization: 'insufficient_authorization',
  invalidGrant: 'invalid_grant',
  // SDK-local
  networkError: 'network_error',
  invalidResponse: 'invalid_response',
  metadataUnavailable: 'metadata_unavailable',
  unsupportedChallenge: 'unsupported_challenge',
  flowState: 'flow_state',
  invalidParameter: 'invalid_parameter',
  passkeyCancelled: 'passkey_cancelled',
  passkeyFailed: 'passkey_failed',
  passkeyUnavailable: 'passkey_unavailable',
  rpIdMismatch: 'rp_id_mismatch',
  credentialsNotFound: 'credentials_not_found',
  reauthenticationRequired: 'reauthentication_required',
  /** The browser store (IndexedDB) failed: private mode, blocked site data, quota. */
  storageError: 'storage_error',
  dpopKeyError: 'dpop_key_error',
  webFallbackCancelled: 'web_fallback_cancelled',
  webFallbackFailed: 'web_fallback_failed',
  /** A resource server asked for a stronger authentication and no handler completed it (RFC 9470). */
  stepUpRequired: 'step_up_required',
} as const;

/** The single error type (spec/05 §2.3): branch on `code`, never on the message. */
export class NativeAuthError extends Error {
  readonly code: string;
  readonly statusCode?: number;
  readonly errorDescription?: string;
  /** A still-valid `auth_session` returned with the error (spec/03 §3.5), if any. */
  readonly authSession?: string;
  /** The JSON error body, when there was one. */
  readonly details?: JsonValue;
  readonly isNetworkError: boolean;
  /** `true` for transient conditions (network, `slow_down`, `server_error`). */
  readonly isRetryable: boolean;
  /** `Retry-After` in seconds for `slow_down`. */
  readonly retryAfter?: number;

  constructor(
    code: string,
    errorDescription?: string,
    extra: {
      statusCode?: number;
      authSession?: string;
      details?: JsonValue;
      isNetworkError?: boolean;
      isRetryable?: boolean;
      retryAfter?: number;
      cause?: unknown;
    } = {}
  ) {
    super(errorDescription ?? code, { cause: extra.cause });
    this.name = 'NativeAuthError';
    this.code = code;
    this.errorDescription = errorDescription;
    this.statusCode = extra.statusCode;
    this.authSession = extra.authSession;
    this.details = extra.details;
    this.isNetworkError = extra.isNetworkError ?? false;
    this.isRetryable = extra.isRetryable ?? false;
    this.retryAfter = extra.retryAfter;
  }

  /** `max_age` from a §6 `insufficient_authorization` body: the freshness a step-up must satisfy. */
  get maxAge(): number | undefined {
    return int(asObject(this.details)?.max_age);
  }

  /** Any thrown value as a `NativeAuthError`. */
  static from(error: unknown): NativeAuthError {
    if (error instanceof NativeAuthError) return error;
    const message = error instanceof Error ? error.message : String(error);
    return new NativeAuthError(NativeAuthErrorCode.invalidResponse, message, {
      cause: error,
    });
  }

  static network(error: unknown): NativeAuthError {
    return new NativeAuthError(
      NativeAuthErrorCode.networkError,
      error instanceof Error ? error.message : String(error),
      { isNetworkError: true, isRetryable: true, cause: error }
    );
  }

  /** Maps a JSON error body from any endpoint to an error, keeping the server's `error` code. */
  static fromResponse(
    response: HttpResponse,
    fallbackCode: string = NativeAuthErrorCode.invalidResponse
  ): NativeAuthError {
    const json = asObject(parseJson(response.body));
    const code = str(json?.error) ?? fallbackCode;
    const retryAfter = num(Number(header(response, 'retry-after')?.trim()));
    return new NativeAuthError(
      code,
      str(json?.error_description) ??
        (json === undefined
          ? `HTTP ${response.status} without a JSON body`
          : undefined),
      {
        statusCode: response.status,
        authSession: str(json?.auth_session),
        details: json,
        isRetryable:
          code === NativeAuthErrorCode.slowDown ||
          code === NativeAuthErrorCode.serverError ||
          response.status >= 500,
        retryAfter,
      }
    );
  }
}
