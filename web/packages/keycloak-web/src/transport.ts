import { NativeAuthError } from './errors';
import { parseJson, type JsonValue } from './json';

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  /** Header names in lower case. */
  headers: Record<string, string>;
  body: string;
}

/** Sends one request. The SDK's only way to the network, so tests replay recorded transcripts. */
export interface Transport {
  send(request: HttpRequest): Promise<HttpResponse>;
}

export function header(
  response: HttpResponse,
  name: string
): string | undefined {
  return response.headers[name.toLowerCase()];
}

export function responseJson(response: HttpResponse): JsonValue | undefined {
  return parseJson(response.body);
}

/** `application/x-www-form-urlencoded` in field order (the transcripts compare field by field). */
export const FORM_CONTENT_TYPE =
  'application/x-www-form-urlencoded; charset=UTF-8';

export function encodeForm(fields: [string, string][]): string {
  return fields
    .map(
      ([name, value]) =>
        `${encodeURIComponent(name)}=${encodeURIComponent(value)}`
    )
    .join('&');
}

export function decodeForm(body: string): [string, string][] {
  if (body.length === 0) return [];
  return body.split('&').map((pair) => {
    const i = pair.indexOf('=');
    const decode = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));
    return i < 0
      ? [decode(pair), '']
      : [decode(pair.slice(0, i)), decode(pair.slice(i + 1))];
  });
}

/**
 * `fetch` without cookies (`credentials: "omit"`) or HTTP caching, with a timeout. The native
 * endpoint uses no cookies (spec/03 §2), so nothing here needs them; the SSO cookie session (spec/22
 * phase 6) is set by a top-level navigation, never by these requests.
 */
export class FetchTransport implements Transport {
  constructor(
    private readonly timeoutMs = 30_000,
    private readonly fetchImpl: typeof fetch = (...args) => fetch(...args)
  ) {}

  async send(request: HttpRequest): Promise<HttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch (e) {
      throw NativeAuthError.network(e);
    } finally {
      clearTimeout(timer);
    }
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    let body: string;
    try {
      body = await response.text();
    } catch (e) {
      throw NativeAuthError.network(e);
    }
    return { status: response.status, headers, body };
  }
}

/** One entry of the redacted flow log (`KeycloakWeb.Options.onRequest`). */
export interface FlowLogEntry {
  method: string;
  url: string;
  status?: number;
  error?: string;
  durationMs: number;
}

const SENSITIVE_FIELDS = new Set([
  'password',
  'password_confirm',
  'totp',
  'otp',
  'code',
  'code_verifier',
  'refresh_token',
  'token',
  'recovery_code',
  'pin',
  'pin_confirm',
  'auth_session',
]);

/** Whether a form field's value is a secret (masked in logs and transcripts). */
export function isSensitiveField(name: string): boolean {
  return SENSITIVE_FIELDS.has(name);
}

/** Wraps a transport and reports each exchange without bodies, for diagnostics. */
export class ObservingTransport implements Transport {
  constructor(
    private readonly inner: Transport,
    private readonly observer?: (entry: FlowLogEntry) => void
  ) {}

  async send(request: HttpRequest): Promise<HttpResponse> {
    if (this.observer === undefined) return this.inner.send(request);
    const started = Date.now();
    const url = request.url.split('?')[0]!;
    try {
      const response = await this.inner.send(request);
      this.observer({
        method: request.method,
        url,
        status: response.status,
        durationMs: Date.now() - started,
      });
      return response;
    } catch (e) {
      this.observer({
        method: request.method,
        url,
        error: NativeAuthError.from(e).code,
        durationMs: Date.now() - started,
      });
      throw e;
    }
  }
}
