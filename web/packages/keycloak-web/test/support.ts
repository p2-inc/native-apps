/**
 * Replays the recorded integration-test transcripts (`keycloak-native-auth/demo/transcripts`), the
 * contract every SDK replays: the SDK must send the recorded requests and understand the recorded
 * responses. Same matching rules as `MockTransport.kt` and `MockTransport.swift`, so a re-recorded
 * transcript fails every SDK alike.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import {
  KeycloakWeb,
  MemoryStore,
  NativeAuthError,
  decodeForm,
  type Challenge,
  type ChallengeType,
  type FlowStep,
  type HttpRequest,
  type HttpResponse,
  type LoginParameters,
  type NativeLoginFlow,
  type PasskeyAssertion,
  type PasskeyAssertionParams,
  type PasskeyAttestation,
  type PasskeyPlatform,
  type PasskeyRegistrationParams,
  type Transport,
  type WebAuthenticationPresenter,
} from '../src';

const here = dirname(fileURLToPath(import.meta.url));
export const TRANSCRIPTS =
  process.env.KEYCLOAK_NATIVE_TRANSCRIPTS ?? join(here, '../../../../keycloak-native-auth/demo/transcripts');

export const MASK = '***';
export const IT_PARAMETERS: LoginParameters = { scope: 'openid profile', deviceName: 'NativeAuthIT' };
export const DEMO = 'demo-native';
export const DEMO_ALT = 'demo-native-alt';
export const DEMO_PASSKEY = 'demo-native-passkey';
export const METADATA = 'NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath';

interface RecordedRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  form?: Record<string, string>;
  json?: Record<string, unknown>;
  body?: string;
}

interface RecordedResponse {
  status: number;
  headers?: Record<string, string>;
  json?: unknown;
  body?: string;
}

export interface Exchange {
  seq: number;
  request: RecordedRequest;
  response: RecordedResponse;
}

export interface Transcript {
  test: string;
  base_url: string;
  exchanges: Exchange[];
}

export function loadTranscript(name: string): Transcript {
  return JSON.parse(readFileSync(join(TRANSCRIPTS, `${name}.json`), 'utf8')) as Transcript;
}

export function allTranscripts(): string[] {
  return readdirSync(TRANSCRIPTS)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''))
    .sort();
}

export function exchange(t: Transcript, seq: number): Exchange {
  const e = t.exchanges.find((x) => x.seq === seq);
  if (e === undefined) throw new Error(`no exchange #${seq} in ${t.test}`);
  return e;
}

export function form(t: Transcript, seq: number): Record<string, string> {
  return exchange(t, seq).request.form ?? {};
}

export function responseOf(r: RecordedResponse): HttpResponse {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(r.headers ?? {})) headers[k.toLowerCase()] = v;
  return {
    status: r.status,
    headers,
    body: r.json !== undefined ? JSON.stringify(r.json) : (r.body ?? ''),
  };
}

const VOLATILE_FORM_FIELDS = new Set(['code_challenge', 'device_id', 'nonce']);
const VOLATILE_JSON_FIELDS = new Set(['publicKeyJwk']);

export class Mismatch extends Error {}

/** Replays exchanges in order, rejecting any request that differs from the recorded one. */
export class MockTransport implements Transport {
  private readonly queue: Exchange[];
  readonly sent: HttpRequest[] = [];

  constructor(exchanges: Exchange[]) {
    this.queue = [...exchanges];
  }

  get remaining(): number {
    return this.queue.length;
  }

  async send(request: HttpRequest): Promise<HttpResponse> {
    this.sent.push(request);
    const expected = this.queue.shift();
    if (expected === undefined) {
      throw new Mismatch(`unexpected request ${request.method} ${new URL(request.url).pathname}: transcript exhausted`);
    }
    match(request, expected.request, expected.seq);
    return responseOf(expected.response);
  }
}

export function match(actual: HttpRequest, expected: RecordedRequest, seq: number): void {
  const prefix = `exchange #${seq} ${expected.method} ${expected.path}: `;
  const path = new URL(actual.url).pathname;
  if (actual.method !== expected.method || path !== expected.path) {
    throw new Mismatch(`${prefix}SDK sent ${actual.method} ${path}`);
  }
  const authorization = expected.headers?.Authorization;
  if (authorization !== undefined) {
    const scheme = authorization.split(' ')[0]!;
    const sent = actual.headers.Authorization;
    if (sent === undefined || !sent.startsWith(`${scheme} `)) {
      throw new Mismatch(`${prefix}expected an Authorization header with scheme ${scheme}`);
    }
  }
  if (expected.form !== undefined) {
    if (actual.body === undefined) throw new Mismatch(`${prefix}expected a form body`);
    const sent = new Map<string, string>();
    for (const [name, value] of decodeForm(actual.body)) if (!sent.has(name)) sent.set(name, value);
    for (const [name, value] of Object.entries(expected.form)) {
      const v = sent.get(name);
      if (v === undefined) throw new Mismatch(`${prefix}missing form field ${name}`);
      if (value === MASK || VOLATILE_FORM_FIELDS.has(name)) continue;
      if (v !== value) throw new Mismatch(`${prefix}field ${name}: SDK sent '${v}', recorded '${value}'`);
    }
    const extra = [...sent.keys()].filter((k) => !(k in expected.form!));
    if (extra.length > 0) throw new Mismatch(`${prefix}SDK sent fields the test did not: ${extra.sort().join(', ')}`);
  }
  if (expected.json !== undefined && typeof expected.json === 'object') {
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(actual.body ?? '') as Record<string, unknown>;
    } catch {
      throw new Mismatch(`${prefix}expected a JSON body`);
    }
    for (const [key, value] of Object.entries(expected.json)) {
      const sent = body[key];
      if (sent === undefined) throw new Mismatch(`${prefix}missing JSON field ${key}`);
      if (key === 'transports' && typeof value === 'string' && Array.isArray(sent)) {
        if (sent.join(',') !== value) throw new Mismatch(`${prefix}transports differ`);
        continue;
      }
      if (value === MASK || VOLATILE_JSON_FIELDS.has(key)) continue;
      if (JSON.stringify(sent) !== JSON.stringify(value)) throw new Mismatch(`${prefix}JSON field ${key} differs`);
    }
  }
}

/** Scripted passkey platform: returns queued results and records the params it was asked for. */
export class MockPasskeyPlatform implements PasskeyPlatform {
  readonly assertions: PasskeyAssertion[] = [];
  readonly attestations: PasskeyAttestation[] = [];
  readonly assertParams: PasskeyAssertionParams[] = [];
  readonly registerParams: PasskeyRegistrationParams[] = [];
  readonly mediations: (string | undefined)[] = [];
  nextError: NativeAuthError | undefined;
  autofill = false;

  async supportsConditionalMediation(): Promise<boolean> {
    return this.autofill;
  }

  async assert(
    params: PasskeyAssertionParams,
    options: { mediation?: 'conditional' | 'optional'; signal?: AbortSignal } = {}
  ): Promise<PasskeyAssertion> {
    this.assertParams.push(params);
    this.mediations.push(options.mediation);
    const error = this.nextError;
    if (error !== undefined) {
      this.nextError = undefined;
      throw error;
    }
    const next = this.assertions.shift();
    if (next === undefined) throw new NativeAuthError('mock_empty', 'no assertion queued');
    return next;
  }

  async register(params: PasskeyRegistrationParams): Promise<PasskeyAttestation> {
    this.registerParams.push(params);
    const error = this.nextError;
    if (error !== undefined) {
      this.nextError = undefined;
      throw error;
    }
    const next = this.attestations.shift();
    if (next === undefined) throw new NativeAuthError('mock_empty', 'no attestation queued');
    return next;
  }
}

/** Plays the popup: records the URL and answers with a scripted callback. */
export class MockPresenter implements WebAuthenticationPresenter {
  readonly opened: { url: string; redirectUri: string }[] = [];
  constructor(public callback: (url: string) => string) {}

  async authenticate(url: string, redirectUri: string): Promise<string> {
    this.opened.push({ url, redirectUri });
    return this.callback(url);
  }
}

export interface Harness {
  kc: KeycloakWeb;
  transport: MockTransport;
  transcripts: Transcript[];
  passkeys: MockPasskeyPlatform;
  store: MemoryStore;
}

/** The metadata exchange (always first) followed by the scenario's exchanges. */
export function replay(
  names: string[],
  clientId: string,
  options: { seqs?: number[]; range?: [number, number]; presenter?: WebAuthenticationPresenter; metadataFrom?: string } = {}
): Harness {
  const metadata = loadTranscript(options.metadataFrom ?? METADATA);
  const transcripts = names.map(loadTranscript);
  const exchanges: Exchange[] = [exchange(metadata, 1)];
  const first = transcripts[0]!;
  if (options.seqs !== undefined) exchanges.push(...options.seqs.map((s) => exchange(first, s)));
  else if (options.range !== undefined)
    exchanges.push(...first.exchanges.filter((e) => e.seq >= options.range![0] && e.seq <= options.range![1]));
  else for (const t of transcripts) exchanges.push(...t.exchanges);
  const transport = new MockTransport(exchanges);
  const passkeys = new MockPasskeyPlatform();
  const store = new MemoryStore();
  const kc = KeycloakWeb.configure({
    issuer: `${metadata.base_url}/realms/demo`,
    clientId,
    transport,
    storage: store,
    passkeyPlatform: passkeys,
    ...(options.presenter !== undefined && { webPresenter: options.presenter }),
    onWarning: () => {},
  });
  return { kc, transport, transcripts, passkeys, store };
}

export function challenges(step: FlowStep): Challenge[] {
  if (step.kind !== 'challenges') throw new Error(`expected challenges, got ${step.kind}`);
  return step.challenges;
}

export function types(step: FlowStep): string[] {
  return challenges(step).map((c) => c.wireType);
}

export function requireChallenge<T extends ChallengeType>(step: FlowStep, type: T): Extract<Challenge, { type: T }> {
  const c = challenges(step).find((x) => x.type === type);
  if (c === undefined) throw new Error(`no ${type} challenge in ${types(step).join(', ')}`);
  return c as Extract<Challenge, { type: T }>;
}

export function authorized(step: FlowStep) {
  if (step.kind !== 'authorized') throw new Error(`expected authorized, got ${step.kind}`);
  return step;
}

export async function usernamePassword(flow: NativeLoginFlow, username: string, password: string): Promise<FlowStep> {
  let step = await flow.start();
  step = await flow.respond({ kind: 'username', username }, requireChallenge(step, 'username'));
  return flow.respond({ kind: 'password', password }, requireChallenge(step, 'password'));
}

export async function expectError(body: () => Promise<unknown>): Promise<NativeAuthError> {
  try {
    await body();
  } catch (e) {
    if (e instanceof Mismatch) throw e;
    expect(e).toBeInstanceOf(NativeAuthError);
    return e as NativeAuthError;
  }
  throw new Error('expected a NativeAuthError');
}

export function assertionFrom(f: Record<string, string>): PasskeyAssertion {
  return {
    credentialId: f.credential_id!,
    clientDataJson: f.client_data_json!,
    authenticatorData: f.authenticator_data!,
    signature: f.signature!,
    ...(f.user_handle !== undefined && { userHandle: f.user_handle }),
  };
}

export function attestationFrom(j: Record<string, unknown>): PasskeyAttestation {
  const transports = j.transports;
  return {
    credentialId: j.credential_id as string,
    clientDataJson: j.client_data_json as string,
    attestationObject: j.attestation_object as string,
    transports: Array.isArray(transports)
      ? (transports as string[])
      : typeof transports === 'string'
        ? transports.split(',').filter((s) => s.length > 0)
        : [],
  };
}
