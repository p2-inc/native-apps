import { DPoPSigner } from './dpop';
import { base64UrlEncode, randomBytes, sha256 } from './encoding';
import { NativeAuthError, NativeAuthErrorCode } from './errors';
import { arr, asObject, int, str } from './json';
import type { MetadataClient } from './metadata';
import {
  answerChallengeType,
  answerFields,
  parseChallenge,
  parseFlowContext,
  parseRedirectToWeb,
  type Challenge,
  type ChallengeAnswer,
  type FlowContext,
  type KcActionStatus,
  type RedirectToWebRequest,
} from './model';
import type { Credentials, Tokens } from './tokens';
import {
  FORM_CONTENT_TYPE,
  encodeForm,
  responseJson,
  type HttpResponse,
  type Transport,
} from './transport';

/** Parameters of the initial request (spec/03 §2.1). */
export interface LoginParameters {
  /** Default `openid`. */
  scope?: string;
  acrValues?: string;
  loginHint?: string;
  prompt?: string;
  maxAge?: number;
  nonce?: string;
  uiLocales?: string;
  /** Free-text device label shown in events and push prompts. */
  deviceName?: string;
  /** Stable app-generated id. */
  deviceId?: string;
  /** Application-initiated action (spec/21, `kc_action`), e.g. `UPDATE_PASSWORD`. */
  kcAction?: string;
  /**
   * What the flow does (spec/22 phase 3): a login (default), a new-user `registration`, or a
   * forgotten-password `reset_credentials`. Metadata `flowsSupported` lists what the realm allows.
   */
  flow?: 'login' | 'registration' | 'reset_credentials';
  /** Extra fields of the initial request (spec/03 §2.3); use the reserved `x_` prefix. */
  additionalParameters?: Record<string, string>;
  /** Extra fields on every continuation request of the flow. */
  continuationParameters?: Record<string, string>;
}

/** What `start()` and `respond()` hand back (spec/05 §2.1). */
export type FlowStep =
  | {
      kind: 'challenges';
      /** The challenge set in server order. */
      challenges: Challenge[];
      /** The entries this SDK can answer, in server order. */
      supportedChallenges: Challenge[];
      context: FlowContext;
      /** Remaining lifetime of the authentication session, in seconds. */
      expiresIn?: number;
    }
  | {
      kind: 'authorized';
      credentials: Credentials;
      /** Outcome of `LoginParameters.kcAction` (spec/21); absent without `kc_action`. */
      kcActionStatus?: KcActionStatus;
    }
  | { kind: 'redirectToWeb'; request: RedirectToWebRequest };

export type FlowState = 'idle' | 'awaitingAnswer' | 'finished';

export interface Pkce {
  verifier: string;
  challenge: string;
}

export async function generatePkce(): Promise<Pkce> {
  const verifier = base64UrlEncode(randomBytes(32));
  return { verifier, challenge: base64UrlEncode(await sha256(verifier)) };
}

const RESERVED_FIELD_NAMES = new Set([
  'client_id',
  'response_type',
  'scope',
  'code_challenge',
  'code_challenge_method',
  'acr_values',
  'login_hint',
  'prompt',
  'max_age',
  'nonce',
  'ui_locales',
  'device_name',
  'device_id',
  'kc_action',
  'native_flow',
  'auth_session',
  'challenge_type',
  'challenge_id',
  'action',
]);

const CONTINUATION_FIELD_NAMES = new Set(['auth_session', 'challenge_type', 'challenge_id']);

/** `extra` in key order, refusing names that are reserved or already set. */
function extraFields(
  extra: Record<string, string> | undefined,
  existing: [string, string][]
): [string, string][] {
  if (extra === undefined) return [];
  const taken = new Set(existing.map(([name]) => name));
  for (const name of Object.keys(extra)) {
    if (name.length === 0 || RESERVED_FIELD_NAMES.has(name) || taken.has(name)) {
      throw new NativeAuthError(
        NativeAuthErrorCode.invalidParameter,
        `Extra field '${name}' is empty, reserved or already set by the request`
      );
    }
  }
  return Object.keys(extra)
    .sort()
    .map((name) => [name, extra[name]!]);
}

type ChallengeOutcome =
  | { kind: 'code'; code: string; authSession?: string; kcActionStatus?: string }
  | {
      kind: 'challenges';
      authSession: string;
      expiresIn?: number;
      challenges: Challenge[];
      context: FlowContext;
    }
  | { kind: 'redirectToWeb'; request: RedirectToWebRequest };

/** Parses a challenge endpoint response (spec/03 §3). */
export function parseChallengeResponse(response: HttpResponse): ChallengeOutcome {
  const json = asObject(responseJson(response));
  if (json === undefined) {
    throw new NativeAuthError(
      NativeAuthErrorCode.invalidResponse,
      `Challenge endpoint answered HTTP ${response.status} without a JSON body`,
      { statusCode: response.status }
    );
  }
  if (response.status === 200) {
    const code = str(json.authorization_code);
    if (code === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, '200 without authorization_code', {
        statusCode: 200,
        details: json,
      });
    }
    return {
      kind: 'code',
      code,
      authSession: str(json.auth_session),
      kcActionStatus: str(json.kc_action_status),
    };
  }
  const error = str(json.error);
  // 403 per draft-04; 400 tolerated for older servers (spec/03 §3.2).
  if (
    error === NativeAuthErrorCode.insufficientAuthorization &&
    (response.status === 403 || response.status === 400) &&
    Array.isArray(json.challenges)
  ) {
    const authSession = str(json.auth_session);
    if (authSession === undefined) {
      throw new NativeAuthError(
        NativeAuthErrorCode.invalidResponse,
        'Challenge response without auth_session',
        { statusCode: response.status, details: json }
      );
    }
    return {
      kind: 'challenges',
      authSession,
      expiresIn: int(json.expires_in),
      challenges: arr(json.challenges).flatMap((c) => {
        const parsed = parseChallenge(c);
        return parsed === undefined ? [] : [parsed];
      }),
      context: parseFlowContext(json.context),
    };
  }
  if (error === NativeAuthErrorCode.redirectToWeb) {
    const request = parseRedirectToWeb(json);
    if (request !== undefined) return { kind: 'redirectToWeb', request };
  }
  throw NativeAuthError.fromResponse(response);
}

/**
 * The challenge-driven state machine (spec/05 §2): `start() → challenges → respond(…) → authorized`.
 * One flow per login; nothing is sent until `start()`.
 */
export class NativeLoginFlow {
  private stateValue: FlowState = 'idle';
  private session: string | undefined;
  private pending: Challenge[] = [];
  private lastExpiresIn: number | undefined;
  private actionStatus: KcActionStatus | undefined;
  private endpoint: string | undefined;
  private started = false;

  constructor(
    readonly clientId: string,
    readonly parameters: LoginParameters,
    readonly pkce: Pkce,
    /** The post-login `auth_session` this flow steps up, `undefined` for a fresh login. */
    readonly stepUpSession: string | undefined,
    private readonly metadata: MetadataClient,
    private readonly transport: Transport,
    private readonly dpop: DPoPSigner | undefined,
    private readonly tokens: Tokens
  ) {}

  get state(): FlowState {
    return this.stateValue;
  }

  get isStepUp(): boolean {
    return this.stepUpSession !== undefined;
  }

  /** The current `auth_session`, replaced on every response (spec/03 §5). For diagnostics. */
  get authSession(): string | undefined {
    return this.session;
  }

  get pendingChallenges(): Challenge[] {
    return this.pending;
  }

  /** Remaining lifetime of the authentication session as last reported, in seconds. */
  get expiresIn(): number | undefined {
    return this.lastExpiresIn;
  }

  /** Outcome of `LoginParameters.kcAction` once the flow is authorized (spec/21). */
  get kcActionStatus(): KcActionStatus | undefined {
    return this.actionStatus;
  }

  async start(): Promise<FlowStep> {
    if (this.started) {
      throw new NativeAuthError(NativeAuthErrorCode.flowState, 'start() can only be called once per flow');
    }
    this.started = true;
    const document = await this.metadata.metadata();
    this.endpoint = document.authorizationChallengeEndpoint;
    const p = this.parameters;
    const fields: [string, string][] = [
      ['client_id', this.clientId],
      ['response_type', 'code'],
    ];
    const scope = p.scope ?? 'openid';
    if (scope.length > 0) fields.push(['scope', scope]);
    fields.push(['code_challenge', this.pkce.challenge], ['code_challenge_method', 'S256']);
    if (p.acrValues !== undefined) fields.push(['acr_values', p.acrValues]);
    if (p.loginHint !== undefined) fields.push(['login_hint', p.loginHint]);
    if (p.prompt !== undefined) fields.push(['prompt', p.prompt]);
    if (p.maxAge !== undefined) fields.push(['max_age', String(p.maxAge)]);
    if (p.nonce !== undefined) fields.push(['nonce', p.nonce]);
    if (p.uiLocales !== undefined) fields.push(['ui_locales', p.uiLocales]);
    if (p.deviceName !== undefined) fields.push(['device_name', p.deviceName]);
    if (p.deviceId !== undefined) fields.push(['device_id', p.deviceId]);
    if (p.kcAction !== undefined) fields.push(['kc_action', p.kcAction]);
    if (p.flow !== undefined && p.flow !== 'login') fields.push(['native_flow', p.flow]);
    fields.push(...extraFields(p.additionalParameters, fields));
    // spec/03 §5: an initial request plus the post-login auth_session = step-up.
    if (this.stepUpSession !== undefined) fields.push(['auth_session', this.stepUpSession]);
    return this.send(fields);
  }

  /**
   * Answers `challenge`, which must be pending. `additionalFields` are sent with this request only
   * (spec/03 §2.3).
   */
  async respond(
    answer: ChallengeAnswer,
    challenge: Challenge,
    additionalFields?: Record<string, string>
  ): Promise<FlowStep> {
    const session = this.session;
    if (this.stateValue !== 'awaitingAnswer' || session === undefined) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        `No challenge is pending (state: ${this.stateValue})`
      );
    }
    if (!this.pending.some((c) => c.id === challenge.id && c.wireType === challenge.wireType)) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        `Challenge ${challenge.wireType} is not in the pending set`
      );
    }
    if (answer.kind !== 'skip' && answer.kind !== 'custom') {
      const expected = answerChallengeType[answer.kind];
      if (expected !== challenge.wireType) {
        throw new NativeAuthError(
          NativeAuthErrorCode.unsupportedChallenge,
          `A ${answer.kind} answer cannot be sent for a ${challenge.wireType} challenge`
        );
      }
    }
    if (answer.kind === 'skip' && !challenge.skippable) {
      throw new NativeAuthError(NativeAuthErrorCode.flowState, `Challenge ${challenge.wireType} is not skippable`);
    }
    const fields = answerFields(answer);
    const clash = fields.find(([name]) => CONTINUATION_FIELD_NAMES.has(name));
    if (clash !== undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.invalidParameter, `An answer may not set '${clash[0]}'`);
    }
    const all: [string, string][] = [
      ['auth_session', session],
      ['challenge_type', challenge.wireType],
      ['challenge_id', challenge.id],
      ...fields,
    ];
    all.push(...extraFields(this.parameters.continuationParameters, all));
    all.push(...extraFields(additionalFields, all));
    return this.send(all);
  }

  /** `action=cancel`: the server invalidates the session. Safe to call at any point. */
  async cancel(): Promise<void> {
    const previous = this.stateValue;
    const session = this.session;
    this.stateValue = 'finished';
    this.pending = [];
    if (previous !== 'awaitingAnswer' || session === undefined || this.endpoint === undefined) return;
    this.session = undefined;
    try {
      // The server answers invalid_session once the session is cancelled (spec/03 §2.2).
      await this.post([
        ['auth_session', session],
        ['action', 'cancel'],
      ]);
    } catch {
      // Best effort.
    }
  }

  /** The browser fallback finished the login (`WebFallback.complete`). */
  browserCompleted(kcActionStatus: string | undefined): void {
    this.stateValue = 'finished';
    this.actionStatus = kcActionStatus;
  }

  private async send(fields: [string, string][]): Promise<FlowStep> {
    let outcome: ChallengeOutcome;
    try {
      outcome = parseChallengeResponse(await this.post(fields));
    } catch (e) {
      const error = NativeAuthError.from(e);
      this.noteFailure(error);
      throw error;
    }
    switch (outcome.kind) {
      case 'challenges':
        this.session = outcome.authSession;
        this.pending = outcome.challenges;
        this.lastExpiresIn = outcome.expiresIn;
        this.stateValue = 'awaitingAnswer';
        return {
          kind: 'challenges',
          challenges: outcome.challenges,
          supportedChallenges: outcome.challenges.filter((c) => c.supported),
          context: outcome.context,
          expiresIn: outcome.expiresIn,
        };
      case 'code': {
        this.stateValue = 'finished';
        this.pending = [];
        this.session = outcome.authSession;
        this.actionStatus = outcome.kcActionStatus;
        const credentials = await this.tokens.exchange(outcome.code, this.pkce.verifier, {
          authSession: outcome.authSession,
        });
        return {
          kind: 'authorized',
          credentials,
          ...(outcome.kcActionStatus !== undefined && { kcActionStatus: outcome.kcActionStatus }),
        };
      }
      case 'redirectToWeb':
        // The server removed the native authentication session (spec/03 §3.4).
        this.stateValue = 'finished';
        this.pending = [];
        this.session = undefined;
        return { kind: 'redirectToWeb', request: outcome.request };
    }
  }

  private noteFailure(error: NativeAuthError): void {
    switch (error.code) {
      case NativeAuthErrorCode.invalidSession:
      case NativeAuthErrorCode.accessDenied:
      case NativeAuthErrorCode.invalidClient:
      case NativeAuthErrorCode.redirectToWeb:
      case NativeAuthErrorCode.serverError:
        // Terminal for this flow (spec/03 §3.5).
        this.stateValue = 'finished';
        this.pending = [];
        this.session = undefined;
        break;
      case NativeAuthErrorCode.invalidRequest:
        // The session survives; a fresh auth_session may have been handed back.
        if (error.authSession !== undefined) this.session = error.authSession;
        break;
    }
  }

  private async post(fields: [string, string][]): Promise<HttpResponse> {
    const url = this.endpoint!;
    let response = await this.transport.send(await this.request(url, fields));
    const nonce = this.dpop !== undefined ? DPoPSigner.nonceChallenge(response) : undefined;
    if (nonce !== undefined) {
      this.dpop!.setNonce(nonce, url);
      response = await this.transport.send(await this.request(url, fields));
    }
    return response;
  }

  private async request(url: string, fields: [string, string][]) {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': FORM_CONTENT_TYPE,
    };
    if (this.dpop !== undefined) headers.DPoP = await this.dpop.proof('POST', url);
    return { method: 'POST', url, headers, body: encodeForm(fields) };
  }
}
