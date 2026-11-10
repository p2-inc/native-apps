import type { Spec } from '../../NativeKeycloakNative';
import type { ChallengeAnswer, JsonObject, JsonValue } from '../../model';
import type {
  KeycloakNativeConfig,
  LoginParameters,
} from '../../KeycloakNative';
import {
  isChallengeEndpoint,
  isTokenEndpoint,
  type Exchange,
  type Transcript,
} from './transcripts';

/**
 * A stand-in for the native module that replays a recorded transcript: every request the TypeScript
 * layer causes is turned into the form the native SDKs would send and compared with the recording
 * (same field set; values equal except `***` and the per-run fields), and the recorded response is
 * handed back as the native side would encode it. A server change that renames a field or a
 * TypeScript change that sends the wrong answer fails these tests.
 *
 * The form encoding here mirrors `ChallengeAnswer.formFields` and `NativeLoginFlow.start()` of the
 * native SDKs (ChallengeModels.kt / ChallengeModels.swift, LoginFlow.kt / LoginFlow.swift); their own
 * transcript replay tests pin those down on the wire.
 */
export class TranscriptNative implements Spec {
  private cursor = 0;
  private config: KeycloakNativeConfig | undefined;
  private flows = new Map<
    string,
    { parameters: LoginParameters; stepUp: boolean; session?: string }
  >();
  private nextFlow = 0;
  /** Credentials persisted through `storeCredentials`. */
  stored: JsonObject | undefined;
  private lastCredentials = new Map<string, JsonObject>();
  /** Every request matched, in order (for assertions). */
  readonly matched: Exchange[] = [];
  /** What `pickSavedPassword` returns; `undefined` behaves like a closed sheet. */
  savedPassword: { username: string; password: string } | undefined;
  /** Logins offered to the password manager. */
  readonly savedPasswords: { username: string; password: string }[] = [];
  /** Native ceremonies run, in order. */
  readonly ceremonies: {
    kind: string;
    challengeId: string;
    label?: string;
    provider?: string;
  }[] = [];
  readonly pushResponses: {
    cid: string;
    action: string;
    userVerification: string;
  }[] = [];
  enrollment: JsonObject | undefined;

  constructor(
    private readonly transcript: Transcript,
    /** Fields whose recorded value differs on every run. */
    private readonly perRunFields: ReadonlySet<string> = new Set([
      'code_challenge',
      'device_id',
      'nonce',
    ])
  ) {}

  /** Exchanges not consumed yet. */
  get remaining(): Exchange[] {
    return this.transcript.exchanges.slice(this.cursor);
  }

  async configure(_instanceId: string, config: string): Promise<void> {
    this.config = JSON.parse(config) as KeycloakNativeConfig;
  }

  async createFlow(
    _instanceId: string,
    parameters: string,
    stepUp: boolean
  ): Promise<string> {
    this.nextFlow += 1;
    const id = `flow-${this.nextFlow}`;
    this.flows.set(id, {
      parameters: JSON.parse(parameters) as LoginParameters,
      stepUp,
    });
    return id;
  }

  async start(flowId: string): Promise<string> {
    const flow = this.flow(flowId);
    const p = flow.parameters;
    const form: Record<string, string | undefined> = {
      client_id: this.config?.clientId,
      response_type: 'code',
      scope: p.scope === undefined ? 'openid' : p.scope || undefined,
      code_challenge: '<per run>',
      code_challenge_method: 'S256',
      acr_values: p.acrValues,
      login_hint: p.loginHint,
      prompt: p.prompt,
      max_age: p.maxAge === undefined ? undefined : String(p.maxAge),
      nonce: p.nonce,
      ui_locales: p.uiLocales,
      device_name: p.deviceName,
      device_id: p.deviceId,
      ...p.additionalParameters,
    };
    const presenceOnly = new Set(this.perRunFields);
    if (flow.stepUp) {
      // The post-login session comes from the native credentials store.
      form.auth_session = '<stored>';
      presenceOnly.add('auth_session');
    }
    return this.challengeRequest(flowId, form, presenceOnly);
  }

  async respond(
    flowId: string,
    challengeId: string,
    challengeType: string,
    answer: string,
    additionalFields: string
  ): Promise<string> {
    const flow = this.flow(flowId);
    const form: Record<string, string | undefined> = {
      auth_session: flow.session,
      challenge_type: challengeType,
      challenge_id: challengeId,
      ...answerFields(JSON.parse(answer) as ChallengeAnswer),
      ...flow.parameters.continuationParameters,
      ...(JSON.parse(additionalFields) as Record<string, string>),
    };
    return this.challengeRequest(flowId, form, this.perRunFields);
  }

  /**
   * The native side runs the ceremony and sends its fields; the WebAuthn material differs per run, so
   * the recorded ceremony fields only need to be present (the native replay suites pin their values).
   */
  async respondWithPasskey(
    flowId: string,
    challengeId: string,
    _prefer: boolean
  ): Promise<string> {
    this.ceremonies.push({ kind: 'passkey', challengeId });
    return this.ceremony(flowId, challengeId, 'passkey', {});
  }

  async respondWithPasskeyRegistration(
    flowId: string,
    challengeId: string,
    label: string
  ): Promise<string> {
    this.ceremonies.push({ kind: 'passkeyRegistration', challengeId, label });
    return this.ceremony(
      flowId,
      challengeId,
      'passkey_registration',
      label.length > 0 ? { label } : {}
    );
  }

  async respondWithPushEnrollment(
    flowId: string,
    challengeId: string,
    deviceLabel: string,
    pushProviderType: string,
    pushProviderId: string
  ): Promise<string> {
    this.ceremonies.push({
      kind: 'pushEnrollment',
      challengeId,
      label: deviceLabel,
      provider: `${pushProviderType}:${pushProviderId}`,
    });
    const step = await this.ceremony(
      flowId,
      challengeId,
      'push_enrollment',
      {}
    );
    const parsed = JSON.parse(step) as {
      kind: string;
      challenges?: { type?: string; error?: unknown }[];
    };
    const rejected = parsed.challenges?.some(
      (c) => c.type === 'push_enrollment' && c.error !== undefined
    );
    if (!rejected)
      this.enrollment = this.syntheticEnrollment(
        deviceLabel,
        pushProviderType,
        pushProviderId
      );
    return step;
  }

  async cancel(flowId: string): Promise<void> {
    const flow = this.flow(flowId);
    if (flow.session === undefined) return;
    const exchange = this.next(isChallengeEndpoint);
    expectForm(exchange, { auth_session: flow.session, action: 'cancel' });
    flow.session = undefined;
  }

  async completeWebFallback(flowId: string): Promise<string> {
    // The browser part is not recorded; the token exchange with the browser's code is.
    const exchange = this.next(isTokenEndpoint);
    if (exchange.request.form?.grant_type !== 'authorization_code') {
      throw new Error(
        `#${exchange.seq}: expected the browser code exchange, got ${JSON.stringify(exchange.request.form)}`
      );
    }
    const credentials = this.credentialsFrom(exchange);
    this.lastCredentials.set(flowId, credentials);
    return JSON.stringify(credentials);
  }

  async storeCredentials(flowId: string): Promise<void> {
    const credentials = this.lastCredentials.get(flowId);
    if (credentials === undefined)
      throw rejection('flow_state', 'This flow has no credentials');
    this.stored = credentials;
  }

  releaseFlow(flowId: string): void {
    this.flows.delete(flowId);
  }

  async credentials(): Promise<string> {
    if (this.stored === undefined)
      throw rejection('credentials_not_found', 'Nothing is stored');
    return JSON.stringify(this.stored);
  }

  async storedCredentials(): Promise<string | null> {
    return this.stored === undefined ? null : JSON.stringify(this.stored);
  }

  async hasValidCredentials(): Promise<boolean> {
    return this.stored !== undefined;
  }

  async resourceRequestHeaders(): Promise<string> {
    if (this.stored === undefined)
      throw rejection('credentials_not_found', 'Nothing is stored');
    return JSON.stringify({
      Authorization: `${this.stored.tokenType} ${this.stored.accessToken}`,
    });
  }

  async logout(): Promise<void> {
    this.stored = undefined;
  }

  async clearCredentials(): Promise<void> {
    this.stored = undefined;
  }

  async metadata(): Promise<string> {
    return '{}';
  }

  async dpopKeyThumbprint(): Promise<string | null> {
    return null;
  }

  async pickSavedPassword(): Promise<string> {
    if (this.savedPassword === undefined)
      throw rejection('saved_password_cancelled', 'The sheet was closed');
    return JSON.stringify(this.savedPassword);
  }

  async savePassword(
    _instanceId: string,
    username: string,
    password: string
  ): Promise<void> {
    this.savedPasswords.push({ username, password });
  }

  async registerNewPasskey(
    _instanceId: string,
    label: string
  ): Promise<string> {
    return JSON.stringify({ credentialId: 'registered', label: label || null });
  }

  async pushEnrollment(): Promise<string | null> {
    return this.enrollment === undefined
      ? null
      : JSON.stringify(this.enrollment);
  }

  async pushEnroll(
    _instanceId: string,
    deviceLabel: string,
    pushProviderType: string,
    pushProviderId: string
  ): Promise<string> {
    const start = this.next((e) =>
      e.request.path.endsWith('/native-auth/push/enroll/start')
    );
    if (start.response.status !== 200)
      throw rejection('invalid_response', undefined, start.response.status);
    const complete = this.next((e) =>
      e.request.path.endsWith('/enroll/complete')
    );
    if (complete.response.status !== 200 && complete.response.status !== 201)
      throw rejection('invalid_response', undefined, complete.response.status);
    this.enrollment = this.syntheticEnrollment(
      deviceLabel,
      pushProviderType,
      pushProviderId
    );
    return JSON.stringify(this.enrollment);
  }

  async pushForgetEnrollment(): Promise<void> {
    this.enrollment = undefined;
  }

  async pushPendingApprovals(): Promise<string> {
    const exchange = this.next((e) =>
      e.request.path.endsWith('/push-mfa/login/pending')
    );
    const body = asObject(exchange.response.json);
    if (exchange.response.status !== 200)
      throw rejection('invalid_response', undefined, exchange.response.status);
    return JSON.stringify(
      Array.isArray(body.challenges) ? body.challenges : []
    );
  }

  async pushRespond(
    _instanceId: string,
    cid: string,
    action: string,
    userVerification: string
  ): Promise<string> {
    this.pushResponses.push({ cid, action, userVerification });
    const exchange = this.next((e) =>
      e.request.path.endsWith(`/push-mfa/login/challenges/${cid}/respond`)
    );
    const body = asObject(exchange.response.json);
    switch (exchange.response.status) {
      case 200:
        return String(body.status);
      case 403:
        throw rejection(
          'user_verification_mismatch',
          String(body.error ?? ''),
          403
        );
      case 409:
        throw rejection('push_conflict', String(body.error ?? ''), 409);
      default:
        throw rejection(
          'invalid_response',
          undefined,
          exchange.response.status
        );
    }
  }

  async pushHandleMessage(
    _instanceId: string,
    data: string
  ): Promise<string | null> {
    const o = JSON.parse(data) as Record<string, string>;
    return o.cid === undefined ? null : JSON.stringify({ cid: o.cid });
  }

  async pushUpdateProvider(): Promise<void> {}

  async pushRotateKey(): Promise<void> {
    this.stored = undefined;
  }

  async pushLockout(): Promise<void> {}

  // ---

  private flow(flowId: string) {
    const flow = this.flows.get(flowId);
    if (flow === undefined) throw new Error(`Unknown flow ${flowId}`);
    return flow;
  }

  private next(predicate: (e: Exchange) => boolean): Exchange {
    while (this.cursor < this.transcript.exchanges.length) {
      const exchange = this.transcript.exchanges[this.cursor]!;
      this.cursor += 1;
      if (predicate(exchange)) {
        this.matched.push(exchange);
        return exchange;
      }
    }
    throw new Error(`${this.transcript.test}: no further exchange matches`);
  }

  private ceremony(
    flowId: string,
    challengeId: string,
    type: string,
    fields: Record<string, string>
  ): Promise<string> {
    const flow = this.flow(flowId);
    const exchange = this.transcript.exchanges
      .slice(this.cursor)
      .find(isChallengeEndpoint);
    const recorded = exchange?.request.form ?? {};
    const ceremonyFields = Object.keys(recorded).filter(
      (k) =>
        !['auth_session', 'challenge_type', 'challenge_id', 'label'].includes(k)
    );
    const form: Record<string, string | undefined> = {
      auth_session: flow.session,
      challenge_type: type,
      challenge_id: challengeId,
      ...Object.fromEntries(ceremonyFields.map((k) => [k, '<ceremony>'])),
      ...fields,
      ...flow.parameters.continuationParameters,
    };
    return Promise.resolve(
      this.challengeRequest(
        flowId,
        form,
        new Set([...this.perRunFields, ...ceremonyFields])
      )
    );
  }

  private syntheticEnrollment(
    deviceLabel: string,
    pushProviderType: string,
    pushProviderId: string
  ): JsonObject {
    return {
      credentialId: 'credential',
      deviceId: 'device',
      userId: 'user',
      deviceLabel,
      pushProviderType,
      pushProviderId: pushProviderId.length > 0 ? pushProviderId : null,
      deviceApiBase: 'http://localhost/realms/demo/push-mfa',
      keyThumbprint: 'jkt',
      enrolledAt: Date.now(),
    };
  }

  private challengeRequest(
    flowId: string,
    form: Record<string, string | undefined>,
    presenceOnly: ReadonlySet<string>
  ): string {
    const exchange = this.next(isChallengeEndpoint);
    expectForm(exchange, form, presenceOnly);
    const body = asObject(exchange.response.json);
    const flow = this.flow(flowId);
    const status = exchange.response.status;
    if (status === 200 && typeof body.authorization_code === 'string') {
      flow.session = undefined;
      const token = this.next(isTokenEndpoint);
      expectForm(
        token,
        {
          grant_type: 'authorization_code',
          client_id: this.config?.clientId,
          code: body.authorization_code,
          code_verifier: '***',
        },
        new Set(),
        // The token endpoint may carry a redirect_uri sentinel (code_exchange metadata).
        new Set(['redirect_uri'])
      );
      const credentials = this.credentialsFrom(token);
      this.lastCredentials.set(flowId, credentials);
      return JSON.stringify({ kind: 'authorized', credentials });
    }
    if (
      body.error === 'insufficient_authorization' &&
      Array.isArray(body.challenges)
    ) {
      flow.session = body.auth_session as string;
      return JSON.stringify({
        kind: 'challenges',
        challenges: body.challenges,
        context: body.context ?? {},
        expiresIn: body.expires_in,
      });
    }
    if (body.error === 'redirect_to_web') {
      flow.session = undefined;
      return JSON.stringify({ kind: 'redirectToWeb', request: body });
    }
    if (
      body.error === 'invalid_request' &&
      typeof body.auth_session === 'string'
    ) {
      flow.session = body.auth_session;
    }
    throw rejection(
      typeof body.error === 'string' ? body.error : 'invalid_response',
      typeof body.error_description === 'string'
        ? body.error_description
        : undefined,
      status
    );
  }

  /** What the native modules encode for JavaScript (`NativeCredentials`, spec/19 §4). */
  private credentialsFrom(exchange: Exchange): JsonObject {
    const body = asObject(exchange.response.json);
    if (exchange.response.status !== 200) {
      throw rejection(
        String(body.error ?? 'invalid_response'),
        typeof body.error_description === 'string'
          ? body.error_description
          : undefined,
        exchange.response.status
      );
    }
    const now = Date.now();
    const tokenType = String(body.token_type ?? 'Bearer');
    return {
      accessToken: String(body.access_token),
      tokenType: tokenType.toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer',
      idToken: (body.id_token as string | undefined) ?? null,
      scope: (body.scope as string | undefined) ?? null,
      expiresAt: now + Number(body.expires_in ?? 0) * 1000,
      refreshExpiresAt:
        typeof body.refresh_expires_in === 'number' &&
        body.refresh_expires_in > 0
          ? now + body.refresh_expires_in * 1000
          : null,
      issuedAt: now,
      hasRefreshToken: typeof body.refresh_token === 'string',
      isDPoPBound: tokenType.toLowerCase() === 'dpop',
    };
  }
}

function asObject(value: JsonValue | undefined): JsonObject {
  return value !== null &&
    value !== undefined &&
    typeof value === 'object' &&
    !Array.isArray(value)
    ? value
    : {};
}

/** The form fields of an answer, as the native SDKs send them. */
export function answerFields(answer: ChallengeAnswer): Record<string, string> {
  switch (answer.kind) {
    case 'username':
      return { username: answer.username };
    case 'password':
      return { password: answer.password };
    case 'totp':
      return answer.credentialId
        ? { totp: answer.code, credential_id: answer.credentialId }
        : { totp: answer.code };
    case 'otp':
      return { otp: answer.code };
    case 'recoveryCode':
      return { recovery_code: answer.code };
    case 'updatePassword':
      return { password: answer.password, password_confirm: answer.confirm };
    case 'verifyEmail':
      return { code: answer.code };
    case 'terms':
      return { accepted: String(answer.accepted) };
    case 'otpResend':
    case 'verifyEmailResend':
    case 'pushResend':
      return { action: 'resend' };
    case 'pushPoll':
      return { action: 'poll' };
    case 'pushEnrollmentCheck':
      return { action: 'check' };
    case 'skip':
      return { action: 'skip' };
    case 'custom':
      return Object.fromEntries(answer.fields.map((f) => [f.name, f.value]));
  }
}

/**
 * The matching rules of the Swift and Kotlin harnesses: the same field set; values equal, except a
 * recorded `***` (masked secret) and `presenceOnly` fields, which must merely be present.
 */
function expectForm(
  exchange: Exchange,
  expected: Record<string, string | undefined>,
  presenceOnly: ReadonlySet<string> = new Set(),
  optional: ReadonlySet<string> = new Set()
): void {
  const recorded = exchange.request.form ?? {};
  const sent = Object.fromEntries(
    Object.entries(expected).filter(
      (entry): entry is [string, string] => entry[1] !== undefined
    )
  );
  const problems: string[] = [];
  for (const name of new Set([
    ...Object.keys(recorded),
    ...Object.keys(sent),
  ])) {
    const r = recorded[name];
    const s = sent[name];
    if (r === undefined && s !== undefined)
      problems.push(`sent ${name}, not in the recording`);
    else if (s === undefined && r !== undefined && !optional.has(name))
      problems.push(`recorded ${name}=${r}, not sent`);
    else if (
      r !== undefined &&
      s !== undefined &&
      r !== '***' &&
      !presenceOnly.has(name) &&
      r !== s
    )
      problems.push(`${name}: sent ${s}, recorded ${r}`);
  }
  if (problems.length > 0) {
    throw new Error(
      `#${exchange.seq} ${exchange.request.path}: ${problems.join('; ')}`
    );
  }
}

function rejection(code: string, message?: string, statusCode?: number) {
  const error = new Error(message ?? code) as Error & {
    code: string;
    userInfo: Record<string, unknown>;
  };
  error.code = code;
  error.userInfo = { statusCode };
  return error;
}
