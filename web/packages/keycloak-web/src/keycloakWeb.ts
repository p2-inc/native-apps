import { CredentialsManager } from './credentials';
import { DPoPSigner, type DPoPMode } from './dpop';
import { NativeAuthError, NativeAuthErrorCode } from './errors';
import { generatePkce, NativeLoginFlow, type FlowStep, type LoginParameters } from './flow';
import { MetadataClient, type NativeAuthMetadata } from './metadata';
import type { Challenge } from './model';
import {
  BrowserPasskeyPlatform,
  PasskeyRegistrationClient,
  type PasskeyPlatform,
  type RegisteredPasskey,
} from './passkeys';
import { IndexedDBStore, MemoryStore, type KeyValueStore } from './storage';
import { authorizationScheme, isDPoPBound, Tokens, type Credentials } from './tokens';
import {
  FetchTransport,
  ObservingTransport,
  type FlowLogEntry,
  type Transport,
} from './transport';
import { PopupPresenter, WebFallback, type WebAuthenticationPresenter } from './webFallback';

export interface KeycloakWebOptions {
  /** The realm issuer, e.g. `https://auth.example.com/realms/acme`. */
  issuer: string;
  clientId: string;
  /** Default `automatic`: DPoP proofs on every request, with a non-extractable WebCrypto key. */
  dpop?: DPoPMode;
  /**
   * Where the DPoP key and the refresh token live. Default `indexeddb` (a reload keeps the session);
   * `memory` signs the user out on reload. IndexedDB failures fall back to memory with a warning.
   */
  storage?: 'indexeddb' | 'memory' | KeyValueStore;
  /** Replaces `fetch` (tests, custom pinning). */
  transport?: Transport;
  /** The passkey platform; default `navigator.credentials`. */
  passkeyPlatform?: PasskeyPlatform;
  /** How `redirect_to_web` steps open Keycloak's pages; default a popup. */
  webPresenter?: WebAuthenticationPresenter;
  /** Receives one entry per request, without bodies (diagnostics). */
  onRequest?: (entry: FlowLogEntry) => void;
  /** Receives warnings (storage fallbacks, failed server logout). Default `console.warn`. */
  onWarning?: (message: string) => void;
  /**
   * Called when a resource server answers `kc.fetch` with RFC 9470 `insufficient_user_authentication`.
   * Run a step-up (for example `<StepUpDialog>`) and resolve `true` once it succeeded; `kc.fetch`
   * then retries the request once. Without a handler the call fails with `step_up_required`.
   */
  onStepUpRequired?: (request: StepUpRequest) => Promise<boolean>;
  metadataCacheTtlMs?: number;
}

/** What a resource server asked for (RFC 9470). */
export interface StepUpRequest {
  acrValues?: string;
  maxAge?: number;
  /** The request that was refused. */
  url: string;
  method: string;
}

/**
 * The configured SDK instance (spec/05 §2), one per issuer + client: login, step-up, the
 * credentials, passkeys, the browser fallback and authenticated requests.
 */
export class KeycloakWeb {
  readonly issuer: string;
  readonly clientId: string;
  readonly transport: Transport;
  readonly store: KeyValueStore;
  readonly metadataClient: MetadataClient;
  readonly dpopSigner: DPoPSigner | undefined;
  readonly tokens: Tokens;
  private readonly credentials: CredentialsManager;
  private readonly passkeyPlatform: PasskeyPlatform;
  readonly presenter: WebAuthenticationPresenter;
  private readonly warn: (message: string) => void;
  private stepUpHandler: ((request: StepUpRequest) => Promise<boolean>) | undefined;

  private constructor(options: KeycloakWebOptions) {
    this.issuer = options.issuer.replace(/\/+$/, '');
    this.clientId = options.clientId;
    this.warn = options.onWarning ?? ((m) => console.warn(`[keycloak-web] ${m}`));
    this.transport = new ObservingTransport(options.transport ?? new FetchTransport(), options.onRequest);
    this.store = resolveStore(options.storage, this.warn);
    this.metadataClient = new MetadataClient(this.issuer, this.transport, options.metadataCacheTtlMs);
    this.dpopSigner =
      options.dpop === 'disabled' ? undefined : new DPoPSigner(this.store, this.scopedKey('dpop-key'), this.warn);
    this.tokens = new Tokens(this.clientId, this.issuer, this.metadataClient, this.transport, this.dpopSigner);
    this.credentials = new CredentialsManager(this.store, this.scopedKey('credentials'), this.tokens, this.warn);
    this.passkeyPlatform = options.passkeyPlatform ?? new BrowserPasskeyPlatform();
    this.presenter = options.webPresenter ?? new PopupPresenter();
    this.stepUpHandler = options.onStepUpRequired;
  }

  static configure(options: KeycloakWebOptions): KeycloakWeb {
    return new KeycloakWeb(options);
  }

  /** A key under this instance's issuer + client scope in the store. */
  scopedKey(suffix: string): string {
    return `${this.issuer}|${this.clientId}|${suffix}`;
  }

  authentication(): Authentication {
    return new Authentication(this);
  }

  credentialsManager(): CredentialsManager {
    return this.credentials;
  }

  metadata(forceRefresh = false): Promise<NativeAuthMetadata> {
    return this.metadataClient.metadata(forceRefresh);
  }

  /** RFC 7638 thumbprint of the DPoP key (`jkt`); `undefined` when DPoP is disabled. */
  async dpopKeyThumbprint(): Promise<string | undefined> {
    return this.dpopSigner?.thumbprint();
  }

  /** Restores the session after a reload (a refresh with the stored refresh token). */
  restore(): Promise<Credentials | undefined> {
    return this.credentials.restore();
  }

  /** Signs out: ends the Keycloak session, forgets the tokens and the DPoP key. */
  async signOut(): Promise<void> {
    await this.credentials.logout();
    await this.dpopSigner?.reset();
  }

  /** Sets or replaces the RFC 9470 step-up handler (`KeycloakWebOptions.onStepUpRequired`). */
  setStepUpHandler(handler: ((request: StepUpRequest) => Promise<boolean>) | undefined): void {
    this.stepUpHandler = handler;
  }

  // Passkeys

  passkeyPlatformSupportsAutofill(): Promise<boolean> {
    return this.passkeyPlatform.supportsConditionalMediation();
  }

  /**
   * Runs the browser's passkey prompt for a `passkey` challenge and answers it. With `mediation:
   * 'conditional'` the passkeys appear in the username field's autofill instead (the input needs
   * `autocomplete="username webauthn"`); abort it with `signal` before another answer.
   */
  async usePasskey(
    flow: NativeLoginFlow,
    challenge: Challenge,
    options: { mediation?: 'conditional' | 'optional'; signal?: AbortSignal } = {}
  ): Promise<FlowStep> {
    if (challenge.type !== 'passkey' || challenge.params === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.unsupportedChallenge, 'Not a usable passkey challenge');
    }
    const assertion = await this.passkeyPlatform.assert(challenge.params, options);
    return flow.respond({ kind: 'passkey', assertion }, challenge);
  }

  /** Runs the browser's registration for a `passkey_registration` challenge and answers it. */
  async registerPasskeyOnChallenge(flow: NativeLoginFlow, challenge: Challenge, label?: string): Promise<FlowStep> {
    if (challenge.type !== 'passkey_registration' || challenge.params === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.unsupportedChallenge, 'Not a usable passkey_registration challenge');
    }
    const attestation = await this.passkeyPlatform.register(challenge.params);
    return flow.respond({ kind: 'passkeyRegistration', attestation, ...(label ? { label } : {}) }, challenge);
  }

  /**
   * Adds a passkey for the signed-in user (spec/03 §6). Errors: `insufficient_authorization` when
   * the login is older than the realm allows (step up with `error.authSession`, then retry),
   * `passkey_cancelled`.
   */
  async registerNewPasskey(label?: string): Promise<RegisteredPasskey> {
    const credentials = await this.credentials.credentials();
    const client = new PasskeyRegistrationClient(this.issuer, this.metadataClient, this.transport, this.dpopSigner);
    const options = await client.options(credentials);
    const attestation = await this.passkeyPlatform.register(options.params);
    return client.finish(credentials, options.registrationId, attestation, label);
  }

  // Browser fallback

  webFallback(): WebFallback {
    return new WebFallback(this.clientId, this.issuer, this.metadataClient, this.presenter, this.tokens);
  }

  /**
   * After a full-page `redirect_to_web` (`webFallback().redirect`): exchanges the code on this URL,
   * stores the credentials and returns them; `undefined` when this page load is not a callback.
   */
  async handleRedirectCallback(): Promise<{ credentials: Credentials; kcActionStatus?: string; returnTo: string } | undefined> {
    const result = await this.webFallback().handleRedirectCallback();
    if (result !== undefined) await this.credentials.store(result.credentials);
    return result;
  }

  // Authenticated requests

  /**
   * Headers for a request to a resource server: `Authorization: Bearer …`, or `Authorization: DPoP …`
   * plus a `DPoP` proof with `ath` when the tokens are bound (spec/03 §8).
   */
  async resourceRequestHeaders(method: string, url: string, credentials?: Credentials): Promise<Record<string, string>> {
    const c = credentials ?? (await this.credentials.credentials());
    const headers: Record<string, string> = { Authorization: `${authorizationScheme(c)} ${c.accessToken}` };
    if (isDPoPBound(c) && this.dpopSigner !== undefined) {
      headers.DPoP = await this.dpopSigner.proof(method, url, c.accessToken);
    }
    return headers;
  }

  /**
   * `fetch` with the user's token. Retries once after a refresh on `invalid_token`, once with a new
   * proof on `use_dpop_nonce`, and once after a step-up on RFC 9470 `insufficient_user_authentication`
   * when a step-up handler is set.
   */
  async fetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const url = new URL(String(input), typeof window === 'undefined' ? undefined : window.location.href).toString();
    const method = (init.method ?? 'GET').toUpperCase();
    const send = async (credentials?: Credentials) => {
      const headers = new Headers(init.headers);
      for (const [name, value] of Object.entries(await this.resourceRequestHeaders(method, url, credentials))) {
        headers.set(name, value);
      }
      return globalThis.fetch(url, { ...init, method, headers });
    };
    let response = await send();
    if (response.status !== 401 && response.status !== 403) return response;
    const challenge = parseWwwAuthenticate(response.headers.get('www-authenticate'));
    if (challenge.error === 'use_dpop_nonce' && challenge.nonce === undefined) {
      const nonce = response.headers.get('dpop-nonce');
      if (nonce !== null) {
        this.dpopSigner?.setNonce(nonce, url);
        response = await send();
      }
    } else if (challenge.error === 'invalid_token') {
      const current = this.credentials.snapshot;
      if (current !== undefined) {
        // Force a refresh: the server no longer accepts this access token.
        await this.credentials.store({ ...current, expiresAt: 0 });
        response = await send(await this.credentials.credentials());
      }
    } else if (challenge.error === 'insufficient_user_authentication') {
      const request: StepUpRequest = {
        url,
        method,
        ...(challenge.acr_values !== undefined && { acrValues: challenge.acr_values }),
        ...(challenge.max_age !== undefined && { maxAge: Number(challenge.max_age) }),
      };
      const handler = this.stepUpHandler;
      if (handler === undefined || !(await handler(request))) {
        throw new NativeAuthError(
          NativeAuthErrorCode.stepUpRequired,
          challenge.error_description ?? 'The server requires a stronger authentication',
          { statusCode: response.status }
        );
      }
      response = await send();
    }
    return response;
  }
}

/** Entry point for logins, step-ups and application-initiated actions (spec/05 §2.2). */
export class Authentication {
  constructor(private readonly kc: KeycloakWeb) {}

  /** Creates a flow; nothing is sent until `start()`. */
  async startLogin(parameters: LoginParameters = {}): Promise<NativeLoginFlow> {
    return this.flow(parameters, undefined);
  }

  /**
   * Step-up inside the existing user session (spec/03 §5): the server skips the username step and
   * asks only for what the requested level still needs. Throws `credentials_not_found` when nobody
   * is signed in; the server answers `invalid_session` when the session has ended.
   */
  async stepUp(parameters: LoginParameters = {}, authSession?: string): Promise<NativeLoginFlow> {
    const session = authSession ?? (await this.kc.credentialsManager().authSession());
    if (session === undefined) {
      throw new NativeAuthError(
        NativeAuthErrorCode.credentialsNotFound,
        'No post-login auth_session is stored; log in first'
      );
    }
    return this.flow(parameters, session);
  }

  /**
   * Application-initiated action (spec/21): runs the required action `alias` for the signed-in user,
   * for example `UPDATE_PASSWORD` behind a "Change password" button. Drive it like a login; after
   * `authorized`, `flow.kcActionStatus` says whether it succeeded, was cancelled or could not run.
   */
  requiredAction(alias: string, parameters: LoginParameters = {}): Promise<NativeLoginFlow> {
    return this.stepUp({ ...parameters, kcAction: alias });
  }

  /**
   * Continues after an endpoint refused the token with `insufficient_authorization` and an
   * `auth_session` (for example `registerNewPasskey`): a step-up with that session and its `max_age`.
   */
  async continueAfterTokenChallenge(error: NativeAuthError, parameters: LoginParameters = {}): Promise<NativeLoginFlow> {
    if (error.authSession === undefined) {
      throw new NativeAuthError(
        NativeAuthErrorCode.reauthenticationRequired,
        'The server returned no auth_session; start a new login',
        { cause: error }
      );
    }
    const maxAge = parameters.maxAge ?? error.maxAge;
    return this.flow({ ...parameters, ...(maxAge !== undefined && { maxAge }) }, error.authSession);
  }

  private async flow(parameters: LoginParameters, stepUpSession: string | undefined): Promise<NativeLoginFlow> {
    return new NativeLoginFlow(
      this.kc.clientId,
      parameters,
      await generatePkce(),
      stepUpSession,
      this.kc.metadataClient,
      this.kc.transport,
      this.kc.dpopSigner,
      this.kc.tokens
    );
  }
}

function resolveStore(storage: KeycloakWebOptions['storage'], warn: (m: string) => void): KeyValueStore {
  if (storage === 'memory') return new MemoryStore();
  if (storage !== undefined && storage !== 'indexeddb') return storage;
  if (IndexedDBStore.isAvailable()) return new FallbackStore(new IndexedDBStore(), warn);
  warn('IndexedDB is unavailable; the session lives in memory and a reload signs the user out');
  return new MemoryStore();
}

/** IndexedDB that switches to memory for good after its first failure (private mode, blocked data). */
class FallbackStore implements KeyValueStore {
  private failed = false;
  private readonly memory = new MemoryStore();

  constructor(
    private readonly primary: KeyValueStore,
    private readonly warn: (m: string) => void
  ) {}

  async get<T>(key: string): Promise<T | undefined> {
    return this.call((s) => s.get<T>(key));
  }

  async set<T>(key: string, value: T): Promise<void> {
    return this.call((s) => s.set(key, value));
  }

  async remove(key: string): Promise<void> {
    return this.call((s) => s.remove(key));
  }

  private async call<R>(body: (store: KeyValueStore) => Promise<R>): Promise<R> {
    if (!this.failed) {
      try {
        return await body(this.primary);
      } catch (e) {
        this.failed = true;
        this.warn(`${String(e)}; using memory: a reload signs the user out`);
      }
    }
    return body(this.memory);
  }
}

/** Parses the parameters of a `WWW-Authenticate` header (Bearer or DPoP scheme). */
export function parseWwwAuthenticate(value: string | null): Record<string, string | undefined> {
  const result: Record<string, string | undefined> = {};
  if (value === null) return result;
  const pattern = /([a-zA-Z_][\w-]*)="((?:[^"\\]|\\.)*)"|([a-zA-Z_][\w-]*)=([^\s,]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    const name = (match[1] ?? match[3])!;
    result[name] = (match[2]?.replace(/\\(.)/g, '$1') ?? match[4])!;
  }
  return result;
}
