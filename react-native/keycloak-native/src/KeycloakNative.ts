import NativeKeycloakNative, { type Spec } from './NativeKeycloakNative';
import {
  NativeAuthError,
  NativeAuthErrorCode,
  answerChallengeType,
  parseCredentials,
  parseFlowStep,
  type Challenge,
  type ChallengeAnswer,
  type Credentials,
  type FlowStep,
  type JsonObject,
  type RedirectToWebRequest,
} from './model';

/** Parameters of the initial request (spec/03 §2.1), as `LoginParameters` of the native SDKs. */
export interface LoginParameters {
  scope?: string;
  acrValues?: string;
  loginHint?: string;
  prompt?: string;
  maxAge?: number;
  nonce?: string;
  uiLocales?: string;
  /** Free-text device label shown in events and push prompts. */
  deviceName?: string;
  /** Stable app-generated UUID. */
  deviceId?: string;
  /** Extra fields of the initial request (spec/03 §2.3); use the reserved `x_` prefix. */
  additionalParameters?: Record<string, string>;
  /** Extra fields of every continuation request of the flow. */
  continuationParameters?: Record<string, string>;
}

/** How the native side binds tokens with DPoP (`DPoPMode`). */
export type DPoPMode = 'automatic' | 'hardware' | 'software' | 'disabled';

export interface KeycloakNativeConfig {
  /** The issuer URL including `/realms/<realm>`, not the challenge endpoint. */
  issuer: string;
  clientId: string;
  /** Default `automatic`: Secure Enclave / Android Keystore when available, software otherwise. */
  dpop?: DPoPMode;
  /** Only for development against a tunnel (spec/12). Never ship it. */
  allowRpIdMismatch?: boolean;
  /** Ask the browser fallback for a session that shares no cookies with normal browsing. */
  ephemeralWebSession?: boolean;
  /** Seconds the metadata document is cached (default 300). */
  metadataCacheTtl?: number;
  /**
   * Where the native side keeps credentials, the DPoP key reference and push state: the Keychain
   * service on iOS (default `io.phasetwo.keycloak.native`), the `KeystoreSecureStore` namespace on
   * Android (default the client id). Items are scoped by issuer and client id within it.
   */
  storageNamespace?: string;
  /** iOS: a Keychain access group shared with app extensions. */
  keychainAccessGroup?: string;
}

let nativeOverride: Spec | undefined;

/** Replaces the native module (tests, previews). Pass `undefined` to restore it. */
export function setNativeModuleForTesting(module: Spec | undefined): void {
  nativeOverride = module;
}

function nativeModule(): Spec {
  const module = nativeOverride ?? NativeKeycloakNative;
  if (module == null) {
    throw new NativeAuthError(
      NativeAuthErrorCode.notConfigured,
      'The KeycloakNative native module is not linked (rebuild the app after installing the package)'
    );
  }
  return module;
}

async function call<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (e) {
    throw NativeAuthError.from(e);
  }
}

let nextInstance = 0;

/**
 * The configured SDK instance (spec/05 §2): one per issuer + client. The native side holds the SDK
 * core (`KeycloakNative` of `KeycloakNativeCore` / `io.phasetwo.keycloak.nativeauth.sdk`), its secure
 * storage, DPoP key and platform pieces; this object is a typed handle to it.
 */
export class KeycloakNative {
  readonly issuer: string;
  readonly clientId: string;
  readonly config: Readonly<KeycloakNativeConfig>;
  /** The native instance id. */
  readonly instanceId: string;
  private readonly ready: Promise<void>;

  private constructor(config: KeycloakNativeConfig, instanceId: string) {
    this.config = Object.freeze({ ...config });
    this.issuer = config.issuer.replace(/\/+$/, '');
    this.clientId = config.clientId;
    this.instanceId = instanceId;
    this.ready = call(() =>
      nativeModule().configure(instanceId, JSON.stringify(config))
    );
    // Surfaced by the first call that awaits it.
    this.ready.catch(() => {});
  }

  /**
   * Configures an instance. Keep one per issuer + client for the life of the app, so credentials,
   * the DPoP key, the metadata cache and refreshes stay consistent.
   */
  static configure(config: KeycloakNativeConfig): KeycloakNative {
    nextInstance += 1;
    return new KeycloakNative(
      config,
      `${config.issuer.replace(/\/+$/, '')}|${config.clientId}|${nextInstance}`
    );
  }

  /** Entry point for logins and step-ups (spec/05 §2.2). */
  readonly authentication = {
    /** Creates a flow; nothing is sent until `start()`. */
    startLogin: (parameters: LoginParameters = {}): Promise<NativeLoginFlow> =>
      this.createFlow(parameters, false),
    /**
     * Step-up / re-authentication inside the stored session (spec/03 §5). Fails with
     * `credentials_not_found` when no post-login session is stored.
     */
    stepUp: (parameters: LoginParameters = {}): Promise<NativeLoginFlow> =>
      this.createFlow({ scope: 'openid', ...parameters }, true),
  };

  /** Completes a `redirectToWeb` step through the system browser (spec/03 §3.4). */
  readonly webFallback = {
    complete: (
      request: RedirectToWebRequest,
      flow: NativeLoginFlow
    ): Promise<Credentials> => flow.completeWebFallback(request),
  };

  /** The instance's credentials, kept in the Keychain / Android Keystore by the native side. */
  readonly credentialsManager = {
    /**
     * Persists credentials from a flow's `authorized` step or browser fallback. Other credentials
     * objects (from `credentials()`) are already stored.
     */
    store: async (credentials: Credentials): Promise<void> => {
      const flow = credentialsSource.get(credentials);
      if (flow === undefined) return;
      await this.ready;
      await call(() => nativeModule().storeCredentials(flow));
    },
    /** Possibly expired credentials, or `null`. */
    stored: async (): Promise<Credentials | null> => {
      await this.ready;
      const json = await call(() =>
        nativeModule().storedCredentials(this.instanceId)
      );
      return json === null ? null : parseCredentials(JSON.parse(json));
    },
    /** Only checks expiry, not server validity. */
    hasValid: async (minTtlSeconds = 0): Promise<boolean> => {
      await this.ready;
      return call(() =>
        nativeModule().hasValidCredentials(this.instanceId, minTtlSeconds)
      );
    },
    /**
     * Stored credentials, refreshed when the access token is within 30 seconds plus `minTtlSeconds`
     * of expiry. `credentials_not_found` when nothing is stored; `reauthentication_required` when the
     * refresh was refused.
     */
    credentials: async (minTtlSeconds = 0): Promise<Credentials> => {
      await this.ready;
      const json = await call(() =>
        nativeModule().credentials(this.instanceId, minTtlSeconds)
      );
      return parseCredentials(JSON.parse(json));
    },
    /** Server logout with the stored refresh token, then clears local credentials regardless. */
    logout: async (): Promise<void> => {
      await this.ready;
      await call(() => nativeModule().logout(this.instanceId));
    },
    clear: async (): Promise<void> => {
      await this.ready;
      await call(() => nativeModule().clearCredentials(this.instanceId));
    },
  };

  /**
   * Headers for a request to a resource server with the stored credentials, refreshed when needed:
   * `Authorization: Bearer …`, or `Authorization: DPoP …` plus a `DPoP` proof for exactly this method
   * and URL (spec/03 §8). Send the request with the same method and URL.
   */
  async resourceRequestHeaders(
    method: string,
    url: string
  ): Promise<Record<string, string>> {
    await this.ready;
    const json = await call(() =>
      nativeModule().resourceRequestHeaders(this.instanceId, method, url)
    );
    return JSON.parse(json) as Record<string, string>;
  }

  /** The server's native-auth metadata document as received. */
  async metadata(forceRefresh = false): Promise<JsonObject> {
    await this.ready;
    const json = await call(() =>
      nativeModule().metadata(this.instanceId, forceRefresh)
    );
    return JSON.parse(json) as JsonObject;
  }

  /** RFC 7638 thumbprint of the DPoP public key (`jkt`), `null` when DPoP is disabled. */
  async dpopKeyThumbprint(): Promise<string | null> {
    await this.ready;
    return call(() => nativeModule().dpopKeyThumbprint(this.instanceId));
  }

  private async createFlow(
    parameters: LoginParameters,
    stepUp: boolean
  ): Promise<NativeLoginFlow> {
    await this.ready;
    const id = await call(() =>
      nativeModule().createFlow(
        this.instanceId,
        JSON.stringify(parameters),
        stepUp
      )
    );
    return new NativeLoginFlow(id, stepUp);
  }
}

/** Which flow produced a credentials object, for `credentialsManager.store`. */
const credentialsSource = new WeakMap<Credentials, string>();

export type FlowState = 'idle' | 'awaitingAnswer' | 'finished';

/**
 * The challenge-driven state machine (spec/05 §2): `start()` → challenges → `respond(answer,
 * challenge)` → authorized. The native `NativeLoginFlow` does the work; this handle tracks the pending
 * set so a stale or foreign challenge is refused before it reaches the bridge. Serialize submissions:
 * a second `respond` while one is in flight is refused with `flow_state`.
 */
export class NativeLoginFlow {
  /** The native flow id. */
  readonly id: string;
  readonly isStepUp: boolean;
  private stateValue: FlowState = 'idle';
  private pending: Challenge[] = [];
  private lastRedirect: RedirectToWebRequest | undefined;
  private inFlight = false;

  /** @internal Created by `KeycloakNative.authentication`. */
  constructor(id: string, isStepUp: boolean) {
    this.id = id;
    this.isStepUp = isStepUp;
  }

  get state(): FlowState {
    return this.stateValue;
  }

  /** The challenges of the last set, in server order. */
  get pendingChallenges(): readonly Challenge[] {
    return this.pending;
  }

  /** Sends the initial request. Call once per flow. */
  async start(): Promise<FlowStep> {
    if (this.stateValue !== 'idle' || this.inFlight) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        'start() can only be called once per flow'
      );
    }
    return this.run(() => nativeModule().start(this.id));
  }

  /**
   * Answers `challenge`, which must be in the pending set. `additionalFields` are sent with this
   * request only (spec/03 §2.3).
   */
  async respond(
    answer: ChallengeAnswer,
    challenge: Challenge,
    additionalFields: Record<string, string> = {}
  ): Promise<FlowStep> {
    if (this.stateValue !== 'awaitingAnswer' || this.inFlight) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        `No challenge is pending (state: ${this.stateValue}${this.inFlight ? ', a request is in flight' : ''})`
      );
    }
    if (
      !this.pending.some(
        (c) => c.id === challenge.id && c.wireType === challenge.wireType
      )
    ) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        `Challenge ${challenge.wireType} is not in the pending set`
      );
    }
    if (answer.kind === 'skip') {
      if (!challenge.skippable) {
        throw new NativeAuthError(
          NativeAuthErrorCode.flowState,
          `Challenge ${challenge.wireType} is not skippable`
        );
      }
    } else if (
      answer.kind !== 'custom' &&
      answerChallengeType[answer.kind] !== challenge.wireType
    ) {
      throw new NativeAuthError(
        NativeAuthErrorCode.unsupportedChallenge,
        `A ${answer.kind} answer cannot be sent for a ${challenge.wireType} challenge`
      );
    }
    return this.run(() =>
      nativeModule().respond(
        this.id,
        challenge.id,
        challenge.wireType,
        JSON.stringify(answer),
        JSON.stringify(additionalFields)
      )
    );
  }

  /** `action=cancel`: best-effort server cancellation. Safe at any point. */
  async cancel(): Promise<void> {
    this.stateValue = 'finished';
    this.pending = [];
    await call(() => nativeModule().cancel(this.id));
  }

  /**
   * Runs the browser fallback for this flow's `redirectToWeb` step and exchanges the code with the
   * flow's PKCE verifier. Errors: `web_fallback_cancelled`, `web_fallback_failed`, token errors.
   */
  async completeWebFallback(
    request: RedirectToWebRequest
  ): Promise<Credentials> {
    if (this.lastRedirect === undefined) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        'This flow did not end in redirectToWeb'
      );
    }
    if (request.requestUri !== this.lastRedirect.requestUri) {
      throw new NativeAuthError(
        NativeAuthErrorCode.flowState,
        'The request is not the one this flow ended with'
      );
    }
    const json = await call(() => nativeModule().completeWebFallback(this.id));
    const credentials = parseCredentials(JSON.parse(json));
    credentialsSource.set(credentials, this.id);
    return credentials;
  }

  /** Forgets the native flow. The flow cannot be used afterwards. */
  release(): void {
    this.stateValue = 'finished';
    this.pending = [];
    try {
      nativeModule().releaseFlow(this.id);
    } catch {
      // Nothing to release.
    }
  }

  private async run(request: () => Promise<string>): Promise<FlowStep> {
    this.inFlight = true;
    try {
      const step = parseFlowStep(JSON.parse(await request()));
      switch (step.kind) {
        case 'challenges':
          this.stateValue = 'awaitingAnswer';
          this.pending = step.challenges;
          break;
        case 'authorized':
          this.stateValue = 'finished';
          this.pending = [];
          credentialsSource.set(step.credentials, this.id);
          break;
        case 'redirectToWeb':
          this.stateValue = 'finished';
          this.pending = [];
          this.lastRedirect = step.request;
          break;
      }
      return step;
    } catch (e) {
      const error = NativeAuthError.from(e);
      // Terminal for the flow (spec/03 §3.5): the server removed the authentication session.
      if (
        error.code === NativeAuthErrorCode.invalidSession ||
        error.code === NativeAuthErrorCode.accessDenied ||
        error.code === NativeAuthErrorCode.invalidClient ||
        error.code === NativeAuthErrorCode.serverError ||
        error.code === NativeAuthErrorCode.redirectToWeb
      ) {
        this.stateValue = 'finished';
        this.pending = [];
      }
      throw error;
    } finally {
      this.inFlight = false;
    }
  }
}
