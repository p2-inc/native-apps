import { NativeAuthError, NativeAuthErrorCode } from './errors';
import type { FlowStep, LoginParameters, NativeLoginFlow } from './flow';
import type { KeycloakWeb } from './keycloakWeb';
import type { Challenge, ChallengeAnswer, FlowContext, KcActionStatus, RedirectToWebRequest } from './model';
import type { Credentials } from './tokens';
import { PopupPresenter } from './webFallback';

/** Outcome of a login, step-up or app-initiated action. */
export type LoginResult =
  | {
      kind: 'authorized';
      credentials: Credentials;
      /** Outcome of an application-initiated action (spec/21); absent without `kc_action`. */
      kcActionStatus?: KcActionStatus;
    }
  | { kind: 'cancelled' }
  | { kind: 'failed'; error: NativeAuthError };

export type LoginPhase =
  | { kind: 'starting' }
  | {
      kind: 'challenges';
      challenges: Challenge[];
      context: FlowContext;
      /** The entry on screen; the rest are offered under "Try another way". */
      selected: Challenge;
    }
  | { kind: 'redirectToWeb'; request: RedirectToWebRequest }
  | { kind: 'finished'; result: LoginResult };

export interface LoginState {
  phase: LoginPhase;
  isSubmitting: boolean;
  /** A user-facing error not attached to a challenge (network, passkey failure…). */
  message?: string;
  /** `message`'s error code, for apps that translate. */
  messageCode?: string;
}

export interface LoginControllerOptions {
  /** What to start: a login (default), a step-up, or an application-initiated action. */
  mode?:
    | { kind: 'login'; parameters?: LoginParameters }
    | { kind: 'registration'; parameters?: LoginParameters }
    | { kind: 'resetPassword'; parameters?: LoginParameters }
    | { kind: 'stepUp'; parameters?: LoginParameters }
    | { kind: 'requiredAction'; alias: string; parameters?: LoginParameters };
  /** Run the passkey prompt as soon as a set shows `passkey`. Default `false`. */
  autoSelectPasskey?: boolean;
  /**
   * Offer passkeys in the username field's autofill (conditional mediation) when the set offers a
   * discoverable passkey next to the username. Default `true`.
   */
  passkeyAutofill?: boolean;
  /** Poll a pending push approval on its `poll_interval`. Default `true`. */
  pollPush?: boolean;
  /** Store the credentials in the `CredentialsManager` once authorized. Default `true`. */
  storeCredentials?: boolean;
  /** Called once with the outcome. */
  onResult?: (result: LoginResult) => void;
}

/** Errors that leave the challenge set on screen with an inline message. */
const RECOVERABLE: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.networkError,
  NativeAuthErrorCode.webFallbackFailed,
  NativeAuthErrorCode.passkeyFailed,
  NativeAuthErrorCode.passkeyUnavailable,
  NativeAuthErrorCode.rpIdMismatch,
  NativeAuthErrorCode.dpopKeyError,
  NativeAuthErrorCode.flowState,
  NativeAuthErrorCode.slowDown,
]);

/** Not a failure at all: the user closed a prompt or the popup. */
const DISMISSED: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.passkeyCancelled,
  NativeAuthErrorCode.webFallbackCancelled,
]);

/**
 * The state behind every login UI (React components, web components, your own): drives the flow,
 * picks the challenge to show, runs passkeys, push polling and the browser fallback, and reports the
 * result. Plain TypeScript with a subscription (`useSyncExternalStore`-compatible). The twin of the
 * React Native module's `LoginController`.
 */
export class LoginController {
  private stateValue: LoginState = { phase: { kind: 'starting' }, isSubmitting: false };
  private readonly listeners = new Set<() => void>();
  private flowValue: NativeLoginFlow | undefined;
  private started = false;
  private done = false;
  private inFlight = 0;
  private autofill: AbortController | undefined;
  private pushTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly options: LoginControllerOptions;

  constructor(
    readonly kc: KeycloakWeb,
    options: LoginControllerOptions = {}
  ) {
    this.options = options;
  }

  get state(): LoginState {
    return this.stateValue;
  }

  /** The flow, once started. */
  get flow(): NativeLoginFlow | undefined {
    return this.flowValue;
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): LoginState => this.stateValue;

  start(): Promise<void> {
    if (this.started) return Promise.resolve();
    this.started = true;
    return this.perform(async () => {
      const auth = this.kc.authentication();
      const mode = this.options.mode ?? { kind: 'login' };
      this.flowValue =
        mode.kind === 'login'
          ? await auth.startLogin(mode.parameters)
          : mode.kind === 'registration'
            ? await auth.startLogin({ ...mode.parameters, flow: 'registration' })
            : mode.kind === 'resetPassword'
              ? await auth.startLogin({ ...mode.parameters, flow: 'reset_credentials' })
              : mode.kind === 'stepUp'
            ? await auth.stepUp(mode.parameters)
            : await auth.requiredAction(mode.alias, mode.parameters);
      return this.flowValue.start();
    });
  }

  submit(answer: ChallengeAnswer, challenge: Challenge): Promise<void> {
    this.stopAutofill();
    return this.perform(() => this.requireFlow().respond(answer, challenge));
  }

  /** Runs the browser's passkey prompt for a `passkey` challenge and submits the assertion. */
  usePasskey(challenge: Challenge): Promise<void> {
    if (challenge.type !== 'passkey' || challenge.params === undefined) return Promise.resolve();
    this.stopAutofill();
    return this.perform(() => this.kc.usePasskey(this.requireFlow(), challenge));
  }

  /** Runs the browser's registration for a `passkey_registration` challenge and submits it. */
  registerPasskey(challenge: Challenge, label?: string): Promise<void> {
    if (challenge.type !== 'passkey_registration' || challenge.params === undefined) return Promise.resolve();
    return this.perform(() => this.kc.registerPasskeyOnChallenge(this.requireFlow(), challenge, label));
  }

  /** Shows another entry of the current set ("Try another way"). */
  select(challenge: Challenge): void {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'challenges' || !phase.challenges.some((c) => c.id === challenge.id)) return;
    this.stopPush();
    this.update({ phase: { ...phase, selected: challenge }, message: undefined, messageCode: undefined });
    this.afterShow();
  }

  /**
   * Continues a `redirectToWeb` step in a popup. Call it from the click handler: the popup opens
   * before anything is awaited, so the popup blocker allows it.
   */
  openBrowser(): Promise<void> {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'redirectToWeb') return Promise.resolve();
    if (this.kc.presenter instanceof PopupPresenter) this.kc.presenter.prepare();
    return this.perform(async () => {
      const flow = this.requireFlow();
      const credentials = await this.kc.webFallback().complete(phase.request, flow);
      const kcActionStatus = flow.kcActionStatus;
      return {
        kind: 'authorized',
        credentials,
        ...(kcActionStatus !== undefined && { kcActionStatus }),
      } satisfies FlowStep;
    });
  }

  /** Continues a `redirectToWeb` step by leaving the page (`kc.handleRedirectCallback()` on return). */
  async redirectToBrowser(): Promise<void> {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'redirectToWeb') return;
    await this.kc.webFallback().redirect(phase.request, this.requireFlow());
  }

  async cancel(): Promise<void> {
    if (this.done) return;
    this.stopTimers();
    this.done = true;
    try {
      await this.flowValue?.cancel();
    } catch {
      // Best effort.
    }
    this.finish({ kind: 'cancelled' });
  }

  /** Stops timers and the autofill request (component unmount). Does not cancel the flow. */
  dispose(): void {
    this.stopTimers();
  }

  /** Restarts what `dispose` stopped (a remount, e.g. React's strict mode). */
  resume(): void {
    if (!this.done && this.pushTimer === undefined) this.afterShow();
  }

  // ---

  private requireFlow(): NativeLoginFlow {
    if (this.flowValue === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.flowState, 'The flow has not started');
    }
    return this.flowValue;
  }

  private update(patch: Partial<LoginState>): void {
    this.stateValue = { ...this.stateValue, ...patch };
    for (const listener of this.listeners) listener();
  }

  private finish(result: LoginResult): void {
    this.update({ phase: { kind: 'finished', result } });
    this.options.onResult?.(result);
  }

  private async perform(body: () => Promise<FlowStep>, quiet = false): Promise<void> {
    if (this.done) return;
    this.inFlight += 1;
    if (!quiet) this.update({ isSubmitting: true, message: undefined, messageCode: undefined });
    try {
      await this.apply(await body());
    } catch (e) {
      const error = NativeAuthError.from(e);
      if (DISMISSED.has(error.code)) {
        // The set stays; the user may pick another way.
      } else if (RECOVERABLE.has(error.code) && !this.flowIsOver()) {
        this.update({ message: error.errorDescription ?? error.code, messageCode: error.code });
      } else {
        // Terminal (invalid_session, access_denied, …): the flow is over.
        this.done = true;
        this.stopTimers();
        this.finish({ kind: 'failed', error });
      }
    } finally {
      this.inFlight -= 1;
      if (!quiet || this.stateValue.isSubmitting) this.update({ isSubmitting: this.inFlight > 0 });
    }
  }

  private flowIsOver(): boolean {
    return this.flowValue?.state === 'finished' && this.stateValue.phase.kind !== 'redirectToWeb';
  }

  private async apply(step: FlowStep): Promise<void> {
    this.stopTimers();
    switch (step.kind) {
      case 'challenges': {
        if (step.challenges.length === 0) {
          throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, 'The server sent an empty challenge set');
        }
        const previous = this.stateValue.phase.kind === 'challenges' ? this.stateValue.phase.selected : undefined;
        const selected = pick(step.challenges, previous);
        this.update({ phase: { kind: 'challenges', challenges: step.challenges, context: step.context, selected } });
        this.afterShow();
        break;
      }
      case 'authorized': {
        this.done = true;
        if (this.options.storeCredentials ?? true) await this.kc.credentialsManager().store(step.credentials);
        this.finish({
          kind: 'authorized',
          credentials: step.credentials,
          ...(step.kcActionStatus !== undefined && { kcActionStatus: step.kcActionStatus }),
        });
        break;
      }
      case 'redirectToWeb':
        this.update({ phase: { kind: 'redirectToWeb', request: step.request } });
        break;
    }
  }

  /** Side effects of the challenge now on screen: passkey prompt or autofill, push polling. */
  private afterShow(): void {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'challenges') return;
    const selected = phase.selected;
    if (this.options.autoSelectPasskey && selected.type === 'passkey' && selected.error === undefined) {
      setTimeout(() => void this.usePasskey(selected), 0);
      return;
    }
    // A username field next to a discoverable passkey: offer the passkeys in its autofill. The
    // request waits until an input with `autocomplete="username webauthn"` is focused.
    const passkey = phase.challenges.find((c) => c.type === 'passkey' && c.params?.discoverable);
    const hasUsername = phase.challenges.some((c) => c.type === 'username');
    if ((this.options.passkeyAutofill ?? true) && hasUsername && passkey !== undefined && this.autofill === undefined) {
      void this.startAutofill(passkey);
    }
    if ((this.options.pollPush ?? true) && selected.type === 'push' && selected.params.isPending) {
      this.pushTimer = setTimeout(() => {
        this.pushTimer = undefined;
        void this.perform(() => this.requireFlow().respond({ kind: 'pushPoll' }, selected), true);
      }, selected.params.pollInterval * 1000);
    }
  }

  private async startAutofill(passkey: Challenge): Promise<void> {
    if (passkey.type !== 'passkey' || passkey.params === undefined) return;
    if (!(await this.kc.passkeyPlatformSupportsAutofill())) return;
    this.stopAutofill();
    const controller = new AbortController();
    this.autofill = controller;
    // Resolves only when the user picks a passkey from the autofill list.
    void this.perform(
      () => this.kc.usePasskey(this.requireFlow(), passkey, { mediation: 'conditional', signal: controller.signal }),
      true
    );
  }

  private stopAutofill(): void {
    this.autofill?.abort();
    this.autofill = undefined;
  }

  private stopTimers(): void {
    this.stopAutofill();
    this.stopPush();
  }

  private stopPush(): void {
    if (this.pushTimer !== undefined) clearTimeout(this.pushTimer);
    this.pushTimer = undefined;
  }
}

/**
 * The entry to show: the one that just failed (it carries `error`), else the previously shown type
 * when it is still offered, else the first supported entry (server order = flow order).
 */
export function pick(challenges: Challenge[], previous: Challenge | undefined): Challenge {
  return (
    challenges.find((c) => c.error !== undefined && c.supported) ??
    (previous === undefined ? undefined : challenges.find((c) => c.type === previous.type && c.supported)) ??
    challenges.find((c) => c.supported) ??
    challenges[0]!
  );
}
