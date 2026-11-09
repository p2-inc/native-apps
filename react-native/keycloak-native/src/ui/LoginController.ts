import type { KeycloakNative, NativeLoginFlow } from '../KeycloakNative';
import {
  NativeAuthError,
  NativeAuthErrorCode,
  type Challenge,
  type ChallengeAnswer,
  type Credentials,
  type FlowContext,
  type FlowStep,
  type RedirectToWebRequest,
} from '../model';

/** Outcome of a `NativeLoginScreen` (spec/05 §4). The screen does not store the credentials. */
export type NativeLoginResult =
  | { kind: 'authorized'; credentials: Credentials }
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
  | { kind: 'finished' };

export interface LoginState {
  phase: LoginPhase;
  isSubmitting: boolean;
  /** A user-facing error that is not attached to a challenge (network, browser failure…). */
  message?: string;
}

/** Errors that leave the challenge set on screen with an inline message. */
const RECOVERABLE: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.networkError,
  NativeAuthErrorCode.webFallbackFailed,
  NativeAuthErrorCode.passkeyFailed,
  NativeAuthErrorCode.passkeyUnavailable,
  NativeAuthErrorCode.rpIdMismatch,
  NativeAuthErrorCode.savedPasswordUnavailable,
]);

/** Errors that are not a failure at all: the user closed a sheet or the browser. */
const DISMISSED: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.passkeyCancelled,
  NativeAuthErrorCode.webFallbackCancelled,
  NativeAuthErrorCode.savedPasswordCancelled,
]);

/**
 * The state behind `NativeLoginScreen`, the twin of the native `NativeLoginModel`s: drives the flow,
 * picks the screen, and reports the result. Plain TypeScript with a subscription, so it is tested
 * without rendering (and against the recorded transcripts).
 */
export class LoginController {
  private stateValue: LoginState = {
    phase: { kind: 'starting' },
    isSubmitting: false,
  };
  private readonly listeners = new Set<() => void>();
  private started = false;
  private done = false;
  private inFlight = 0;

  constructor(
    readonly kc: KeycloakNative,
    readonly flow: NativeLoginFlow,
    private readonly onResult: (result: NativeLoginResult) => void
  ) {}

  get state(): LoginState {
    return this.stateValue;
  }

  /** For `useSyncExternalStore`. */
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): LoginState => this.stateValue;

  startIfNeeded(): Promise<void> {
    if (this.started) return Promise.resolve();
    this.started = true;
    return this.perform(() => this.flow.start());
  }

  submit(answer: ChallengeAnswer, challenge: Challenge): Promise<void> {
    return this.perform(() => this.flow.respond(answer, challenge));
  }

  /** Shows another entry of the current set. */
  select(challenge: Challenge): void {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'challenges') return;
    if (!phase.challenges.some((c) => c.id === challenge.id)) return;
    this.update({
      phase: { ...phase, selected: challenge },
      message: undefined,
    });
  }

  /** Opens the system browser for a `redirectToWeb` step and exchanges the code. */
  openBrowser(): Promise<void> {
    const phase = this.stateValue.phase;
    if (phase.kind !== 'redirectToWeb') return Promise.resolve();
    return this.perform(async () => ({
      kind: 'authorized',
      credentials: await this.flow.completeWebFallback(phase.request),
    }));
  }

  async cancel(): Promise<void> {
    if (this.done) return;
    this.done = true;
    try {
      await this.flow.cancel();
    } catch {
      // Best effort.
    }
    this.update({ phase: { kind: 'finished' } });
    this.onResult({ kind: 'cancelled' });
  }

  // ---

  private update(patch: Partial<LoginState>): void {
    this.stateValue = { ...this.stateValue, ...patch };
    this.listeners.forEach((l) => l());
  }

  private async perform(body: () => Promise<FlowStep>): Promise<void> {
    if (this.done) return;
    this.inFlight += 1;
    this.update({ isSubmitting: true, message: undefined });
    try {
      this.apply(await body());
    } catch (e) {
      const error = NativeAuthError.from(e);
      if (DISMISSED.has(error.code)) {
        // The set stays; the user may pick another way.
      } else if (RECOVERABLE.has(error.code)) {
        this.update({ message: error.errorDescription ?? error.code });
      } else {
        // Terminal (invalid_session, access_denied, …): the flow is over.
        this.done = true;
        this.update({ phase: { kind: 'finished' } });
        this.onResult({ kind: 'failed', error });
      }
    } finally {
      this.inFlight -= 1;
      this.update({ isSubmitting: this.inFlight > 0 });
    }
  }

  private apply(step: FlowStep): void {
    switch (step.kind) {
      case 'challenges': {
        if (step.challenges.length === 0) {
          throw new NativeAuthError(
            NativeAuthErrorCode.invalidResponse,
            'The server sent an empty challenge set'
          );
        }
        const previous =
          this.stateValue.phase.kind === 'challenges'
            ? this.stateValue.phase.selected
            : undefined;
        this.update({
          phase: {
            kind: 'challenges',
            challenges: step.challenges,
            context: step.context,
            selected: pick(step.challenges, previous),
          },
        });
        break;
      }
      case 'authorized':
        this.done = true;
        this.update({ phase: { kind: 'finished' } });
        this.onResult({ kind: 'authorized', credentials: step.credentials });
        break;
      case 'redirectToWeb':
        this.update({
          phase: { kind: 'redirectToWeb', request: step.request },
        });
        break;
    }
  }
}

/**
 * The entry to show: the one that just failed (it carries `error`), else the previously shown type
 * when it is still offered, else the first supported entry (server order = flow order).
 */
export function pick(
  challenges: Challenge[],
  previous: Challenge | undefined
): Challenge {
  return (
    challenges.find((c) => c.error !== undefined && c.supported) ??
    (previous === undefined
      ? undefined
      : challenges.find((c) => c.type === previous.type && c.supported)) ??
    challenges.find((c) => c.supported) ??
    challenges[0]!
  );
}
