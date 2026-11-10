import type { KeycloakNative, NativeLoginFlow } from '../KeycloakNative';
import {
  NativeAuthError,
  NativeAuthErrorCode,
  type Challenge,
  type ChallengeAnswer,
  type Credentials,
  type FlowContext,
  type FlowStep,
  type PushProviderRegistration,
  type RedirectToWebRequest,
  type SavedPassword,
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
  /** A user-facing error that is not attached to a challenge (network, passkey failure…). */
  message?: string;
}

export interface LoginControllerOptions {
  /** Run the passkey prompt as soon as a set shows `passkey` (spec/05 §4). Default `false`. */
  autoSelectPasskey?: boolean;
  /** The default `username` and `password` screens show "Use a saved password". Default `true`. */
  offerSavedPasswords?: boolean;
  /**
   * After an authorized login, offer the typed password to the password manager (Android's
   * Credential Manager prompt; iOS saves through AutoFill on its own). Default `true`.
   */
  offerToSavePassword?: boolean;
  /**
   * Where push messages reach this device, for a `push_enrollment` challenge: for example
   * `{type: 'fcm', id: await messaging().getToken()}`. Without it the device enrolls with `none` and
   * reads its approvals itself.
   */
  pushRegistration?: () => Promise<PushProviderRegistration>;
}

/** Errors that leave the challenge set on screen with an inline message. */
const RECOVERABLE: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.networkError,
  NativeAuthErrorCode.webFallbackFailed,
  NativeAuthErrorCode.passkeyFailed,
  NativeAuthErrorCode.passkeyUnavailable,
  NativeAuthErrorCode.rpIdMismatch,
  NativeAuthErrorCode.savedPasswordUnavailable,
  NativeAuthErrorCode.dpopKeyError,
  NativeAuthErrorCode.flowState,
]);

/** Errors that are not a failure at all: the user closed a sheet or the browser. */
const DISMISSED: ReadonlySet<string> = new Set([
  NativeAuthErrorCode.passkeyCancelled,
  NativeAuthErrorCode.webFallbackCancelled,
  NativeAuthErrorCode.savedPasswordCancelled,
]);

/**
 * The state behind `NativeLoginScreen`, the twin of the native `NativeLoginModel`s: drives the flow,
 * picks the screen, runs the platform ceremonies through the native module, and reports the result.
 * Plain TypeScript with a subscription, so it is tested without rendering (and against the recorded
 * transcripts).
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
  readonly autoSelectPasskey: boolean;
  readonly offersSavedPasswords: boolean;
  private readonly offersToSavePassword: boolean;
  private readonly pushRegistration?: () => Promise<PushProviderRegistration>;
  /**
   * The password of a saved password picked on the `username` step, answered once to the `password`
   * challenge that follows (and dropped if none does).
   */
  private pendingSavedPassword: string | undefined;
  /** A typed password (or one set through `update_password`), offered for saving once authorized. */
  private typedPassword: SavedPassword | undefined;
  private typedUsername: string | undefined;

  constructor(
    readonly kc: KeycloakNative,
    readonly flow: NativeLoginFlow,
    private readonly onResult: (result: NativeLoginResult) => void,
    options: LoginControllerOptions = {}
  ) {
    this.autoSelectPasskey = options.autoSelectPasskey ?? false;
    this.offersSavedPasswords = options.offerSavedPasswords ?? true;
    this.offersToSavePassword = options.offerToSavePassword ?? true;
    this.pushRegistration = options.pushRegistration;
  }

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
    switch (answer.kind) {
      case 'username':
        this.typedUsername = answer.username;
        break;
      case 'password':
      case 'updatePassword':
        this.remember(answer.password);
        break;
    }
    return this.perform(() => this.flow.respond(answer, challenge));
  }

  /** Runs the platform passkey prompt for a `passkey` challenge and submits the assertion. */
  usePasskey(
    challenge: Challenge,
    preferImmediatelyAvailableCredentials = false
  ): Promise<void> {
    if (challenge.type !== 'passkey' || challenge.params === undefined)
      return Promise.resolve();
    return this.perform(() =>
      this.flow.usePasskey(challenge, { preferImmediatelyAvailableCredentials })
    );
  }

  /** Runs the platform registration for a `passkey_registration` challenge and submits it. */
  registerPasskey(challenge: Challenge, label?: string): Promise<void> {
    if (
      challenge.type !== 'passkey_registration' ||
      challenge.params === undefined
    )
      return Promise.resolve();
    return this.perform(() => this.flow.registerPasskey(challenge, label));
  }

  /** Enrolls this device on a `push_enrollment` challenge (spec/03 §4.15). */
  enrollPush(challenge: Challenge, deviceLabel: string): Promise<void> {
    if (challenge.type !== 'push_enrollment') return Promise.resolve();
    return this.perform(async () => {
      const registration =
        this.pushRegistration === undefined
          ? { type: 'none' }
          : await this.pushRegistration();
      return this.flow.enrollPush(challenge, deviceLabel, registration);
    });
  }

  /**
   * Shows the system sheet of saved passwords. On a `username` challenge the picked username is
   * submitted and its password answers the `password` challenge that follows; on a `password`
   * challenge the password is submitted. Closing the sheet leaves the screen as it was.
   */
  useSavedPassword(challenge: Challenge): Promise<void> {
    return this.perform(async () => {
      const saved = await this.kc.pickSavedPassword();
      // A picked password is already saved: it is not offered for saving again.
      this.typedPassword = undefined;
      if (challenge.type === 'password') {
        return this.flow.respond(
          { kind: 'password', password: saved.password },
          challenge
        );
      }
      this.pendingSavedPassword = saved.password;
      return this.flow.respond(
        { kind: 'username', username: saved.username },
        challenge
      );
    });
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

  private remember(password: string): void {
    const phase = this.stateValue.phase;
    const username =
      (phase.kind === 'challenges' ? phase.context.username : undefined) ??
      this.typedUsername;
    if (username !== undefined) this.typedPassword = { username, password };
  }

  private update(patch: Partial<LoginState>): void {
    this.stateValue = { ...this.stateValue, ...patch };
    this.listeners.forEach((l) => l());
  }

  private async perform(body: () => Promise<FlowStep>): Promise<void> {
    if (this.done) return;
    this.inFlight += 1;
    this.update({ isSubmitting: true, message: undefined });
    try {
      await this.apply(await body());
    } catch (e) {
      this.pendingSavedPassword = undefined;
      const error = NativeAuthError.from(e);
      if (DISMISSED.has(error.code)) {
        // The set stays; the user may pick another way (spec/12 D4).
      } else if (RECOVERABLE.has(error.code) && !this.flowIsOver()) {
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

  private flowIsOver(): boolean {
    return (
      this.flow.state === 'finished' &&
      this.stateValue.phase.kind !== 'redirectToWeb'
    );
  }

  private async apply(step: FlowStep): Promise<void> {
    switch (step.kind) {
      case 'challenges': {
        const challenges = step.challenges;
        if (challenges.length === 0) {
          throw new NativeAuthError(
            NativeAuthErrorCode.invalidResponse,
            'The server sent an empty challenge set'
          );
        }
        // A password that came back with an error was wrong: never offer it for saving.
        if (
          challenges.some((c) => c.type === 'password' && c.error !== undefined)
        )
          this.typedPassword = undefined;
        const savedPassword = this.pendingSavedPassword;
        if (savedPassword !== undefined) {
          this.pendingSavedPassword = undefined;
          const password = challenges.find(
            (c) => c.type === 'password' && c.error === undefined
          );
          if (password !== undefined) {
            this.update({
              phase: {
                kind: 'challenges',
                challenges,
                context: step.context,
                selected: password,
              },
            });
            // In the same perform, so the screen stays busy until the answer is in.
            await this.apply(
              await this.flow.respond(
                { kind: 'password', password: savedPassword },
                password
              )
            );
            return;
          }
        }
        const previous =
          this.stateValue.phase.kind === 'challenges'
            ? this.stateValue.phase.selected
            : undefined;
        const selected = pick(challenges, previous);
        this.update({
          phase: {
            kind: 'challenges',
            challenges,
            context: step.context,
            selected,
          },
        });
        if (
          this.autoSelectPasskey &&
          selected.type === 'passkey' &&
          selected.error === undefined
        ) {
          // Not awaited: the prompt runs as its own submission once this one has settled.
          setTimeout(() => {
            this.usePasskey(selected);
          }, 0);
        }
        break;
      }
      case 'authorized': {
        this.done = true;
        const typed = this.typedPassword;
        this.typedPassword = undefined;
        if (typed !== undefined && this.offersToSavePassword) {
          try {
            await this.kc.savePassword(typed.username, typed.password);
          } catch {
            // Closing the prompt or having no password manager does not change the outcome.
          }
        }
        this.update({ phase: { kind: 'finished' } });
        this.onResult({ kind: 'authorized', credentials: step.credentials });
        break;
      }
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
