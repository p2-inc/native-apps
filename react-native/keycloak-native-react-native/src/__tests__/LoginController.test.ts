import { KeycloakNative, setNativeModuleForTesting } from '../KeycloakNative';
import {
  LoginController,
  pick,
  type NativeLoginResult,
} from '../ui/LoginController';
import { parseChallenge, type Challenge } from '../model';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

/** The twin of the native UI layers' model tests (`NativeLoginModelTests`), against transcripts. */
async function controllerFor(name: string) {
  setNativeModuleForTesting(new TranscriptNative(loadTranscript(name)));
  const kc = KeycloakNative.configure({
    issuer: 'http://localhost:8080/realms/demo',
    clientId: 'demo-native',
  });
  const flow = await kc.authentication.startLogin({
    scope: 'openid profile',
    deviceName: 'NativeAuthIT',
  });
  const results: NativeLoginResult[] = [];
  const controller = new LoginController(kc, flow, (r) => results.push(r));
  let notifications = 0;
  controller.subscribe(() => {
    notifications += 1;
  });
  return { controller, results, notifications: () => notifications };
}

function selected(controller: LoginController): Challenge {
  const phase = controller.state.phase;
  if (phase.kind !== 'challenges')
    throw new Error(`expected challenges, got ${phase.kind}`);
  return phase.selected;
}

afterEach(() => setNativeModuleForTesting(undefined));

describe('LoginController', () => {
  it('walks username, password and TOTP to an authorized result', async () => {
    const { controller, results, notifications } = await controllerFor(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    expect(controller.state.phase.kind).toBe('starting');
    await controller.startIfNeeded();
    await controller.startIfNeeded();
    expect(selected(controller).type).toBe('username');
    expect(controller.state.isSubmitting).toBe(false);

    await controller.submit(
      { kind: 'username', username: 'alice' },
      selected(controller)
    );
    expect(selected(controller).type).toBe('password');
    await controller.submit(
      { kind: 'password', password: 'secret' },
      selected(controller)
    );
    expect(selected(controller).type).toBe('totp');
    await controller.submit(
      { kind: 'totp', code: '123456' },
      selected(controller)
    );

    expect(controller.state.phase.kind).toBe('finished');
    expect(results).toHaveLength(1);
    expect(results[0]!.kind).toBe('authorized');
    expect(notifications()).toBeGreaterThan(4);
  });

  it('keeps the failed password challenge on screen with its error', async () => {
    const { controller, results } = await controllerFor(
      'NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds'
    );
    await controller.startIfNeeded();
    await controller.submit(
      { kind: 'username', username: 'alice' },
      selected(controller)
    );
    await controller.submit(
      { kind: 'password', password: 'wrong' },
      selected(controller)
    );
    expect(selected(controller).type).toBe('password');
    expect(selected(controller).error?.code).toBe('invalid_credential');
    expect(results).toHaveLength(0);
  });

  it('reports a terminal error as failed', async () => {
    const { controller, results } = await controllerFor(
      'NativeAuthIT.bruteForceLockEndsWithAccessDenied'
    );
    await controller.startIfNeeded();
    await controller.submit(
      { kind: 'username', username: 'erin' },
      selected(controller)
    );
    while (controller.state.phase.kind === 'challenges') {
      await controller.submit(
        { kind: 'password', password: 'wrong' },
        selected(controller)
      );
    }
    expect(results).toEqual([
      {
        kind: 'failed',
        error: expect.objectContaining({ code: 'access_denied' }),
      },
    ]);
  });

  it('opens the browser for a redirect_to_web step', async () => {
    const { controller, results } = await controllerFor(
      'RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt'
    );
    await controller.startIfNeeded();
    await controller.submit(
      { kind: 'username', username: 'frank' },
      selected(controller)
    );
    await controller.submit(
      { kind: 'password', password: 'secret' },
      selected(controller)
    );
    expect(controller.state.phase.kind).toBe('redirectToWeb');
    await controller.openBrowser();
    expect(results.map((r) => r.kind)).toEqual(['authorized']);
  });

  it('switches to an alternative of the current set only', async () => {
    const { controller } = await controllerFor(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    await controller.startIfNeeded();
    const before = selected(controller);
    controller.select(parseChallenge({ type: 'password', id: 'elsewhere' })!);
    expect(selected(controller)).toBe(before);
  });

  it('cancels once', async () => {
    const { controller, results } = await controllerFor(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    await controller.cancel();
    await controller.cancel();
    expect(results).toEqual([{ kind: 'cancelled' }]);
  });
});

describe('pick', () => {
  const c = (type: string, id: string, error = false) =>
    parseChallenge({
      type,
      id,
      ...(error ? { error: { code: 'invalid_credential' } } : {}),
    })!;

  it('prefers the failed entry, then the previous type, then the first supported one', () => {
    expect(
      pick([c('x_new', '0'), c('totp', '1'), c('otp', '2')], undefined).id
    ).toBe('1');
    expect(pick([c('totp', '1'), c('otp', '2')], c('otp', 'old')).id).toBe('2');
    expect(
      pick([c('totp', '1'), c('otp', '2', true)], c('totp', 'old')).id
    ).toBe('2');
    expect(pick([c('x_new', '0')], undefined).id).toBe('0');
  });
});
