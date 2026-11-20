import { KeycloakNative, setNativeModuleForTesting } from '../KeycloakNative';
import type { NativeLoginFlow } from '../KeycloakNative';
import { LoginController, type NativeLoginResult } from '../ui/LoginController';
import { parseFlowStep, type Challenge, type FlowStep } from '../model';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

/**
 * Application-initiated actions (spec/21): `authentication.requiredAction` sends `kc_action` as a
 * step-up with the stored session; the `authorized` step and the controller's result carry
 * `kcActionStatus`. Replayed from the transcripts of KcActionIT (twin of the native replay tests).
 */
const PARAMS = { scope: 'openid profile', deviceName: 'NativeAuthIT' };

function setup(name: string) {
  const native = new TranscriptNative(loadTranscript(name));
  setNativeModuleForTesting(native);
  const kc = KeycloakNative.configure({
    issuer: 'http://localhost:8080/realms/demo',
    clientId: 'demo-native',
  });
  return { native, kc };
}

function find(step: FlowStep, type: Challenge['type']): Challenge {
  if (step.kind !== 'challenges')
    throw new Error(`expected challenges, got ${step.kind}`);
  const c = step.challenges.find((x) => x.type === type);
  if (!c)
    throw new Error(`no ${type} in ${step.challenges.map((x) => x.type)}`);
  return c;
}

/** username → password → TOTP, then the credentials are stored natively. */
async function signIn(kc: KeycloakNative) {
  const flow = await kc.authentication.startLogin(PARAMS);
  let step = await flow.start();
  step = await flow.respond(
    { kind: 'username', username: 'alice' },
    find(step, 'username')
  );
  step = await flow.respond(
    { kind: 'password', password: 'alice-password' },
    find(step, 'password')
  );
  step = await flow.respond(
    { kind: 'totp', code: '000000' },
    find(step, 'totp')
  );
  if (step.kind !== 'authorized') throw new Error(step.kind);
  expect(step.kcActionStatus).toBeUndefined();
  await kc.credentialsManager.store(step.credentials);
}

afterEach(() => setNativeModuleForTesting(undefined));

describe('requiredAction', () => {
  it('changes the password right after signing in and signs out other devices', async () => {
    const { kc } = setup(
      'KcActionIT.aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd'
    );
    await signIn(kc); // the other device
    await signIn(kc); // this app
    const flow: NativeLoginFlow = await kc.authentication.requiredAction(
      'UPDATE_PASSWORD',
      PARAMS
    );
    let step = await flow.start();
    // Within the realm's maximum authentication age: straight to the action.
    const update = find(step, 'update_password');
    if (update.type !== 'update_password') throw new Error(update.type);
    expect(update.skippable).toBe(true);
    expect(update.params.logoutOtherSessions).toBe(true);
    step = await flow.respond(
      {
        kind: 'updatePassword',
        password: 'alice-new-password',
        confirm: 'alice-new-password',
        logoutOtherSessions: true,
      },
      update
    );
    expect(step.kind).toBe('authorized');
    if (step.kind === 'authorized') expect(step.kcActionStatus).toBe('success');
  });

  it('cancelling in the default controller reports cancelled after the forced re-authentication', async () => {
    const { kc } = setup(
      'KcActionIT.maxAgeZeroReauthenticatesAndCancellingKeepsThePassword'
    );
    await signIn(kc);
    const flow = await kc.authentication.requiredAction('UPDATE_PASSWORD', {
      ...PARAMS,
      maxAge: 0,
    });
    const results: NativeLoginResult[] = [];
    const c = new LoginController(kc, flow, (r) => results.push(r));
    await c.startIfNeeded();
    const shown = () => {
      const phase = c.state.phase;
      if (phase.kind !== 'challenges') throw new Error(phase.kind);
      return phase.selected;
    };
    await c.submit({ kind: 'password', password: 'alice-password' }, shown());
    await c.submit({ kind: 'totp', code: '000000' }, shown());
    expect(shown().type).toBe('update_password');
    await c.submit({ kind: 'skip' }, shown());
    expect(results).toEqual([
      expect.objectContaining({
        kind: 'authorized',
        kcActionStatus: 'cancelled',
      }),
    ]);
  });

  it('an action that cannot be initiated reports error', async () => {
    const { kc } = setup(
      'KcActionIT.anActionThatCannotBeInitiatedReportsError'
    );
    await signIn(kc);
    for (const action of ['TERMS_AND_CONDITIONS', 'no-such-action']) {
      const flow = await kc.authentication.requiredAction(action, PARAMS);
      const step = await flow.start();
      if (step.kind !== 'authorized')
        throw new Error(`${action}: ${step.kind}`);
      expect(step.kcActionStatus).toBe('error');
      await kc.credentialsManager.store(step.credentials);
    }
  });

  it('passes an unknown kcActionStatus through', () => {
    const step = parseFlowStep({
      kind: 'authorized',
      credentials: { accessToken: 'a', tokenType: 'Bearer', expiresAt: 1 },
      kcActionStatus: 'later',
    });
    if (step.kind !== 'authorized') throw new Error(step.kind);
    expect(step.kcActionStatus).toBe('later');
  });
});
