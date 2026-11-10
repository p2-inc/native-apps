import {
  KeycloakNative,
  NativeLoginFlow,
  setNativeModuleForTesting,
} from '../KeycloakNative';
import { NativeAuthError, type FlowStep } from '../model';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

/**
 * Drives the TypeScript API against recorded transcripts (the twins of the Swift `TranscriptReplayTests`
 * and the Kotlin `TranscriptReplay`): the request each answer causes must match the recording, and the
 * recorded responses must come back as the right typed steps.
 */
function replay(name: string, clientId = 'demo-native') {
  const native = new TranscriptNative(loadTranscript(name));
  setNativeModuleForTesting(native);
  const kc = KeycloakNative.configure({
    issuer: 'http://localhost:8080/realms/demo/',
    clientId,
  });
  return { native, kc };
}

function challenges(step: FlowStep) {
  if (step.kind !== 'challenges')
    throw new Error(`expected challenges, got ${step.kind}`);
  return step;
}

afterEach(() => setNativeModuleForTesting(undefined));

const loginParameters = { scope: 'openid profile', deviceName: 'NativeAuthIT' };

describe('transcript replay', () => {
  it('happy path: username, password, TOTP, tokens', async () => {
    const { native, kc } = replay(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    expect(kc.issuer).toBe('http://localhost:8080/realms/demo');
    const flow = await kc.authentication.startLogin(loginParameters);
    expect(flow.state).toBe('idle');

    let step = challenges(await flow.start());
    const username = step.challenges[0]!;
    expect(username.type).toBe('username');
    expect(step.context.clientName).toBeDefined();
    expect(flow.state).toBe('awaitingAnswer');

    step = challenges(
      await flow.respond({ kind: 'username', username: 'alice' }, username)
    );
    const password = step.challenges[0]!;
    if (password.type !== 'password') throw new Error(password.type);
    expect(password.params.usernameKnown).toBe(true);
    expect(step.context.username).toBe('alice');

    step = challenges(
      await flow.respond({ kind: 'password', password: 'secret' }, password)
    );
    const totp = step.supportedChallenges.find((c) => c.type === 'totp');
    if (totp?.type !== 'totp') throw new Error('no totp');
    expect(totp.params.digits).toBe(6);

    const done = await flow.respond({ kind: 'totp', code: '123456' }, totp);
    if (done.kind !== 'authorized') throw new Error(done.kind);
    expect(done.credentials.accessToken.split('.')).toHaveLength(3);
    expect(done.credentials.hasRefreshToken).toBe(true);
    expect(flow.state).toBe('finished');

    await kc.credentialsManager.store(done.credentials);
    expect(native.stored?.accessToken).toBe(done.credentials.accessToken);
    expect((await kc.credentialsManager.credentials()).accessToken).toBe(
      done.credentials.accessToken
    );
    const headers = await kc.resourceRequestHeaders(
      'GET',
      'https://api.example.com/me'
    );
    expect(headers.Authorization).toMatch(/^Bearer /);
    await kc.credentialsManager.logout();
    expect(await kc.credentialsManager.stored()).toBeNull();
  });

  it('a wrong password comes back as an inline error on a new set', async () => {
    const { kc } = replay(
      'NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds'
    );
    const flow = await kc.authentication.startLogin(loginParameters);
    let step = challenges(await flow.start());
    step = challenges(
      await flow.respond(
        { kind: 'username', username: 'alice' },
        step.challenges[0]!
      )
    );
    step = challenges(
      await flow.respond(
        { kind: 'password', password: 'wrong' },
        step.challenges[0]!
      )
    );
    const retry = step.challenges[0]!;
    expect(retry.type).toBe('password');
    expect(retry.error?.code).toBe('invalid_credential');
    step = challenges(
      await flow.respond({ kind: 'password', password: 'right' }, retry)
    );
    expect(step.supportedChallenges.some((c) => c.type === 'totp')).toBe(true);
  });

  it('refuses answers for a challenge outside the pending set or of another type', async () => {
    const { kc } = replay(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    const flow = await kc.authentication.startLogin(loginParameters);
    await expect(
      flow.respond({ kind: 'username', username: 'x' }, { id: 'x' } as never)
    ).rejects.toMatchObject({ code: 'flow_state' });
    const step = challenges(await flow.start());
    const username = step.challenges[0]!;
    await expect(
      flow.respond({ kind: 'password', password: 'x' }, username)
    ).rejects.toMatchObject({ code: 'unsupported_challenge' });
    await expect(
      flow.respond({ kind: 'skip' }, username)
    ).rejects.toMatchObject({ code: 'flow_state' });
    await expect(
      flow.respond(
        { kind: 'username', username: 'x' },
        { ...username, id: 'stale' }
      )
    ).rejects.toMatchObject({ code: 'flow_state' });
    await expect(flow.start()).rejects.toBeInstanceOf(NativeAuthError);
  });

  it('a redirect_to_web step finishes the flow and the browser fallback returns credentials', async () => {
    const { native, kc } = replay(
      'RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt'
    );
    const flow = await kc.authentication.startLogin(loginParameters);
    let step = challenges(await flow.start());
    step = challenges(
      await flow.respond(
        { kind: 'username', username: 'frank' },
        step.challenges[0]!
      )
    );
    const redirect = await flow.respond(
      { kind: 'password', password: 'secret' },
      step.challenges[0]!
    );
    if (redirect.kind !== 'redirectToWeb') throw new Error(redirect.kind);
    expect(redirect.request.redirectUri).toBe('demoapp://auth/callback');
    expect(redirect.request.requestUri).toMatch(
      /^urn:ietf:params:oauth:request_uri:/
    );
    expect(flow.state).toBe('finished');

    const credentials = await kc.webFallback.complete(redirect.request, flow);
    expect(credentials.accessToken.length).toBeGreaterThan(0);
    await kc.credentialsManager.store(credentials);
    expect(native.stored?.accessToken).toBe(credentials.accessToken);
  });

  it('a brute-force lock ends the flow with access_denied', async () => {
    const { kc } = replay('NativeAuthIT.bruteForceLockEndsWithAccessDenied');
    const flow = await kc.authentication.startLogin(loginParameters);
    let step = challenges(await flow.start());
    step = challenges(
      await flow.respond(
        { kind: 'username', username: 'erin' },
        step.challenges[0]!
      )
    );
    let error: unknown;
    try {
      for (;;)
        step = challenges(
          await flow.respond(
            { kind: 'password', password: 'wrong' },
            step.challenges[0]!
          )
        );
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(NativeAuthError);
    expect((error as NativeAuthError).code).toBe('access_denied');
    expect(flow.state).toBe('finished');
  });

  it('alternatives come in one set', async () => {
    const { kc } = replay(
      'NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered',
      'demo-native-alt'
    );
    const flow: NativeLoginFlow =
      await kc.authentication.startLogin(loginParameters);
    let step = challenges(await flow.start());
    step = challenges(
      await flow.respond(
        { kind: 'username', username: 'alice' },
        step.challenges[0]!
      )
    );
    expect(step.challenges.length).toBeGreaterThan(1);
    expect(step.challenges.map((c) => c.type)).toEqual(
      expect.arrayContaining(['password'])
    );
  });
});
