/**
 * Contract tests: the web SDK drives each recorded scenario through `MockTransport`, which rejects any
 * request that differs from what the integration test sent and answers with what Keycloak sent. Twin
 * of the Kotlin `TranscriptReplayTest` and `Phase2ReplayTest`.
 */
import { describe, expect, it } from 'vitest';
import {
  KeycloakWeb,
  NativeAuthErrorCode,
  accessTokenClaims,
  parseChallengeResponse,
  type Credentials,
} from '../src';
import {
  DEMO,
  DEMO_ALT,
  DEMO_PASSKEY,
  IT_PARAMETERS,
  METADATA,
  MockPresenter,
  MockTransport,
  allTranscripts,
  assertionFrom,
  attestationFrom,
  authorized,
  challenges,
  exchange,
  expectError,
  form,
  loadTranscript,
  replay,
  requireChallenge,
  responseOf,
  types,
  usernamePassword,
} from './support';

const username = (c: Credentials) => accessTokenClaims(c)?.preferred_username;

describe('username, password and TOTP', () => {
  it('happy path yields tokens without redirect_uri', async () => {
    const { kc, transport, transcripts } = replay(
      ['NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'],
      DEMO,
      { range: [1, 5] }
    );
    const t = transcripts[0]!;
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);

    let step = await flow.start();
    const user = requireChallenge(step, 'username');
    expect(challenges(step)).toHaveLength(1);
    expect(user.required).toBe(true);
    expect(user.params.allowEmail).toBe(true);
    expect(flow.expiresIn).toBe(1800);

    step = await flow.respond({ kind: 'username', username: 'alice' }, user);
    if (step.kind !== 'challenges') throw new Error('expected challenges');
    expect(step.context.username).toBe('alice');
    expect(step.context.displayName).toBe('Alice Example');
    const password = requireChallenge(step, 'password');
    expect(password.params.usernameKnown).toBe(true);

    step = await flow.respond({ kind: 'password', password: 'alice-password' }, password);
    const totp = requireChallenge(step, 'totp');
    expect(types(step)).toEqual(['totp']);
    expect(totp.params.digits).toBe(6);
    expect(totp.params.credentialLabels).toEqual(['Phone']);

    step = await flow.respond({ kind: 'totp', code: '000000' }, totp);
    const credentials = authorized(step).credentials;
    const tokenJson = exchange(t, 5).response.json as Record<string, string>;
    expect(credentials.accessToken).toBe(tokenJson.access_token);
    expect(credentials.refreshToken).toBe(tokenJson.refresh_token);
    expect(credentials.idToken).toBe(tokenJson.id_token);
    expect(credentials.authSession).toBe((exchange(t, 4).response.json as Record<string, string>).auth_session);
    expect(username(credentials)).toBe('alice');
    expect(flow.state).toBe('finished');
    expect(transport.remaining).toBe(0);

    // Every challenge and token request carried a DPoP proof; the exchange has no redirect_uri.
    for (const request of transport.sent.slice(1)) expect(request.headers.DPoP?.split('.')).toHaveLength(3);
    expect(transport.sent.at(-1)!.body).not.toContain('redirect_uri');

    await kc.credentialsManager().store(credentials);
    expect(await kc.credentialsManager().authSession()).toBe(credentials.authSession);
  });

  it('a password-only user skips the conditional second factor', async () => {
    const { kc, transport } = replay(['NativeAuthIT.passwordOnlyUserSkipsConditionalSecondFactor'], DEMO);
    const step = await usernamePassword(await kc.authentication().startLogin(IT_PARAMETERS), 'bob', 'bob-password');
    expect(username(authorized(step).credentials)).toBe('bob');
    expect(transport.remaining).toBe(0);
  });

  it('a wrong password rechallenges with an error descriptor', async () => {
    const { kc } = replay(['NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds'], DEMO);
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await usernamePassword(flow, 'alice', 'wrong');
    const again = requireChallenge(step, 'password');
    expect(again.error?.code).toBe('invalid_credential');
    step = await flow.respond({ kind: 'password', password: 'alice-password' }, again);
    expect(types(step)).toEqual(['totp']);
  });

  it('an expired auth_session ends the flow', async () => {
    const { kc } = replay(['NativeAuthIT.expiredAuthSessionIsRejectedWithInvalidSession'], DEMO);
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    const step = await flow.start();
    const error = await expectError(() =>
      flow.respond({ kind: 'username', username: 'alice' }, requireChallenge(step, 'username'))
    );
    expect(error.code).toBe(NativeAuthErrorCode.invalidSession);
    expect(flow.state).toBe('finished');
  });

  it('cancel invalidates the session', async () => {
    const { kc, transport } = replay(['NativeAuthIT.cancelledAuthSessionCannotBeReused'], DEMO, { range: [1, 2] });
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    await flow.start();
    await flow.cancel();
    expect(flow.state).toBe('finished');
    expect(transport.remaining).toBe(0);
    expect(transport.sent.at(-1)!.body).toContain('action=cancel');
  });

  it('brute force ends with access_denied', async () => {
    const { kc, transport } = replay(['NativeAuthIT.bruteForceLockEndsWithAccessDenied'], DEMO, { range: [1, 5] });
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await usernamePassword(flow, 'erin', 'wrong-1');
    let error;
    for (let i = 2; i < 10 && error === undefined; i++) {
      try {
        step = await flow.respond({ kind: 'password', password: `wrong-${i}` }, requireChallenge(step, 'password'));
      } catch (e) {
        error = e as { code: string };
      }
    }
    expect(error?.code).toBe(NativeAuthErrorCode.accessDenied);
    expect(flow.state).toBe('finished');
    expect(transport.remaining).toBe(0);
  });
});

describe('tokens', () => {
  it('refresh, logout and revoke', async () => {
    const { kc, transport } = replay(['NativeAuthIT.tokensCanBeRefreshedLoggedOutAndRevoked'], DEMO);
    const manager = kc.credentialsManager();
    const credentials = authorized(
      await usernamePassword(await kc.authentication().startLogin(IT_PARAMETERS), 'bob', 'bob-password')
    ).credentials;

    // Expired credentials trigger exactly one refresh for concurrent callers.
    const expired = { ...credentials, expiresAt: Date.now() - 1000 };
    await manager.store(expired);
    const [a, b] = await Promise.all([manager.credentials(), manager.credentials()]);
    expect(a).toBe(b);
    expect(a.accessToken).not.toBe(expired.accessToken);
    expect(a.authSession).toBe(credentials.authSession);

    await kc.tokens.logout(a.refreshToken!);
    expect((await expectError(() => kc.tokens.refresh(a))).code).toBe(NativeAuthErrorCode.invalidGrant);

    const fresh = authorized(
      await usernamePassword(await kc.authentication().startLogin(IT_PARAMETERS), 'bob', 'bob-password')
    ).credentials;
    await kc.tokens.revoke(fresh.refreshToken!);

    await manager.store({ ...fresh, authSession: undefined, expiresAt: 0 });
    expect((await expectError(() => manager.credentials())).code).toBe(NativeAuthErrorCode.reauthenticationRequired);
    expect(await manager.hasSession()).toBe(false);
    expect(transport.remaining).toBe(0);
  });

  it('a reload restores the session from the persisted refresh token only', async () => {
    const name = 'NativeAuthIT.tokensCanBeRefreshedLoggedOutAndRevoked';
    const { kc, store } = replay([name], DEMO, { range: [1, 4] });
    const credentials = authorized(
      await usernamePassword(await kc.authentication().startLogin(IT_PARAMETERS), 'bob', 'bob-password')
    ).credentials;
    await kc.credentialsManager().store(credentials);

    // Only the refresh token and the post-login auth_session are persisted, never the access token.
    const persisted = await store.get<Record<string, unknown>>(kc.scopedKey('credentials'));
    expect(persisted?.refreshToken).toBe(credentials.refreshToken);
    expect(persisted?.authSession).toBe(credentials.authSession);
    expect(JSON.stringify(persisted)).not.toContain(credentials.accessToken);

    // "Reload": a new instance over the same store refreshes with the persisted token (exchange #5).
    const t = loadTranscript(name);
    const transport = new MockTransport([exchange(loadTranscript(METADATA), 1), exchange(t, 5)]);
    const reloaded = KeycloakWeb.configure({ issuer: kc.issuer, clientId: DEMO, transport, storage: store, onWarning: () => {} });
    expect(reloaded.credentialsManager().snapshot).toBeUndefined();
    const restored = await reloaded.restore();
    expect(restored?.accessToken).toBe((exchange(t, 5).response.json as Record<string, string>).access_token);
    expect(restored?.authSession).toBe(credentials.authSession);
    expect(username(restored!)).toBe('bob');
    expect(transport.remaining).toBe(0);
  });

  it('restore without a stored session is undefined and sends nothing', async () => {
    const { kc, transport } = replay(['NativeAuthIT.passwordOnlyUserSkipsConditionalSecondFactor'], DEMO);
    expect(await kc.restore()).toBeUndefined();
    expect(transport.sent).toHaveLength(0);
  });
});

describe('passkeys', () => {
  it('allow-list login after the username offers passkey and password', async () => {
    const { kc, transport, transcripts, passkeys } = replay(
      ['PasskeyIT.allowListLoginAfterUsernameOffersPasskeyAndPassword'],
      DEMO,
      { range: [1, 5] }
    );
    const recorded = assertionFrom(form(transcripts[0]!, 3));
    passkeys.assertions.push(recorded);
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await flow.start();
    step = await flow.respond({ kind: 'username', username: 'alice' }, requireChallenge(step, 'username'));
    expect(types(step)).toEqual(['passkey', 'password']);
    const passkey = requireChallenge(step, 'passkey');
    expect(passkey.required).toBe(false);
    expect(passkey.params?.rpId).toBe('localhost');
    expect(passkey.params?.discoverable).toBe(false);
    expect(passkey.params?.allowCredentials.some((c) => c.id === recorded.credentialId)).toBe(true);

    step = await kc.usePasskey(flow, passkey);
    expect(passkeys.assertParams[0]!.challenge).toBe(passkey.params!.challenge);
    expect(types(step)).toEqual(['totp']);
    step = await flow.respond({ kind: 'totp', code: '666666' }, requireChallenge(step, 'totp'));
    expect(authorized(step).credentials.authSession).toBeDefined();
    expect(transport.remaining).toBe(0);
  });

  it('discoverable login with a user handle', async () => {
    const { kc, transport, transcripts, passkeys } = replay(['PasskeyIT.discoverableLoginWithUserHandle'], DEMO_PASSKEY, {
      range: [1, 4],
    });
    const recorded = assertionFrom(form(transcripts[0]!, 2));
    expect(recorded.userHandle).toBeDefined();
    passkeys.assertions.push(recorded);
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await flow.start();
    expect(types(step)).toEqual(['passkey', 'username']);
    const passkey = requireChallenge(step, 'passkey');
    expect(passkey.params?.discoverable).toBe(true);
    step = await kc.usePasskey(flow, passkey, { mediation: 'conditional' });
    expect(passkeys.mediations).toEqual(['conditional']);
    if (step.kind !== 'challenges') throw new Error('expected totp');
    expect(step.context.username).toBe('alice');
    step = await flow.respond({ kind: 'totp', code: '777777' }, requireChallenge(step, 'totp'));
    expect(username(authorized(step).credentials)).toBe('alice');
    expect(transport.remaining).toBe(0);
  });

  it('registers a passkey through the authenticated endpoints after login', async () => {
    const { kc, transport, transcripts, passkeys } = replay(
      ['PasskeyIT.registerThroughAuthenticatedEndpointsAfterPasswordTotpLogin'],
      DEMO,
      { range: [1, 7] }
    );
    const recorded = attestationFrom(exchange(transcripts[0]!, 7).request.json!);
    passkeys.attestations.push(recorded);
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await usernamePassword(flow, 'alice', 'alice-password');
    step = await flow.respond({ kind: 'totp', code: '888888' }, requireChallenge(step, 'totp'));
    await kc.credentialsManager().store(authorized(step).credentials);

    const registered = await kc.registerNewPasskey('Second device');
    expect(registered.credentialId).toBe(recorded.credentialId);
    expect(registered.label).toBe('Second device');
    const options = passkeys.registerParams[0]!;
    expect(options.rp).toEqual({ id: 'localhost', name: 'Native Auth Demo' });
    expect(options.user.name).toBe('alice');
    expect(options.pubKeyCredParams).toEqual([-7, -257]);
    const finish = transport.sent.at(-1)!;
    expect(finish.headers.Authorization?.startsWith('Bearer ')).toBe(true);
    expect(finish.headers['Content-Type']).toBe('application/json');
    expect(transport.remaining).toBe(0);
  });
});

describe('step-up and app-initiated actions', () => {
  it('step-up to level 2 asks only for TOTP and keeps the user session', async () => {
    const { kc, transport } = replay(['StepUpIT.stepUpToLevel2AsksOnlyForTotpAndKeepsTheUserSession'], 'demo-native-stepup');
    const level1 = authorized(
      await usernamePassword(await kc.authentication().startLogin(IT_PARAMETERS), 'alice', 'alice-password')
    ).credentials;
    expect(accessTokenClaims(level1)?.acr).toBe('1');
    await kc.credentialsManager().store(level1);

    const stepUp = await kc.authentication().stepUp({ acrValues: '2', scope: 'openid profile', deviceName: 'NativeAuthIT' });
    expect(stepUp.isStepUp).toBe(true);
    let step = await stepUp.start();
    if (step.kind !== 'challenges') throw new Error('expected totp');
    expect(types(step)).toEqual(['totp']);
    expect(step.context.stepUp).toBe(true);
    expect(step.context.acrRequested).toBe('2');
    step = await stepUp.respond({ kind: 'totp', code: '000000' }, requireChallenge(step, 'totp'));
    const level2 = authorized(step).credentials;
    expect(accessTokenClaims(level2)?.acr).toBe('2');
    expect(accessTokenClaims(level2)?.sid).toBe(accessTokenClaims(level1)?.sid);
    expect(level2.authSession).not.toBe(level1.authSession);
    await kc.credentialsManager().store(level2);
    // The scenario continues past what this test drives; what it drove matched.
    expect(transport.sent.length).toBeGreaterThan(4);
  });

  it('step-up without a stored session is credentials_not_found', async () => {
    const { kc } = replay(['NativeAuthIT.passwordOnlyUserSkipsConditionalSecondFactor'], DEMO);
    expect((await expectError(() => kc.authentication().stepUp())).code).toBe(NativeAuthErrorCode.credentialsNotFound);
  });
});

describe('redirect_to_web', () => {
  it('a pending non-native required action finishes in the popup', async () => {
    const t = loadTranscript('RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt');
    const tokenExchange = t.exchanges.find((e) => e.request.path.endsWith('/token'))!;
    const code = tokenExchange.request.form!.code!;
    let state = 'STATE';
    const presenter = new MockPresenter(() => `demoapp://auth/callback?state=${state}&code=${code}`);
    const { kc, transport } = replay([t.test], DEMO, { seqs: [1, 2, 3, tokenExchange.seq], presenter });
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    const step = await usernamePassword(flow, 'frank', 'frank-password');
    if (step.kind !== 'redirectToWeb') throw new Error(`expected redirectToWeb, got ${step.kind}`);
    expect(step.request.reason).toBe('required_action:UPDATE_PROFILE');
    expect(step.request.redirectUri).toBe('demoapp://auth/callback');
    expect(flow.state).toBe('finished');
    state = step.request.state!;

    const credentials = await kc.webFallback().complete(step.request, flow);
    expect(username(credentials)).toBe('frank');
    const opened = new URL(presenter.opened[0]!.url);
    expect(opened.pathname.endsWith('/protocol/openid-connect/auth')).toBe(true);
    expect(opened.searchParams.get('client_id')).toBe(DEMO);
    expect(opened.searchParams.get('request_uri')?.startsWith('urn:ietf:params:oauth:request_uri:')).toBe(true);
    expect(transport.sent.at(-1)!.body).toContain('redirect_uri=demoapp%3A%2F%2Fauth%2Fcallback');
    expect(transport.remaining).toBe(0);
  });

  it('a callback with the wrong state is refused', async () => {
    const t = loadTranscript('RedirectToWebIT.pendingNonNativeRequiredActionRedirectsToWebAndTheBrowserFlowCompletesIt');
    const presenter = new MockPresenter(() => 'demoapp://auth/callback?state=forged&code=x');
    const { kc } = replay([t.test], DEMO, { seqs: [1, 2, 3], presenter });
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    const step = await usernamePassword(flow, 'frank', 'frank-password');
    if (step.kind !== 'redirectToWeb') throw new Error('expected redirectToWeb');
    expect((await expectError(() => kc.webFallback().complete(step.request, flow))).code).toBe(
      NativeAuthErrorCode.invalidResponse
    );
  });
});

describe('every transcript parses', () => {
  it('each challenge endpoint response maps to an outcome or a coded error', () => {
    for (const name of allTranscripts()) {
      if (name === 'README') continue;
      const t = loadTranscript(name);
      for (const e of t.exchanges) {
        if (!e.request.path.endsWith('/native-auth/challenge')) continue;
        try {
          const outcome = parseChallengeResponse(responseOf(e.response));
          expect(['code', 'challenges', 'redirectToWeb']).toContain(outcome.kind);
        } catch (error) {
          expect((error as { code?: string }).code, `${name} #${e.seq}`).toBeTruthy();
        }
      }
    }
  });
});
