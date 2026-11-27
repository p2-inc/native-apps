import { afterEach, describe, expect, it, vi } from 'vitest';
import { LoginController, accessTokenClaims, type LoginResult } from '../src';
import {
  DEMO,
  DEMO_PASSKEY,
  IT_PARAMETERS,
  assertionFrom,
  authorized,
  form,
  replay,
  usernamePassword,
} from './support';

function waitFor(controller: LoginController, predicate: () => boolean): Promise<void> {
  return new Promise((resolve) => {
    if (predicate()) return resolve();
    const off = controller.subscribe(() => {
      if (predicate()) {
        off();
        resolve();
      }
    });
  });
}

function selectedType(controller: LoginController): string | undefined {
  const phase = controller.state.phase;
  return phase.kind === 'challenges' ? phase.selected.wireType : undefined;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('LoginController', () => {
  it('drives a login to the stored credentials', async () => {
    const { kc, transport } = replay(['NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'], DEMO, {
      range: [1, 5],
    });
    const results: LoginResult[] = [];
    const controller = new LoginController(kc, {
      mode: { kind: 'login', parameters: IT_PARAMETERS },
      onResult: (r) => results.push(r),
    });
    await controller.start();
    expect(selectedType(controller)).toBe('username');
    const current = () => {
      const phase = controller.state.phase;
      if (phase.kind !== 'challenges') throw new Error('no challenge on screen');
      return phase.selected;
    };
    await controller.submit({ kind: 'username', username: 'alice' }, current());
    await controller.submit({ kind: 'password', password: 'alice-password' }, current());
    expect(selectedType(controller)).toBe('totp');
    await controller.submit({ kind: 'totp', code: '000000' }, current());

    expect(results).toHaveLength(1);
    expect(results[0]!.kind).toBe('authorized');
    expect(controller.state.phase.kind).toBe('finished');
    expect(kc.credentialsManager().snapshot?.accessToken).toBeDefined();
    expect(transport.remaining).toBe(0);
  });

  it('runs an app-initiated action and reports its status', async () => {
    const name = 'KcActionIT.aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd';
    const { kc, transport } = replay([name], DEMO, { seqs: [6, 7, 8, 9, 10, 11, 12, 13] });
    const flow = await kc.authentication().startLogin(IT_PARAMETERS);
    let step = await usernamePassword(flow, 'alice', 'alice-password');
    if (step.kind !== 'challenges') throw new Error('expected totp');
    step = await flow.respond({ kind: 'totp', code: '000000' }, step.challenges[0]!);
    await kc.credentialsManager().store(authorized(step).credentials);

    const results: LoginResult[] = [];
    const controller = new LoginController(kc, {
      mode: { kind: 'requiredAction', alias: 'UPDATE_PASSWORD', parameters: IT_PARAMETERS },
      onResult: (r) => results.push(r),
    });
    await controller.start();
    const phase = controller.state.phase;
    if (phase.kind !== 'challenges' || phase.selected.type !== 'update_password') throw new Error('expected update_password');
    expect(phase.selected.skippable).toBe(true);
    expect(phase.selected.params.logoutOtherSessions).toBe(true);
    await controller.submit(
      { kind: 'updatePassword', password: 'new-password', confirm: 'new-password', logoutOtherSessions: true },
      phase.selected
    );
    expect(results).toHaveLength(1);
    const result = results[0]!;
    expect(result.kind === 'authorized' && result.kcActionStatus).toBe('success');
    expect(transport.remaining).toBe(0);
  });

  it('polls a pending push approval on its interval', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const { kc, transport } = replay(['PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch'], DEMO, {
      range: [1, 5],
    });
    const controller = new LoginController(kc, { mode: { kind: 'login', parameters: IT_PARAMETERS } });
    await controller.start();
    const pick = () => {
      const phase = controller.state.phase;
      if (phase.kind !== 'challenges') throw new Error('no challenges');
      return phase;
    };
    await controller.submit({ kind: 'username', username: 'alice' }, pick().selected);
    await controller.submit({ kind: 'password', password: 'alice-password' }, pick().selected);
    const push = pick().challenges.find((c) => c.type === 'push')!;
    controller.select(push);
    expect(selectedType(controller)).toBe('push');
    await controller.submit({ kind: 'pushResend' }, push);
    const pending = pick().selected;
    expect(pending.type === 'push' && pending.params.isPending && pending.params.userVerificationNumber).toBe('88');
    expect(transport.remaining).toBe(1);

    // After poll_interval (3 s) the controller polls by itself.
    await vi.advanceTimersByTimeAsync(3000);
    // The poll signs a DPoP proof (real WebCrypto work): let it settle.
    for (let i = 0; i < 100 && transport.remaining > 0; i++) await new Promise((r) => setImmediate(r));
    expect(transport.remaining).toBe(0);
    expect(transport.sent.at(-1)!.body).toContain('action=poll');
    controller.dispose();
  });

  it('offers a discoverable passkey in the username autofill', async () => {
    const { kc, transport, transcripts, passkeys } = replay(['PasskeyIT.discoverableLoginWithUserHandle'], DEMO_PASSKEY, {
      range: [1, 4],
    });
    passkeys.autofill = true;
    passkeys.assertions.push(assertionFrom(form(transcripts[0]!, 2)));
    const controller = new LoginController(kc, { mode: { kind: 'login', parameters: IT_PARAMETERS } });
    await controller.start();
    // The autofill request resolved with the queued passkey (the user picked it from the list).
    await waitFor(controller, () => selectedType(controller) === 'totp');
    expect(passkeys.mediations).toEqual(['conditional']);
    const phase = controller.state.phase;
    if (phase.kind !== 'challenges') throw new Error('expected totp');
    expect(phase.context.username).toBe('alice');
    await controller.submit({ kind: 'totp', code: '777777' }, phase.selected);
    const finished = controller.state.phase;
    expect(finished.kind === 'finished' && finished.result.kind).toBe('authorized');
    if (finished.kind === 'finished' && finished.result.kind === 'authorized') {
      expect(accessTokenClaims(finished.result.credentials)?.preferred_username).toBe('alice');
    }
    expect(transport.remaining).toBe(0);
  });

  it('a terminal error finishes with failed', async () => {
    const { kc } = replay(['NativeAuthIT.expiredAuthSessionIsRejectedWithInvalidSession'], DEMO);
    const results: LoginResult[] = [];
    const controller = new LoginController(kc, {
      mode: { kind: 'login', parameters: IT_PARAMETERS },
      onResult: (r) => results.push(r),
    });
    await controller.start();
    const phase = controller.state.phase;
    if (phase.kind !== 'challenges') throw new Error('expected username');
    await controller.submit({ kind: 'username', username: 'alice' }, phase.selected);
    expect(results.map((r) => (r.kind === 'failed' ? r.error.code : r.kind))).toEqual(['invalid_session']);
  });

  void authorized;
});
