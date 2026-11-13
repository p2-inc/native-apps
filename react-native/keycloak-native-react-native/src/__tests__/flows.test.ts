import { KeycloakNative, setNativeModuleForTesting } from '../KeycloakNative';
import {
  LoginController,
  type LoginControllerOptions,
  type NativeLoginResult,
} from '../ui/LoginController';
import { PushApprovalsController } from '../ui/PushApprovals';
import {
  isChallengeLocked,
  type Challenge,
  type ChallengeType,
} from '../model';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

/**
 * Every default-screen path of the controller (the twin of the native `NativeLoginModel` tests)
 * against the server's recordings: one-time codes, recovery codes, the native required actions,
 * passkeys, push with number match and push enrollment, saved passwords.
 */
function setup(name: string, options: LoginControllerOptions = {}) {
  const transcript = loadTranscript(name);
  const native = new TranscriptNative(transcript);
  setNativeModuleForTesting(native);
  const clientId =
    transcript.exchanges[0]!.request.form?.client_id ?? 'demo-native';
  const kc = KeycloakNative.configure({
    issuer: 'http://localhost:8080/realms/demo',
    clientId,
  });
  const results: NativeLoginResult[] = [];
  const start = async () => {
    const flow = await kc.authentication.startLogin({
      scope: 'openid profile',
      deviceName: 'NativeAuthIT',
    });
    const controller = new LoginController(
      kc,
      flow,
      (r) => results.push(r),
      options
    );
    await controller.startIfNeeded();
    return controller;
  };
  return { native, kc, results, start };
}

function shown(controller: LoginController): Challenge {
  const phase = controller.state.phase;
  if (phase.kind !== 'challenges')
    throw new Error(`expected challenges, got ${phase.kind}`);
  return phase.selected;
}

function offered(controller: LoginController, type: ChallengeType): Challenge {
  const phase = controller.state.phase;
  if (phase.kind !== 'challenges')
    throw new Error(`expected challenges, got ${phase.kind}`);
  const challenge = phase.challenges.find((c) => c.type === type);
  if (challenge === undefined) throw new Error(`no ${type} in the set`);
  return challenge;
}

async function signInWithPassword(
  controller: LoginController,
  username: string
) {
  await controller.submit({ kind: 'username', username }, shown(controller));
  await controller.submit(
    { kind: 'password', password: 'secret' },
    shown(controller)
  );
}

afterEach(() => {
  setNativeModuleForTesting(undefined);
  jest.restoreAllMocks();
});

describe('one-time codes', () => {
  it('sends the email code on request, then verifies it', async () => {
    const { start, results, native } = setup(
      'OtpIT.aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest'
    );
    const c = await start();
    await signInWithPassword(c, 'alice');
    expect(shown(c).type).toBe('totp');
    c.select(offered(c, 'otp'));
    const otp = shown(c);
    if (otp.type !== 'otp') throw new Error(otp.type);
    expect(otp.params.sent).toBe(false);
    expect(otp.params.destinationMasked).toBe('a***@example.com');
    await c.submit({ kind: 'otpResend' }, otp);
    const sent = shown(c);
    if (sent.type !== 'otp') throw new Error(sent.type);
    expect(sent.params.sent).toBe(true);
    expect(sent.params.resendAllowedAt).toBeGreaterThan(0);
    await c.submit({ kind: 'otp', code: '123456' }, sent);
    // The recording ends with the authorization code (no token exchange).
    const last = native.matched
      .filter((e) => e.request.path.endsWith('/challenge'))
      .at(-1);
    expect(last?.request.form?.challenge_type).toBe('otp');
    expect(last?.response.status).toBe(200);
    expect(results).toHaveLength(1);
  });

  it('keeps the otp screen through a refused resend and wrong codes', async () => {
    const { start, results } = setup(
      'OtpIT.bobGetsAnEmailCodeAsTheOnlySecondFactor'
    );
    const c = await start();
    await signInWithPassword(c, 'bob');
    await c.submit({ kind: 'otpResend' }, shown(c));
    expect(shown(c).type).toBe('otp');
    expect(shown(c).error).toBeDefined();
    await c.submit({ kind: 'otp', code: '000000' }, shown(c));
    expect(shown(c).error).toBeDefined();
    await c.submit({ kind: 'otp', code: '123456' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });
});

describe('recovery codes', () => {
  it('signs in with a recovery code after a wrong one', async () => {
    const { start, results } = setup(
      'RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut'
    );
    const c = await start();
    await signInWithPassword(c, 'ivy');
    c.select(offered(c, 'recovery_code'));
    const recovery = shown(c);
    if (recovery.type !== 'recovery_code') throw new Error(recovery.type);
    expect(recovery.params.remaining).toBe(3);
    await c.submit({ kind: 'recoveryCode', code: 'WRONG' }, recovery);
    // The failed entry stays on screen with its error.
    expect(shown(c).type).toBe('recovery_code');
    expect(shown(c).error).toBeDefined();
    await c.submit({ kind: 'recoveryCode', code: 'AAAA-BBBB' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });
});

describe('native required actions', () => {
  it('update_password: retries until the policy is met, then offers the new password for saving', async () => {
    const { start, results, native } = setup(
      'RequiredActionsIT.carolUpdatesHerPasswordInBand'
    );
    const c = await start();
    await signInWithPassword(c, 'carol');
    const update = shown(c);
    if (update.type !== 'update_password') throw new Error(update.type);
    expect(update.requiredAction).toBe(true);
    expect(update.params.hints).toEqual(['At least 8 characters']);
    for (let i = 0; i < 3; i += 1) {
      await c.submit(
        { kind: 'updatePassword', password: 'short', confirm: 'short' },
        shown(c)
      );
      expect(shown(c).error).toBeDefined();
    }
    await c.submit(
      {
        kind: 'updatePassword',
        password: 'long-enough-1',
        confirm: 'long-enough-1',
      },
      shown(c)
    );
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
    expect(native.savedPasswords).toEqual([
      { username: 'carol', password: 'long-enough-1' },
    ]);
  });

  it('verify_email: resend and code', async () => {
    const { start, results } = setup(
      'RequiredActionsIT.graceVerifiesHerEmailWithACode'
    );
    const c = await start();
    await signInWithPassword(c, 'grace');
    const verify = shown(c);
    if (verify.type !== 'verify_email') throw new Error(verify.type);
    expect(verify.params.emailMasked).toBe('g***@example.com');
    await c.submit({ kind: 'verifyEmailResend' }, verify);
    await c.submit({ kind: 'verifyEmail', code: '000000' }, shown(c));
    await c.submit({ kind: 'verifyEmail', code: '123456' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });

  it('terms: declining ends the login with access_denied', async () => {
    const { start, results } = setup(
      'RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin'
    );
    const c = await start();
    await signInWithPassword(c, 'hank');
    const terms = shown(c);
    if (terms.type !== 'terms') throw new Error(terms.type);
    expect(terms.params.text).toMatch(/^Demo terms/);
    await c.submit({ kind: 'terms', accepted: false }, terms);
    expect(results).toEqual([
      {
        kind: 'failed',
        error: expect.objectContaining({ code: 'access_denied' }),
      },
    ]);
    expect(c.state.phase.kind).toBe('finished');
  });

  it('an optional passkey enrollment can be skipped', async () => {
    const { start, results, native } = setup(
      'EnrolOnFirstLoginIT.bobMayDeclineAnOptionalEnrolmentAndIsOfferedItAgainAtTheNextLogin',
      { offerToSavePassword: false }
    );
    const c = await start();
    await signInWithPassword(c, 'bob');
    const registration = shown(c);
    expect(registration.type).toBe('passkey_registration');
    expect(registration.skippable).toBe(true);
    await c.submit({ kind: 'skip' }, registration);
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
    expect(native.savedPasswords).toEqual([]);
  });
});

/**
 * The PIN extension (spec/20): `PinIT`'s recordings on client `demo-native-pin` (pia has a PIN,
 * pete sets one, rita's PIN locks after 3 attempts).
 */
describe('PIN', () => {
  it('signs in with the PIN after a wrong one', async () => {
    const { start, results } = setup(
      'PinIT.piaSignsInWithHerPinAfterAWrongOne'
    );
    const c = await start();
    await signInWithPassword(c, 'pia');
    const pin = shown(c);
    if (pin.type !== 'pin') throw new Error(pin.type);
    expect(pin.params.length).toBe(4);
    await c.submit({ kind: 'pin', pin: '0000' }, pin);
    const retry = shown(c);
    expect(retry.error?.code).toBe('invalid_credential');
    expect(retry.retry?.remaining).toBe(2);
    await c.submit({ kind: 'pin', pin: '2580' }, retry);
    expect(results.map((r) => r.kind)).toEqual(['authorized']);
  });

  it('sets a PIN in band through missing_credential, pin_mismatch, weak_pin and invalid_format', async () => {
    const { start, results } = setup('PinIT.peteSetsAPinInBand');
    const c = await start();
    await signInWithPassword(c, 'pete');
    const setupPin = shown(c);
    if (setupPin.type !== 'pin_setup') throw new Error(setupPin.type);
    expect(setupPin.requiredAction).toBe(true);
    expect(setupPin.params.length).toBe(4);
    const errors: (string | undefined)[] = [];
    for (const [pin, confirm] of [
      ['', ''],
      ['1357', '1358'],
      ['1111', '1111'],
      ['12', '12'],
    ] as const) {
      await c.submit({ kind: 'pinSetup', pin, confirm }, shown(c));
      errors.push(shown(c).error?.code);
    }
    expect(errors).toEqual([
      'missing_credential',
      'pin_mismatch',
      'weak_pin',
      'invalid_format',
    ]);
    await c.submit(
      { kind: 'pinSetup', pin: '2580', confirm: '2580' },
      shown(c)
    );
    expect(results.map((r) => r.kind)).toEqual(['authorized']);
  });

  it('a locked PIN can only be cancelled', async () => {
    const { start, results } = setup('PinIT.aLockedPinCanOnlyBeCancelled');
    const c = await start();
    await signInWithPassword(c, 'rita');
    expect(shown(c).error).toBeUndefined();
    for (const [pin, remaining] of [
      ['0001', 2],
      ['0002', 1],
    ] as const) {
      await c.submit({ kind: 'pin', pin }, shown(c));
      expect(shown(c).retry?.remaining).toBe(remaining);
    }
    await c.submit({ kind: 'pin', pin: '0009' }, shown(c));
    const locked = shown(c);
    expect(isChallengeLocked(locked)).toBe(true);
    expect(locked.retry?.remaining).toBe(0);
    await c.cancel();
    expect(results.map((r) => r.kind)).toEqual(['cancelled']);
  });
});

describe('passkeys', () => {
  it('registers a passkey on the required action through the native ceremony', async () => {
    const { start, results, native } = setup(
      'EnrolOnFirstLoginIT.bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin'
    );
    const c = await start();
    await signInWithPassword(c, 'bob');
    const registration = shown(c);
    if (registration.type !== 'passkey_registration')
      throw new Error(registration.type);
    expect(registration.params?.rp.id).toBe('localhost');
    await c.registerPasskey(registration, "Bob's phone");
    expect(native.ceremonies).toEqual([
      {
        kind: 'passkeyRegistration',
        challengeId: registration.id,
        label: "Bob's phone",
      },
    ]);
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });

  it('a discoverable passkey runs automatically with autoSelectPasskey', async () => {
    const { start, results, native } = setup(
      'PasskeyIT.discoverableLoginWithUserHandle',
      {
        autoSelectPasskey: true,
      }
    );
    const c = await start();
    // The prompt runs as its own submission after the set is shown.
    await new Promise((resolve) => setTimeout(resolve, 10));
    while (c.state.isSubmitting)
      await new Promise((resolve) => setTimeout(resolve, 5));
    expect(native.ceremonies.map((x) => x.kind)).toEqual(['passkey']);
    expect(shown(c).type).toBe('totp');
    await c.submit({ kind: 'totp', code: '123456' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });

  it('a closed passkey prompt leaves the set on screen', async () => {
    const { start, native } = setup(
      'PasskeyIT.discoverableLoginWithUserHandle'
    );
    const c = await start();
    native.respondWithPasskey = () =>
      Promise.reject(
        Object.assign(new Error('closed'), { code: 'passkey_cancelled' })
      );
    await c.usePasskey(shown(c));
    expect(shown(c).type).toBe('passkey');
    expect(c.state.message).toBeUndefined();
  });
});

describe('push', () => {
  it('number match: send, poll, approve on the device with a wrong then the right number', async () => {
    const { start, results, native, kc } = setup(
      'PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch'
    );
    const c = await start();
    await signInWithPassword(c, 'alice');
    c.select(offered(c, 'push'));
    const push = shown(c);
    if (push.type !== 'push') throw new Error(push.type);
    expect(push.params.sent).toBe(false);
    expect(push.params.devices).toEqual(["Alice's test iPhone"]);
    await c.submit({ kind: 'pushResend' }, push);
    const pending = shown(c);
    if (pending.type !== 'push') throw new Error(pending.type);
    expect(pending.params.isPending).toBe(true);
    expect(pending.params.pollInterval).toBe(3);
    await c.submit({ kind: 'pushPoll' }, pending);
    expect(shown(c).type).toBe('push');

    // The phone (same user, enrolled) answers through the approvals list, while the approval is open.
    jest.spyOn(Date, 'now').mockReturnValue(pending.params.expiresAt! - 60_000);
    const approvals = new PushApprovalsController(kc, pending.params.cid);
    await approvals.refresh();
    const [approval] = approvals.state.approvals;
    expect(approval?.cid).toBe(pending.params.cid);
    expect(approval?.numbers).toHaveLength(3);
    await approvals.respond(approval!, {
      kind: 'approve',
      userVerification: '00',
    });
    expect(approvals.state.message).toBeDefined();
    expect(approvals.state.approvals).toHaveLength(1);
    await approvals.respond(approval!, {
      kind: 'approve',
      userVerification: approval!.numbers[0],
    });
    expect(approvals.state.approvals).toHaveLength(0);
    expect(native.pushResponses.map((r) => r.action)).toEqual([
      'approve',
      'approve',
    ]);

    await c.submit({ kind: 'pushPoll' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
  });

  it('push_enrollment: a refused enrollment stays on screen, the retry stores it', async () => {
    const { start, results, native, kc } = setup(
      'PushMfaIT.judyEnrolsMidFlowThroughTheNativeRequiredAction',
      {
        pushRegistration: async () => ({ type: 'fcm', id: 'fcm-token' }),
      }
    );
    const c = await start();
    await signInWithPassword(c, 'judy');
    const enrollment = shown(c);
    expect(enrollment.type).toBe('push_enrollment');
    await c.enrollPush(enrollment, 'Pixel');
    expect(shown(c).error?.code).toBe('invalid_credential');
    expect(await kc.push.enrollment()).toBeNull();
    await c.enrollPush(shown(c), 'Pixel');
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
    expect(native.ceremonies.map((x) => x.provider)).toEqual([
      'fcm:fcm-token',
      'fcm:fcm-token',
    ]);
    expect((await kc.push.enrollment())?.deviceLabel).toBe('Pixel');
  });

  it('enrolls from inside the app after a login', async () => {
    const { start, kc } = setup(
      'PushMfaIT.aliceEnrolsHerDeviceFromInsideTheApp'
    );
    const c = await start();
    await signInWithPassword(c, 'alice');
    await c.submit({ kind: 'totp', code: '123456' }, shown(c));
    const enrollment = await kc.push.enroll('Pixel 9');
    expect(enrollment.deviceLabel).toBe('Pixel 9');
    expect(enrollment.pushProviderType).toBe('none');
    expect(await kc.push.isEnrolled()).toBe(true);
  });
});

describe('saved passwords', () => {
  it('a password picked on the username step answers both steps and is not offered again', async () => {
    const { start, results, native } = setup(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    native.savedPassword = { username: 'alice', password: 'alice-password' };
    const c = await start();
    await c.useSavedPassword(shown(c));
    expect(shown(c).type).toBe('totp');
    await c.submit({ kind: 'totp', code: '123456' }, shown(c));
    expect(
      results.map((r) => (r.kind === 'failed' ? r.error.message : r.kind))
    ).toEqual(['authorized']);
    expect(native.savedPasswords).toEqual([]);
  });

  it('a closed sheet changes nothing', async () => {
    const { start } = setup(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    const c = await start();
    await c.useSavedPassword(shown(c));
    expect(shown(c).type).toBe('username');
    expect(c.state.message).toBeUndefined();
  });

  it('a typed password is offered for saving after the login', async () => {
    const { start, native } = setup(
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'
    );
    const c = await start();
    await signInWithPassword(c, 'alice');
    await c.submit({ kind: 'totp', code: '123456' }, shown(c));
    expect(native.savedPasswords).toEqual([
      { username: 'alice', password: 'secret' },
    ]);
  });
});
