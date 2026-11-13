import {
  ChallengeTypes,
  NativeAuthError,
  answerChallengeType,
  isChallengeLocked,
  isWellFormedPin,
  millisUntil,
  parseChallenge,
  parseCredentials,
  parseFlowStep,
  type ChallengeOf,
  type JsonObject,
} from '../model';
import {
  challengeSets,
  loadTranscript,
  transcriptNames,
} from './support/transcripts';

function challenge<T extends ChallengeOf<any>['type']>(
  type: T,
  json: JsonObject
): ChallengeOf<T> {
  const parsed = parseChallenge(json);
  expect(parsed?.type).toBe(type);
  return parsed as ChallengeOf<T>;
}

describe('parseChallenge', () => {
  it('reads the descriptor fields and defaults', () => {
    const c = challenge('password', {
      type: 'password',
      id: 'exec-1',
      label: 'Password',
      error: { code: 'invalid_credential', message: 'Invalid password' },
      retry: { remaining: 2 },
      params: { username_known: false },
    });
    expect(c.id).toBe('exec-1');
    expect(c.wireType).toBe('password');
    expect(c.required).toBe(true);
    expect(c.skippable).toBe(false);
    expect(c.supported).toBe(true);
    expect(c.requiredAction).toBe(false);
    expect(c.error).toEqual({
      code: 'invalid_credential',
      message: 'Invalid password',
    });
    expect(c.retry).toEqual({ remaining: 2 });
    expect(c.params.usernameKnown).toBe(false);
  });

  it('needs type and id', () => {
    expect(parseChallenge({ id: 'x' })).toBeUndefined();
    expect(parseChallenge({ type: 'password' })).toBeUndefined();
    expect(parseChallenge('password')).toBeUndefined();
  });

  it('keeps unknown types with their wire value and treats select as unsupported', () => {
    const unknown = parseChallenge({
      type: 'x_face_scan',
      id: 'e',
      params: { a: 1 },
    });
    expect(unknown?.type).toBe('unknown');
    expect(unknown?.wireType).toBe('x_face_scan');
    expect(unknown?.supported).toBe(false);
    expect(unknown?.params).toEqual({ a: 1 });
    const select = parseChallenge({ type: 'select', id: 'e' });
    expect(select?.type).toBe('select');
    expect(select?.supported).toBe(false);
  });

  it('types totp params', () => {
    const c = challenge('totp', {
      type: 'totp',
      id: 'e',
      params: {
        digits: 8,
        algorithm: 'HmacSHA256',
        credential_labels: ['Phone'],
        credentials: [
          { id: 'c1', label: 'Phone' },
          { id: 'c2' },
          { label: 'no id' },
        ],
      },
    });
    expect(c.params).toEqual({
      digits: 8,
      period: 30,
      algorithm: 'HmacSHA256',
      credentialLabels: ['Phone'],
      credentials: [
        { id: 'c1', label: 'Phone' },
        { id: 'c2', label: '' },
      ],
    });
  });

  it('types pin and pin_setup params; pin_setup is a required action', () => {
    const pin = challenge('pin', {
      type: 'pin',
      id: 'e',
      params: { length: 6 },
    });
    expect(pin.params).toEqual({ length: 6 });
    expect(pin.supported).toBe(true);
    expect(pin.requiredAction).toBe(false);
    expect(isChallengeLocked(pin)).toBe(false);
    expect(challenge('pin', { type: 'pin', id: 'e' }).params.length).toBe(4);

    const setup = challenge('pin_setup', {
      type: 'pin_setup',
      id: 'native-configure-pin',
      params: { length: 4 },
    });
    expect(setup.requiredAction).toBe(true);
    expect(isWellFormedPin(setup.params, '2580')).toBe(true);
    expect(isWellFormedPin(setup.params, '258')).toBe(false);
    expect(isWellFormedPin(setup.params, '25800')).toBe(false);
    expect(isWellFormedPin(setup.params, '25a0')).toBe(false);
    expect(isWellFormedPin(setup.params, '２５８０')).toBe(false);
    expect(answerChallengeType.pin).toBe('pin');
    expect(answerChallengeType.pinSetup).toBe('pin_setup');
  });

  it('a credential_locked pin is locked', () => {
    const locked = challenge('pin', {
      type: 'pin',
      id: 'e',
      error: { code: 'credential_locked', message: 'PIN locked' },
      retry: { remaining: 0 },
      params: { length: 4 },
    });
    expect(isChallengeLocked(locked)).toBe(true);
    expect(locked.retry).toEqual({ remaining: 0 });
  });

  it('types otp params with instants in milliseconds', () => {
    const c = challenge('otp', {
      type: 'otp',
      id: 'e',
      params: {
        channel: 'sms',
        destination_masked: '+1***99',
        sent: true,
        ttl: 300,
        resend_allowed_at: 1700000030,
      },
    });
    expect(c.params.channel).toBe('sms');
    expect(c.params.digits).toBe(6);
    expect(c.params.resendAllowedAt).toBe(1700000030000);
    expect(millisUntil(c.params.resendAllowedAt, 1700000000000)).toBe(30000);
    expect(millisUntil(c.params.resendAllowedAt, 1700000040000)).toBe(0);
  });

  it('builds the update_password hints like the native SDKs', () => {
    const c = challenge('update_password', {
      type: 'update_password',
      id: 'UPDATE_PASSWORD',
      params: {
        username: 'carol',
        policy: {
          length: 12,
          digits: 1,
          upperCase: 2,
          notUsername: true,
          passwordHistory: 3,
        },
      },
    });
    expect(c.requiredAction).toBe(true);
    expect(c.params.minimumLength).toBe(12);
    expect(c.params.hints).toEqual([
      'At least 12 characters',
      'At least 1 digit',
      'At least 2 upper-case letters',
      'Not your username',
      'Not one of your last 3 passwords',
    ]);
  });

  it('reads push number match only for number_match', () => {
    const c = challenge('push', {
      type: 'push',
      id: 'e',
      params: {
        sent: true,
        status: 'pending',
        poll_interval: 0,
        user_verification: { type: 'number_match', number: '42' },
        devices: [{ label: 'Pixel' }],
      },
    });
    expect(c.params.userVerificationNumber).toBe('42');
    expect(c.params.pollInterval).toBe(1);
    expect(c.params.devices).toEqual(['Pixel']);
    expect(c.params.isPending).toBe(true);
  });

  it('leaves passkey params undefined when a required field is missing', () => {
    expect(
      challenge('passkey', {
        type: 'passkey',
        id: 'e',
        params: { rp_id: 'example.com' },
      }).params
    ).toBeUndefined();
    const c = challenge('passkey', {
      type: 'passkey',
      id: 'e',
      params: { challenge: 'abc', rp_id: 'example.com' },
    });
    expect(c.params?.discoverable).toBe(true);
    expect(c.params?.userVerification).toBe('preferred');
  });
});

describe('parseFlowStep', () => {
  it('filters the supported challenges in server order', () => {
    const step = parseFlowStep({
      kind: 'challenges',
      challenges: [
        { type: 'x_new', id: '1' },
        { type: 'totp', id: '2' },
        { id: 'broken' },
        { type: 'otp', id: '3' },
      ],
      context: { username: 'alice', step_up: true },
      expiresIn: 1800,
    });
    if (step.kind !== 'challenges') throw new Error(step.kind);
    expect(step.challenges.map((c) => c.wireType)).toEqual([
      'x_new',
      'totp',
      'otp',
    ]);
    expect(step.supportedChallenges.map((c) => c.id)).toEqual(['2', '3']);
    expect(step.context.username).toBe('alice');
    expect(step.context.stepUp).toBe(true);
    expect(step.expiresIn).toBe(1800);
  });

  it('refuses an unknown step', () => {
    expect(() => parseFlowStep({ kind: 'later' })).toThrow(NativeAuthError);
  });

  it('reads credentials without the refresh token', () => {
    const credentials = parseCredentials({
      accessToken: 'at',
      tokenType: 'DPoP',
      expiresAt: 2000,
      issuedAt: 1000,
      hasRefreshToken: true,
      idToken: null,
    });
    expect(credentials).toEqual({
      accessToken: 'at',
      tokenType: 'DPoP',
      idToken: undefined,
      scope: undefined,
      expiresAt: 2000,
      refreshExpiresAt: undefined,
      issuedAt: 1000,
      hasRefreshToken: true,
      isDPoPBound: true,
    });
    expect('refreshToken' in credentials).toBe(false);
  });
});

describe('NativeAuthError.from', () => {
  it('reads a native rejection', () => {
    const e = NativeAuthError.from({
      code: 'network_error',
      message: 'offline',
      userInfo: { isNetworkError: true, isRetryable: true, statusCode: null },
    });
    expect(e.code).toBe('network_error');
    expect(e.errorDescription).toBe('offline');
    expect(e.isNetworkError).toBe(true);
    expect(e.isRetryable).toBe(true);
    expect(e.statusCode).toBeUndefined();
  });

  it('falls back to invalid_response', () => {
    expect(NativeAuthError.from(new Error('boom')).code).toBe(
      'invalid_response'
    );
  });
});

/**
 * Protocol drift: every challenge set the server recorded parses, every type is one this model knows,
 * and every params field is one the model reads. A new or renamed field in a transcript fails here
 * until the model (and this list) is updated, as the native SDKs' replay tests fail.
 */
const MODELED_PARAMS: Record<string, string[]> = {
  username: ['allow_email', 'hint'],
  password: ['username_known'],
  totp: ['digits', 'period', 'algorithm', 'credential_labels', 'credentials'],
  otp: [
    'channel',
    'destination_masked',
    'digits',
    'ttl',
    'sent',
    'resend_allowed_at',
  ],
  recovery_code: ['remaining', 'warning_threshold'],
  update_password: ['username', 'policy'],
  pin: ['length'],
  pin_setup: ['length'],
  verify_email: ['email_masked', 'digits', 'ttl', 'sent', 'resend_allowed_at'],
  terms: ['text', 'url', 'version'],
  push: [
    'sent',
    'cid',
    'expires_at',
    'poll_interval',
    'status',
    'user_verification',
    'devices',
    'resend_allowed_at',
  ],
  push_enrollment: [
    'enrollment_token',
    'expires_in',
    'device_api_base',
    'user_id',
  ],
  passkey: [
    'challenge',
    'rp_id',
    'timeout',
    'user_verification',
    'allow_credentials',
    'discoverable',
  ],
  passkey_registration: [
    'challenge',
    'rp',
    'user',
    'pub_key_cred_params',
    'authenticator_selection',
    'attestation',
    'exclude_credentials',
    'timeout',
  ],
};
const MODELED_DESCRIPTOR = [
  'type',
  'id',
  'label',
  'required',
  'error',
  'retry',
  'skippable',
  'params',
];
const MODELED_CONTEXT = [
  'username',
  'display_name',
  'client_name',
  'acr_requested',
  'step_up',
];

describe('recorded transcripts', () => {
  const names = transcriptNames();

  it('are present', () => {
    expect(names.length).toBeGreaterThan(50);
  });

  it.each(names)(
    '%s: every challenge set parses into known types and fields',
    (name) => {
      for (const set of challengeSets(loadTranscript(name))) {
        const step = parseFlowStep({
          kind: 'challenges',
          challenges: set.challenges ?? [],
          context: set.context ?? {},
        });
        if (step.kind !== 'challenges') throw new Error(step.kind);
        expect(step.challenges).toHaveLength(
          (set.challenges as unknown[]).length
        );
        for (const key of Object.keys(step.context.raw))
          expect(MODELED_CONTEXT).toContain(key);
        for (const c of step.challenges) {
          expect(ChallengeTypes).toContain(c.wireType);
          for (const key of Object.keys(c.raw))
            expect(MODELED_DESCRIPTOR).toContain(key);
          for (const key of Object.keys(c.rawParams)) {
            expect([
              c.wireType,
              key,
              MODELED_PARAMS[c.wireType]?.includes(key),
            ]).toEqual([c.wireType, key, true]);
          }
          if (c.type === 'passkey' || c.type === 'passkey_registration')
            expect(c.params).toBeDefined();
        }
      }
    }
  );
});
