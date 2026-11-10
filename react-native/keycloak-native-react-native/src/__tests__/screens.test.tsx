import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import { KeycloakNative, setNativeModuleForTesting } from '../KeycloakNative';
import { parseChallenge, parseFlowContext, type JsonObject } from '../model';
import {
  DefaultChallengeScreen,
  type ChallengePresentationProps,
} from '../ui/DefaultScreens';
import { PushApprovalsScreen } from '../ui/PushApprovals';
import { englishStrings, germanStrings, stringsForLocale } from '../ui/strings';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

/** Renders one default screen with recorded calls instead of a flow. */
function render(descriptor: JsonObject, context: JsonObject = {}) {
  const challenge = parseChallenge(descriptor)!;
  const calls: unknown[][] = [];
  const record =
    (name: string) =>
    (...args: unknown[]) =>
      calls.push([name, ...args]);
  const props: ChallengePresentationProps = {
    challenge,
    challenges: [challenge],
    alternatives: [],
    flowContext: parseFlowContext(context),
    isSubmitting: false,
    isStepUp: false,
    offersSavedPasswords: true,
    strings: englishStrings,
    submit: record('submit'),
    usePasskey: record('usePasskey'),
    registerPasskey: record('registerPasskey'),
    enrollPush: record('enrollPush'),
    useSavedPassword: record('useSavedPassword'),
    switchTo: record('switchTo'),
    cancel: record('cancel'),
  };
  let tree: ReactTestRenderer;
  act(() => {
    tree = create(<DefaultChallengeScreen {...props} />);
  });
  const byId = (id: string) =>
    tree.root.find(
      (n) =>
        n.props.testID === id &&
        (n.props.onPress !== undefined || n.props.onChangeText !== undefined)
    );
  const has = (id: string) =>
    tree.root.findAll((n) => n.props.testID === id).length > 0;
  const text = () =>
    tree.root
      .findAll((n) => typeof n.props.children === 'string')
      .map((n) => n.props.children as string);
  mounted.push(tree!);
  return { tree: tree!, calls, byId, has, text };
}

const mounted: ReactTestRenderer[] = [];

afterEach(() => {
  act(() => mounted.splice(0).forEach((t) => t.unmount()));
  setNativeModuleForTesting(undefined);
  jest.useRealTimers();
});

describe('default screens', () => {
  it('otp: send first, then the code with a resend cooldown', () => {
    const notSent = render({
      type: 'otp',
      id: 'o',
      params: { channel: 'sms', digits: 6, sent: false },
    });
    expect(notSent.text()).toContain(
      'We can send a 6-digit code to your phone.'
    );
    act(() => notSent.byId('kc-otp-send').props.onPress());
    expect(notSent.calls).toEqual([['submit', { kind: 'otpResend' }]]);

    const sent = render({
      type: 'otp',
      id: 'o',
      params: {
        channel: 'email',
        digits: 6,
        sent: true,
        destination_masked: 'b***@example.com',
        resend_allowed_at: Date.now() / 1000 + 30,
      },
    });
    expect(sent.text()).toContain(
      'We sent a 6-digit code to b***@example.com.'
    );
    expect(sent.byId('kc-otp-resend').props.disabled).toBe(true);
    expect(sent.text().some((t) => /^Resend code in (29|30) s$/.test(t))).toBe(
      true
    );
    act(() => sent.byId('kc-otp').props.onChangeText('12x3456'));
    act(() => sent.byId('kc-otp-submit').props.onPress());
    expect(sent.calls).toEqual([['submit', { kind: 'otp', code: '123456' }]]);
  });

  it('push: shows the number and polls every poll_interval', () => {
    jest.useFakeTimers();
    const s = render({
      type: 'push',
      id: 'p',
      params: {
        sent: true,
        cid: 'c',
        poll_interval: 2,
        status: 'pending',
        user_verification: { type: 'number_match', number: '42' },
        devices: [{ label: 'Pixel' }],
      },
    });
    expect(s.text()).toContain('42');
    expect(s.text()).toContain(
      'We sent a sign-in request to Pixel. Approve it there to continue.'
    );
    act(() => {
      jest.advanceTimersByTime(4100);
    });
    expect(s.calls).toEqual([
      ['submit', { kind: 'pushPoll' }],
      ['submit', { kind: 'pushPoll' }],
    ]);
    act(() => s.tree.unmount());
  });

  it('passkey and passkey_registration run the native ceremonies; an offer can be skipped', () => {
    const passkey = render({
      type: 'passkey',
      id: 'pk',
      params: { challenge: 'abc', rp_id: 'example.com', allow_credentials: [] },
    });
    expect(passkey.text()).toContain('Use a passkey saved on this device.');
    act(() => passkey.byId('kc-use-passkey').props.onPress());
    expect(passkey.calls).toEqual([['usePasskey']]);

    const registration = render({
      type: 'passkey_registration',
      id: 'native-passkey-register',
      skippable: true,
      params: {
        challenge: 'abc',
        rp: { id: 'example.com', name: 'Demo' },
        user: { id: 'u', name: 'bob' },
      },
    });
    expect(registration.text()).toContain(
      'Sign in faster next time: create a passkey for bob on this device.'
    );
    act(() =>
      registration.byId('kc-passkey-label').props.onChangeText(' Phone ')
    );
    act(() => registration.byId('kc-create-passkey').props.onPress());
    act(() => registration.byId('kc-skip').props.onPress());
    expect(registration.calls).toEqual([
      ['registerPasskey', 'Phone'],
      ['submit', { kind: 'skip' }],
    ]);
  });

  it('push_enrollment enrolls with a default device name', () => {
    const s = render(
      { type: 'push_enrollment', id: 'native-push-enroll', params: {} },
      { client_name: 'Demo app' }
    );
    expect(s.text()).toContain(
      'Demo app asks you to enroll this device so you can approve sign-ins from here.'
    );
    act(() => s.byId('kc-push-enroll').props.onPress());
    expect(s.calls).toEqual([['enrollPush', 'This device']]);
  });

  it('update_password: hints, mismatch, submit', () => {
    const s = render(
      {
        type: 'update_password',
        id: 'native-update-password',
        params: { username: 'carol', policy: { length: 8 } },
      },
      { username: 'carol' }
    );
    expect(s.text()).toContain('• At least 8 characters');
    act(() => s.byId('kc-new-password').props.onChangeText('password-1'));
    act(() =>
      s.byId('kc-new-password-confirm').props.onChangeText('password-2')
    );
    expect(s.text()).toContain('Passwords do not match');
    expect(s.byId('kc-update-password').props.disabled).toBe(true);
    act(() =>
      s.byId('kc-new-password-confirm').props.onChangeText('password-1')
    );
    act(() => s.byId('kc-update-password').props.onPress());
    expect(s.calls).toEqual([
      [
        'submit',
        {
          kind: 'updatePassword',
          password: 'password-1',
          confirm: 'password-1',
        },
      ],
    ]);
  });

  it('verify_email, terms and recovery_code', () => {
    const verify = render({
      type: 'verify_email',
      id: 'v',
      params: { email_masked: 'g***@example.com', digits: 6, sent: false },
    });
    expect(verify.text()).toContain(
      'We need to send a 6-digit code to g***@example.com.'
    );
    act(() => verify.byId('kc-verify-email-resend').props.onPress());
    expect(verify.calls).toEqual([['submit', { kind: 'verifyEmailResend' }]]);

    const terms = render({
      type: 'terms',
      id: 't',
      params: { text: 'Be nice.', version: '2' },
    });
    expect(terms.text()).toEqual(
      expect.arrayContaining(['Be nice.', 'Version 2'])
    );
    act(() => terms.byId('kc-terms-decline').props.onPress());
    act(() => terms.byId('kc-terms-accept').props.onPress());
    expect(terms.calls).toEqual([
      ['submit', { kind: 'terms', accepted: false }],
      ['submit', { kind: 'terms', accepted: true }],
    ]);

    const recovery = render({
      type: 'recovery_code',
      id: 'r',
      params: { remaining: 1, warning_threshold: 2 },
    });
    expect(recovery.has('kc-recovery-low')).toBe(true);
    act(() =>
      recovery.byId('kc-recovery-code').props.onChangeText(' abcd-efgh ')
    );
    act(() => recovery.byId('kc-recovery-code-submit').props.onPress());
    expect(recovery.calls).toEqual([
      ['submit', { kind: 'recoveryCode', code: 'abcd-efgh' }],
    ]);
  });

  it('shows the descriptor error, the attempts left and the context line', () => {
    const s = render(
      {
        type: 'password',
        id: 'pw',
        error: { code: 'invalid_credential', message: 'Invalid password' },
        retry: { remaining: 2 },
      },
      { username: 'alice', display_name: 'Alice' }
    );
    expect(s.text()).toEqual(
      expect.arrayContaining([
        'Signing in as Alice',
        'Invalid password',
        '2 attempts left',
      ])
    );
    act(() => s.byId('kc-use-saved-password').props.onPress());
    expect(s.calls).toEqual([['useSavedPassword']]);
  });

  it('unknown types get the update screen', () => {
    const s = render({ type: 'x_face_scan', id: 'x' });
    expect(s.text()).toContain(
      "This version of the app cannot handle the 'x_face_scan' sign-in method. Update the app or sign in on the web."
    );
  });
});

describe('strings', () => {
  it('picks German for de locales and English otherwise', () => {
    expect(stringsForLocale('de-AT')).toBe(germanStrings);
    expect(stringsForLocale('en-US')).toBe(englishStrings);
    expect(stringsForLocale(undefined)).toBe(englishStrings);
    expect(germanStrings.attemptsLeft(1)).toBe('Noch 1 Versuch');
  });

  it('the catalogues have the same keys', () => {
    expect(Object.keys(germanStrings).sort()).toEqual(
      Object.keys(englishStrings).sort()
    );
  });
});

describe('PushApprovalsScreen', () => {
  it('lists the pending approval with its numbers and approves one', async () => {
    const native = new TranscriptNative(
      loadTranscript(
        'PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch'
      )
    );
    setNativeModuleForTesting(native);
    const kc = KeycloakNative.configure({
      issuer: 'http://localhost:8080/realms/demo',
      clientId: 'demo-native',
    });
    jest.spyOn(Date, 'now').mockReturnValue(1793997707000);
    const responded: string[] = [];
    let tree: ReactTestRenderer;
    await act(async () => {
      tree = create(
        <PushApprovalsScreen
          kc={kc}
          onResponded={(_, status) => responded.push(status)}
        />
      );
    });
    mounted.push(tree!);
    for (let i = 0; i < 3; i += 1) await act(async () => {});
    const numberIds = () => [
      ...new Set(
        tree!.root
          .findAll(
            (n) =>
              typeof n.props.testID === 'string' &&
              n.props.testID.startsWith('kc-push-number-')
          )
          .map((n) => n.props.testID as string)
      ),
    ];
    const press = (id: string) =>
      tree!.root
        .findAll(
          (n) => n.props.testID === id && n.props.onPress !== undefined
        )[0]!
        .props.onPress();
    expect(numberIds()).toHaveLength(3);
    // The recording answers the first response with a mismatch, the second with approved.
    await act(async () => press(numberIds()[0]!));
    expect(native.pushResponses).toHaveLength(1);
    expect(numberIds()).toHaveLength(3);
    await act(async () => press(numberIds()[1]!));
    expect(responded).toEqual(['approved']);
    expect(
      tree!.root.findAll((n) => n.props.testID === 'kc-push-no-approvals')
        .length
    ).toBeGreaterThan(0);
    jest.restoreAllMocks();
  });
});
